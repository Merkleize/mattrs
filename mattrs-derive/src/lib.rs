use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Meta, Type};

mod contract;

/// Define a MATT contract: its clauses, taproot tree, typed handle, and one method
/// per clause.
///
/// A single `contract! { .. }` block generates the per-clause `*Args` structs, the
/// clause objects and `ClauseTree`, a `Name` contract struct (with `new`, `fund`,
/// `as_erased`), and a typed `NameHandle` whose per-clause methods return a
/// [`SpendBuilder`](../mattrs/manager/struct.SpendBuilder.html). It expands to the
/// ordinary `StandardClause` / `ClauseTree` / `StandardP2TR` primitives.
///
/// ```ignore
/// contract! {
///     contract Vault {
///         params VaultParams;
///         internal_key |p| internal_key_or_nums(p.alternate_pk);
///
///         clause trigger {
///             args {
///                 #[signer(|p| p.unvault_pk.serialize())] sig: Signature,
///                 ctv_hash: [u8; 32],
///                 out_i: i64,
///             }
///             script Vault::trigger_script;         // fn(&VaultParams) -> ScriptBuf
///             next(p, a) { /* -> Result<Vec<ClauseOutput>, ClauseError> */ }
///         }
///         // ... more clauses ...
///         tree [trigger, [trigger_and_revault, recover]];
///     }
/// }
/// ```
#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    contract::expand(input)
}

/// Derive macro for ClauseArgs trait.
/// Automatically implements encoding/decoding to witness stack and generates arg_specs().
/// 
/// # Attributes
/// 
/// ## Struct-level attributes
/// - `#[clause_args(params = ParamsType)]` - Specifies the params type for param-dependent arg_specs.
///   When specified, generates `arg_specs_for_params(params: &ParamsType)` in addition to `arg_specs()`.
/// 
/// ## Field-level attributes
/// - `#[signer(expr)]` - Creates a SignerType with the given pubkey expression.
///   If `expr` is a closure like `|p| p.unvault_pk`, it will be used in `arg_specs_for_params`.
/// - `#[arg_type(expr)]` - Uses a custom ArgType expression
/// 
/// # Default type mappings (when no attribute is specified)
/// - `Vec<u8>` -> `BytesType`
/// - `[u8; N]` -> `BytesType`
/// - `i32`, `i64` -> `IntType`
/// 
/// # Examples
/// 
/// ```ignore
/// // Simple args without params dependency
/// #[derive(ClauseArgs)]
/// pub struct RecoverArgs {
///     pub out_i: i64,
/// }
/// 
/// // Args with param-dependent signer
/// #[derive(ClauseArgs)]
/// #[clause_args(params = VaultParams)]
/// pub struct TriggerArgs {
///     #[signer(|p| p.unvault_pk.serialize())]
///     pub sig: Vec<u8>,
///     pub ctv_hash: [u8; 32],
///     pub out_i: i64,
/// }
/// ```
#[proc_macro_derive(ClauseArgs, attributes(signer, arg_type, clause_args))]
pub fn derive_clause_args(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Check for #[clause_args(params = ParamsType)] attribute
    let params_type = extract_params_type(&input.attrs);

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("ClauseArgs only supports structs with named fields"),
        },
        _ => panic!("ClauseArgs can only be derived for structs"),
    };

    let encode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            stack.extend(self.#field_name.encode_to_witness());
        }
    });

    let decode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        quote! {
            let (#field_name, consumed) = <#field_type as WitnessEncodable>::decode_from_witness(&witness[offset..])?;
            offset += consumed;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);

    // Does any field use a closure-based `#[signer(|p| ..)]`? Such fields need the
    // params to build their SignerType, so only `arg_specs_for_params()` is valid.
    let has_closure_signer = fields
        .iter()
        .any(|f| matches!(extract_signer_attr(&f.attrs), Some(SignerAttrInfo::Closure(_))));

    // A closure signer is meaningless without a params type to feed it.
    if has_closure_signer && params_type.is_none() {
        panic!(
            "#[derive(ClauseArgs)]: a `#[signer(|p| ..)]` field requires \
             `#[clause_args(params = ParamsType)]` on the struct"
        );
    }

    // The static `arg_specs()` is only generated when no field depends on params
    // (i.e. no closure signer). Otherwise callers must use `arg_specs_for_params()`
    // so that signer specs can never be silently downgraded to BytesType.
    let static_arg_specs_impl = if has_closure_signer {
        quote! {}
    } else {
        let arg_spec_items = fields.iter().map(|f| {
            let field_name = &f.ident;
            let field_name_str = field_name.as_ref().unwrap().to_string();
            let field_type = &f.ty;

            let signer_info = extract_signer_attr(&f.attrs);
            let custom_arg_type = extract_arg_type_attr(&f.attrs);

            let arg_type_expr = if let Some(expr) = custom_arg_type {
                quote! { ::std::sync::Arc::new(#expr) }
            } else if let Some(SignerAttrInfo::Static(expr)) = &signer_info {
                quote! { ::std::sync::Arc::new(::mattrs::argtypes::SignerType::new(#expr)) }
            } else {
                infer_arg_type(field_type)
            };

            quote! {
                ::mattrs::contracts::ArgSpec {
                    name: #field_name_str.to_string(),
                    arg_type: #arg_type_expr,
                }
            }
        });

        quote! {
            /// Get the argument specifications for this clause.
            pub fn arg_specs() -> Vec<::mattrs::contracts::ArgSpec> {
                vec![
                    #(#arg_spec_items),*
                ]
            }
        }
    };

    // Generate arg_specs_for_params if params type is specified
    let arg_specs_for_params_impl = if let Some(ref params_ty) = params_type {
        let arg_spec_items_for_params = fields.iter().map(|f| {
            let field_name = &f.ident;
            let field_name_str = field_name.as_ref().unwrap().to_string();
            let field_type = &f.ty;

            let signer_info = extract_signer_attr(&f.attrs);
            let custom_arg_type = extract_arg_type_attr(&f.attrs);

            let arg_type_expr = if let Some(expr) = custom_arg_type {
                quote! { ::std::sync::Arc::new(#expr) }
            } else if let Some(SignerAttrInfo::Closure(closure)) = &signer_info {
                // Use closure to get pubkey from params
                quote! { 
                    ::std::sync::Arc::new(::mattrs::argtypes::SignerType::new({
                        let f: fn(&#params_ty) -> _ = #closure;
                        f(params)
                    }))
                }
            } else if let Some(SignerAttrInfo::Static(expr)) = &signer_info {
                quote! { ::std::sync::Arc::new(::mattrs::argtypes::SignerType::new(#expr)) }
            } else {
                infer_arg_type(field_type)
            };

            quote! {
                ::mattrs::contracts::ArgSpec {
                    name: #field_name_str.to_string(),
                    arg_type: #arg_type_expr,
                }
            }
        });

        quote! {
            /// Get the argument specifications for this clause with params.
            pub fn arg_specs_for_params(params: &#params_ty) -> Vec<::mattrs::contracts::ArgSpec> {
                vec![
                    #(#arg_spec_items_for_params),*
                ]
            }
        }
    } else {
        quote! {}
    };

    // Generate `new(...)` taking only the non-signer fields. Signature fields are
    // left to `Default` (empty) and filled by the manager at spend time, so callers
    // never construct a placeholder signature.
    let ctor_params = fields
        .iter()
        .filter(|f| extract_signer_attr(&f.attrs).is_none())
        .map(|f| {
            let ident = &f.ident;
            let ty = &f.ty;
            quote! { #ident: #ty }
        });
    let ctor_field_inits = fields.iter().map(|f| {
        let ident = &f.ident;
        if extract_signer_attr(&f.attrs).is_some() {
            quote! { #ident: ::core::default::Default::default() }
        } else {
            quote! { #ident }
        }
    });
    let new_impl = quote! {
        /// Construct the clause arguments. Signature fields are left empty and are
        /// filled in by the manager at spend time.
        pub fn new(#(#ctor_params),*) -> Self {
            Self {
                #(#ctor_field_inits),*
            }
        }
    };

    let expanded = quote! {
        impl WitnessEncodable for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                let mut stack = Vec::new();
                #(#encode_fields)*
                stack
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError>
            where
                Self: Sized
            {
                let mut offset = 0;
                #(#decode_fields)*
                Ok((Self {
                    #(#field_names),*
                }, offset))
            }
        }

        impl ClauseArgs for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                <Self as WitnessEncodable>::encode_to_witness(self)
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError>
            where
                Self: Sized
            {
                let (args, _) = <Self as WitnessEncodable>::decode_from_witness(witness)?;
                Ok(args)
            }
        }

        impl #name {
            #new_impl
            #static_arg_specs_impl
            #arg_specs_for_params_impl
        }
    };

    TokenStream::from(expanded)
}

/// Information about a #[signer(...)] attribute
enum SignerAttrInfo {
    /// Static expression: #[signer(pubkey_bytes)]
    Static(proc_macro2::TokenStream),
    /// Closure expression: #[signer(|p| p.field)]
    Closure(proc_macro2::TokenStream),
}

/// Extract #[clause_args(params = Type)] from struct attributes
fn extract_params_type(attrs: &[syn::Attribute]) -> Option<syn::Type> {
    for attr in attrs {
        if attr.path().is_ident("clause_args") {
            if let Meta::List(meta_list) = &attr.meta {
                let tokens_str = meta_list.tokens.to_string();
                // Parse "params = Type"
                if let Some(type_str) = tokens_str.strip_prefix("params").map(|s| s.trim().strip_prefix('=').map(|s| s.trim())) {
                    if let Some(type_str) = type_str {
                        if let Ok(ty) = syn::parse_str::<syn::Type>(type_str) {
                            return Some(ty);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract #[signer(...)] attribute info
fn extract_signer_attr(attrs: &[syn::Attribute]) -> Option<SignerAttrInfo> {
    for attr in attrs {
        if attr.path().is_ident("signer") {
            if let Meta::List(meta_list) = &attr.meta {
                let tokens = &meta_list.tokens;
                let tokens_str = tokens.to_string();
                
                // Check if it's a closure (starts with |)
                if tokens_str.trim_start().starts_with('|') {
                    return Some(SignerAttrInfo::Closure(quote! { #tokens }));
                } else {
                    return Some(SignerAttrInfo::Static(quote! { #tokens }));
                }
            }
        }
    }
    None
}

/// Extract #[arg_type(...)] attribute
fn extract_arg_type_attr(attrs: &[syn::Attribute]) -> Option<proc_macro2::TokenStream> {
    for attr in attrs {
        if attr.path().is_ident("arg_type") {
            if let Meta::List(meta_list) = &attr.meta {
                let tokens = &meta_list.tokens;
                return Some(quote! { #tokens });
            }
        }
    }
    None
}

/// Infer the ArgType from a Rust type.
fn infer_arg_type(ty: &Type) -> proc_macro2::TokenStream {
    let type_str = quote!(#ty).to_string();
    
    // Check for common patterns
    if type_str == "Vec < u8 >" || type_str.contains("[u8") {
        quote! { ::std::sync::Arc::new(::mattrs::argtypes::BytesType) }
    } else if type_str == "i32" || type_str == "i64" {
        quote! { ::std::sync::Arc::new(::mattrs::argtypes::IntType) }
    } else {
        // Refuse to guess: an unrecognized field type is a compile error rather than
        // a silently-wrong BytesType. The user can add #[arg_type(..)]/#[signer(..)].
        let msg = format!(
            "#[derive(ClauseArgs)]: cannot infer an ArgType for field type `{}`; \
             annotate the field with #[arg_type(..)] or #[signer(..)] \
             (auto-inferred types: Vec<u8>, [u8; N], i32, i64)",
            type_str
        );
        quote! {
            {
                compile_error!(#msg);
                ::std::sync::Arc::new(::mattrs::argtypes::BytesType)
            }
        }
    }
}

/// Derive macro for ContractParams trait.
///
/// Automatically implements encoding/decoding by encoding each field's witness elements
/// and flattening them into a single byte vector.
#[proc_macro_derive(ContractParams)]
pub fn derive_contract_params(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("ContractParams only supports structs with named fields"),
        },
        _ => panic!("ContractParams can only be derived for structs"),
    };

    let encode_to_witness_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            result.extend(self.#field_name.encode_to_witness());
        }
    });

    let decode_from_witness_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        quote! {
            let (#field_name, consumed) = <#field_type as WitnessEncodable>::decode_from_witness(&witness[offset..])?;
            offset += consumed;
        }
    });

    let encode_to_bytes_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            // Encode field and prepend witness element count and sizes
            let field_witness = self.#field_name.encode_to_witness();
            // Write number of witness elements as varint (just use a u32 for simplicity)
            bytes.extend(&(field_witness.len() as u32).to_le_bytes());
            // Write each element with its length prefix
            for elem in field_witness {
                bytes.extend(&(elem.len() as u32).to_le_bytes());
                bytes.extend(&elem);
            }
        }
    });

    let decode_from_bytes_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        quote! {
            let (#field_name, consumed_bytes) = {
                // Read number of witness elements
                if byte_offset + 4 > bytes.len() {
                    return Err(WitnessError::InsufficientData);
                }
                let mut count_bytes = [0u8; 4];
                count_bytes.copy_from_slice(&bytes[byte_offset..byte_offset+4]);
                let element_count = u32::from_le_bytes(count_bytes) as usize;
                let mut local_offset = byte_offset + 4;
                
                // Read witness elements
                let mut temp_witness = Vec::new();
                for _ in 0..element_count {
                    if local_offset + 4 > bytes.len() {
                        return Err(WitnessError::InsufficientData);
                    }
                    let mut len_bytes = [0u8; 4];
                    len_bytes.copy_from_slice(&bytes[local_offset..local_offset+4]);
                    let elem_len = u32::from_le_bytes(len_bytes) as usize;
                    local_offset += 4;
                    
                    if local_offset + elem_len > bytes.len() {
                        return Err(WitnessError::InsufficientData);
                    }
                    temp_witness.push(bytes[local_offset..local_offset+elem_len].to_vec());
                    local_offset += elem_len;
                }
                
                let (value, _) = <#field_type as WitnessEncodable>::decode_from_witness(&temp_witness)?;
                (value, local_offset - byte_offset)
            };
            byte_offset += consumed_bytes;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);
    let field_names_for_bytes = fields.iter().map(|f| &f.ident);

    let expanded = quote! {
        impl WitnessEncodable for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                let mut result = Vec::new();
                #(#encode_to_witness_fields)*
                result
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
                let mut offset = 0;
                #(#decode_from_witness_fields)*
                Ok((Self {
                    #(#field_names),*
                }, offset))
            }
        }

        impl ContractParams for #name {
            fn encode(&self) -> Vec<u8> {
                let mut bytes = Vec::new();
                #(#encode_to_bytes_fields)*
                bytes
            }

            fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
                let mut byte_offset = 0;
                #(#decode_from_bytes_fields)*
                
                Ok(Self {
                    #(#field_names_for_bytes),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derive macro for ContractState trait.
///
/// Automatically implements encoding/decoding for contract state.
///
/// # Limitation: single field only
///
/// `decode()` reconstructs the state from a flat byte blob by treating it as a
/// single witness element. That is only invertible when the struct has exactly
/// one field, so the derive rejects multi-field state at compile time. Multi-field
/// state needs a deliberate commitment encoding (e.g. a hash over the fields) and
/// should implement [`ContractState`] by hand.
#[proc_macro_derive(ContractState)]
pub fn derive_contract_state(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("ContractState only supports structs with named fields"),
        },
        _ => panic!("ContractState can only be derived for structs"),
    };

    // See the doc comment: the byte-blob round-trip is only invertible for a
    // single field. Reject the rest at compile time instead of decoding wrongly.
    if fields.len() != 1 {
        panic!(
            "#[derive(ContractState)] supports exactly one field (got {}); \
             multi-field state needs a manual ContractState impl with a deliberate \
             commitment encoding",
            fields.len()
        );
    }

    let encode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            result.extend(self.#field_name.encode_to_witness());
        }
    });

    let decode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        quote! {
            let (#field_name, consumed) = <#field_type as WitnessEncodable>::decode_from_witness(&witness[offset..])?;
            offset += consumed;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);

    let expanded = quote! {
        impl WitnessEncodable for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                let mut result = Vec::new();
                #(#encode_fields)*
                result
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
                let mut offset = 0;
                #(#decode_fields)*
                Ok((Self {
                    #(#field_names),*
                }, offset))
            }
        }

        impl ContractState for #name {
            fn encode(&self) -> Vec<u8> {
                self.encode_to_witness().into_iter().flatten().collect()
            }

            fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
                // Convert bytes to witness format (single element)
                let witness = vec![bytes.to_vec()];
                let (state, _) = Self::decode_from_witness(&witness)?;
                Ok(state)
            }
        }
    };

    TokenStream::from(expanded)
}
