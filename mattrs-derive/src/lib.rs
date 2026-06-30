use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Fields, ImplItem, ItemImpl, Type, Meta};

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

    // Generate arg_specs for each field (static version without params)
    let arg_spec_items = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_name_str = field_name.as_ref().unwrap().to_string();
        let field_type = &f.ty;

        // Check for custom attributes
        let signer_info = extract_signer_attr(&f.attrs);
        let custom_arg_type = extract_arg_type_attr(&f.attrs);

        let arg_type_expr = if let Some(expr) = custom_arg_type {
            // Use custom arg type
            quote! { ::std::sync::Arc::new(#expr) }
        } else if let Some(SignerAttrInfo::Static(expr)) = &signer_info {
            // Use SignerType with static pubkey
            quote! { ::std::sync::Arc::new(crate::argtypes::SignerType::new(#expr)) }
        } else if signer_info.is_some() {
            // Has closure-based signer - use BytesType for static version
            quote! { ::std::sync::Arc::new(crate::argtypes::BytesType) }
        } else {
            // Infer from type
            infer_arg_type(field_type)
        };

        quote! {
            crate::contracts::ArgSpec {
                name: #field_name_str.to_string(),
                arg_type: #arg_type_expr,
            }
        }
    });

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
                    ::std::sync::Arc::new(crate::argtypes::SignerType::new({
                        let f: fn(&#params_ty) -> _ = #closure;
                        f(params)
                    }))
                }
            } else if let Some(SignerAttrInfo::Static(expr)) = &signer_info {
                quote! { ::std::sync::Arc::new(crate::argtypes::SignerType::new(#expr)) }
            } else {
                infer_arg_type(field_type)
            };

            quote! {
                crate::contracts::ArgSpec {
                    name: #field_name_str.to_string(),
                    arg_type: #arg_type_expr,
                }
            }
        });

        quote! {
            /// Get the argument specifications for this clause with params.
            pub fn arg_specs_for_params(params: &#params_ty) -> Vec<crate::contracts::ArgSpec> {
                vec![
                    #(#arg_spec_items_for_params),*
                ]
            }
        }
    } else {
        quote! {}
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
            /// Get the argument specifications for this clause.
            pub fn arg_specs() -> Vec<crate::contracts::ArgSpec> {
                vec![
                    #(#arg_spec_items),*
                ]
            }

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
        quote! { ::std::sync::Arc::new(crate::argtypes::BytesType) }
    } else if type_str == "i32" || type_str == "i64" {
        quote! { ::std::sync::Arc::new(crate::argtypes::IntType) }
    } else {
        // Default to BytesType for unknown types
        quote! { ::std::sync::Arc::new(crate::argtypes::BytesType) }
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
/// Automatically implements encoding/decoding for contract state.
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

/// Derive macro for Contract trait.
/// 
/// Automatically implements the Contract trait by assuming the struct has these fields:
/// - `params: ParamsType`
/// - `contract: StandardP2TR<ParamsType>`
/// - `taptree: Arc<TapTree>`
/// - `clauses: HashMap<String, Arc<dyn ErasedClause>>`
/// 
/// You can optionally have a `state` field for stateful contracts.
/// 
/// # Example
/// 
/// ```ignore
/// #[derive(Contract)]
/// pub struct Vault {
///     pub params: VaultParams,
///     pub contract: StandardP2TR<VaultParams>,
///     pub taptree: Arc<TapTree>,
///     pub clauses: HashMap<String, Arc<dyn ErasedClause>>,
/// }
/// ```
#[proc_macro_derive(Contract)]
pub fn derive_contract(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("Contract only supports structs with named fields"),
        },
        _ => panic!("Contract can only be derived for structs"),
    };

    // Find the params field to determine the Params type
    let params_field = fields
        .iter()
        .find(|f| f.ident.as_ref().unwrap() == "params")
        .expect("Contract struct must have a 'params' field");

    let params_type = &params_field.ty;

    // Check if there's a state field
    let has_state_field = fields
        .iter()
        .any(|f| f.ident.as_ref().unwrap() == "state");

    let state_type = if has_state_field {
        // Find the state field type
        let state_field = fields
            .iter()
            .find(|f| f.ident.as_ref().unwrap() == "state")
            .unwrap();
        let ty = &state_field.ty;
        quote! { #ty }
    } else {
        quote! { () }
    };

    let state_impl = if has_state_field {
        quote! {
            fn state(&self) -> Option<&Self::State> {
                Some(&self.state)
            }
        }
    } else {
        quote! {
            fn state(&self) -> Option<&Self::State> {
                None
            }
        }
    };

    let expanded = quote! {
        impl crate::contracts::Contract for #name {
            type Params = #params_type;
            type State = #state_type;

            fn params(&self) -> &Self::Params {
                &self.params
            }

            #state_impl

            fn get_clause(&self, name: &str) -> Option<&::std::sync::Arc<dyn crate::contracts::ErasedClause>> {
                self.clauses.get(name)
            }

            fn taptree(&self) -> &::std::sync::Arc<crate::contracts::TapTree> {
                &self.taptree
            }

            fn instance(&self) -> &crate::contracts::StandardP2TR<Self::Params> {
                &self.contract
            }
        }
    };

    TokenStream::from(expanded)
}

/// Attribute macro to mark contract implementation methods as clauses.
///
/// This generates an extension trait that provides functional clause calling on InstanceHandle.
///
/// # Example
/// ```ignore
/// #[clause_impl]
/// impl Vault {
///     #[clause]
///     fn trigger(&self, sig: Signature, ctv_hash: [u8; 32], out_i: i32) -> Vec<ClauseOutput> {
///         // ...
///     }
/// }
/// ```
///
/// This generates methods on `InstanceHandle` that can be called like:
/// ```ignore
/// let outputs = handle.trigger(sig, ctv_hash, out_i)?;
/// ```
#[proc_macro_attribute]
pub fn clause_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemImpl);

    // Get the contract type
    let contract_type = &input.self_ty;

    // Find all methods marked with #[clause]
    let mut clause_methods = Vec::new();
    let mut cleaned_impl_items = Vec::new();

    for item in &input.items {
        if let ImplItem::Fn(method) = item {
            let has_clause_attr = method.attrs.iter().any(|attr| {
                attr.path()
                    .segments
                    .first()
                    .map(|seg| seg.ident == "clause")
                    .unwrap_or(false)
            });

            if has_clause_attr {
                clause_methods.push(method.clone());

                // Remove the #[clause] attribute from the cleaned version
                let mut cleaned_method = method.clone();
                cleaned_method.attrs.retain(|attr| {
                    !attr
                        .path()
                        .segments
                        .first()
                        .map(|seg| seg.ident == "clause")
                        .unwrap_or(false)
                });
                cleaned_impl_items.push(ImplItem::Fn(cleaned_method));
            } else {
                cleaned_impl_items.push(item.clone());
            }
        } else {
            cleaned_impl_items.push(item.clone());
        }
    }

    // Generate the original impl block (without #[clause] attributes)
    let mut cleaned_impl = input.clone();
    cleaned_impl.items = cleaned_impl_items;

    // Generate extension trait for clause methods
    let trait_name = syn::Ident::new(
        &format!(
            "{}ClauseMethods",
            quote!(#contract_type).to_string().replace(' ', "")
        ),
        contract_type.span(),
    );

    let clause_method_impls = clause_methods.iter().map(|method| {
        let method_name = &method.sig.ident;
        let clause_name = method_name.to_string();

        // Extract parameters (skip &self)
        let params: Vec<_> = method.sig.inputs.iter().skip(1).collect();
        let param_names: Vec<_> = params
            .iter()
            .filter_map(|arg| {
                if let syn::FnArg::Typed(pat_type) = arg {
                    if let syn::Pat::Ident(ident) = &*pat_type.pat {
                        Some(&ident.ident)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        quote! {
            fn #method_name(
                &self,
                #(#params),*
            ) -> Result<Vec<mattrs::manager::InstanceHandle>, mattrs::manager::ManagerError> {
                // Build args map
                let mut args = std::collections::HashMap::new();
                #(
                    args.insert(
                        stringify!(#param_names).to_string(),
                        mattrs::argtypes::ArgValue::from(#param_names)
                    );
                )*

                // Call spend_instance on the manager
                self.manager.spend_instance(
                    self.instance.clone(),
                    #clause_name,
                    args,
                    None,
                    None,
                )
            }
        }
    });

    let expanded = quote! {
        #cleaned_impl

        /// Extension trait providing functional clause calling on InstanceHandle.
        pub trait #trait_name<'a> {
            #(#clause_method_impls)*
        }

        // Implement the trait for InstanceHandle (blanket impl would go here)
        // For now, users will need to call manager.spend_instance directly
        // or we generate specific impls
    };

    TokenStream::from(expanded)
}

/// Marker attribute for clause methods (used with #[clause_impl]).
#[proc_macro_attribute]
pub fn clause(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // This is just a marker - the actual work is done by #[clause_impl]
    item
}
