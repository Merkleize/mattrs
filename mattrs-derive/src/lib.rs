use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Data, DeriveInput, Fields, GenericArgument, PathArguments, Type};

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
///         // Optional; defaults to the NUMS key (no key-spend path).
///         internal_key |p| internal_key_or_nums(p.alternate_pk);
///
///         clause trigger {
///             args {
///                 // shorthand for `#[signer(|p| p.unvault_pk.serialize())]`
///                 #[signer(p.unvault_pk)] sig: Signature,
///                 ctv_hash: [u8; 32],
///                 out_i: i64,
///             }
///             script Vault::trigger_script;         // fn(&VaultParams) -> ScriptBuf
///             // The body yields a Result whose Ok value may be a
///             // Vec<ClauseOutput>, a CtvTemplate, or a NextOutputs —
///             // anything Into<NextOutputs> — with error type ClauseError.
///             next(p, a) { /* ... */ }
///         }
///         // ... more clauses ...
///         tree [trigger, [trigger_and_revault, recover]];
///     }
/// }
/// ```
///
/// Three optional forms cover contracts whose shape is only known at runtime
/// (see `mattrs::fraud` for a worked example of all three):
///
/// - **`ctx <Type>;`** — non-encodable construction context (script fragments,
///   factories, timeouts...). `new` becomes `new(params, ctx)` and stores the
///   ctx on the contract struct (`Type` must be `Clone`). Script/spec builder
///   exprs are then called with `(&params, &ctx)`, and `next` bodies (as well
///   as a dynamic `tree |p| ..` body) can reference the context as `ctx`.
///   Unlike params, the ctx never round-trips through `ParamEncodable`.
///
/// - **`args raw <expr>;`** — a clause whose witness layout is only known at
///   runtime. `<expr>` is called like a script builder and evaluates to the
///   clause's `Vec<ArgSpec>`; the clause uses `RawArgs`, and no `*Args` struct
///   or handle method is generated (add ergonomic spend methods in a plain
///   `impl NameHandle` block).
///
/// - **`#[from_state]`** on an `args` field — the generated handle method omits
///   the argument and fills it from the instance's typed state (the same-named
///   state field), returning `Result<SpendBuilder, MissingStateError>`. For
///   clauses that re-reveal state committed on-chain, this keeps the method's
///   parameters down to the genuinely new values. Requires a `state` section.
#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    contract::expand(input)
}

/// The named fields of a derive input, or a spanned error naming the derive.
fn named_fields<'a>(
    input: &'a DeriveInput,
    derive_name: &str,
) -> syn::Result<&'a Punctuated<syn::Field, syn::Token![,]>> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(&fields.named),
            other => Err(syn::Error::new_spanned(
                other,
                format!("{} only supports structs with named fields", derive_name),
            )),
        },
        _ => Err(syn::Error::new_spanned(
            &input.ident,
            format!("{} can only be derived for structs", derive_name),
        )),
    }
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
///   If `expr` is a closure like `|p| p.unvault_pk.serialize()`, it will be used in `arg_specs_for_params`.
/// - `#[arg_type(expr)]` - Uses a custom ArgType expression
///
/// # Default type mappings (when no attribute is specified)
/// - `Vec<u8>` -> `BytesType`
/// - `[u8; N]` -> `BytesType`
/// - `i32`, `i64` -> `IntType`
/// - `WitProof<N>` -> `MerkleProofType::new(N)`
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
///     pub sig: Signature,
///     pub ctv_hash: [u8; 32],
///     pub out_i: i64,
/// }
/// ```
#[proc_macro_derive(ClauseArgs, attributes(signer, arg_type, clause_args))]
pub fn derive_clause_args(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_clause_args(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_clause_args(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    // Check for #[clause_args(params = ParamsType)] attribute
    let params_type = extract_params_type(&input.attrs)?;

    let fields = named_fields(input, "ClauseArgs")?;

    let encode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            stack.extend(::mattrs::contracts::WitnessEncodable::encode_to_witness(
                &self.#field_name,
            ));
        }
    });

    let decode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        quote! {
            let (#field_name, consumed) = <#field_type as ::mattrs::contracts::WitnessEncodable>::decode_from_witness(&witness[offset..])?;
            offset += consumed;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);

    // Does any field use a closure-based `#[signer(|p| ..)]`? Such fields need the
    // params to build their SignerType, so only `arg_specs_for_params()` is valid.
    let mut has_closure_signer = false;
    for f in fields {
        if matches!(
            extract_signer_attr(&f.attrs)?,
            Some(SignerAttrInfo::Closure(_))
        ) {
            has_closure_signer = true;
        }
    }

    // A closure signer is meaningless without a params type to feed it.
    if has_closure_signer && params_type.is_none() {
        return Err(syn::Error::new_spanned(
            name,
            "#[derive(ClauseArgs)]: a `#[signer(|p| ..)]` field requires \
             `#[clause_args(params = ParamsType)]` on the struct",
        ));
    }

    // The static `arg_specs()` is only generated when no field depends on params
    // (i.e. no closure signer). Otherwise callers must use `arg_specs_for_params()`
    // so that signer specs can never be silently downgraded to BytesType.
    let static_arg_specs_impl = if has_closure_signer {
        quote! {}
    } else {
        let arg_spec_items = fields
            .iter()
            .map(|f| arg_spec_item(f, None))
            .collect::<syn::Result<Vec<_>>>()?;

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
        let arg_spec_items = fields
            .iter()
            .map(|f| arg_spec_item(f, Some(params_ty)))
            .collect::<syn::Result<Vec<_>>>()?;

        quote! {
            /// Get the argument specifications for this clause with params.
            pub fn arg_specs_for_params(params: &#params_ty) -> Vec<::mattrs::contracts::ArgSpec> {
                vec![
                    #(#arg_spec_items),*
                ]
            }
        }
    } else {
        quote! {}
    };

    // Generate `new(...)` taking only the non-signer fields. Signature fields are
    // left to `Default` (empty) and filled by the manager at spend time, so callers
    // never construct a placeholder signature.
    let mut ctor_params = Vec::new();
    let mut ctor_field_inits = Vec::new();
    for f in fields {
        let ident = &f.ident;
        if extract_signer_attr(&f.attrs)?.is_some() {
            ctor_field_inits.push(quote! { #ident: ::core::default::Default::default() });
        } else {
            let ty = &f.ty;
            ctor_params.push(quote! { #ident: #ty });
            ctor_field_inits.push(quote! { #ident });
        }
    }
    let new_impl = quote! {
        /// Construct the clause arguments. Signature fields are left empty and are
        /// filled in by the manager at spend time.
        #[allow(clippy::too_many_arguments)]
        pub fn new(#(#ctor_params),*) -> Self {
            Self {
                #(#ctor_field_inits),*
            }
        }
    };

    Ok(quote! {
        impl ::mattrs::contracts::WitnessEncodable for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                let mut stack = Vec::new();
                #(#encode_fields)*
                stack
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> ::core::result::Result<(Self, usize), ::mattrs::contracts::WitnessError>
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

        impl ::mattrs::contracts::ClauseArgs for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                <Self as ::mattrs::contracts::WitnessEncodable>::encode_to_witness(self)
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> ::core::result::Result<Self, ::mattrs::contracts::WitnessError>
            where
                Self: Sized
            {
                let (args, _) = <Self as ::mattrs::contracts::WitnessEncodable>::decode_from_witness(witness)?;
                Ok(args)
            }
        }

        impl #name {
            #new_impl
            #static_arg_specs_impl
            #arg_specs_for_params_impl
        }
    })
}

/// One `ArgSpec { name, arg_type }` item for a field. `params_ty` is `Some` when
/// generating `arg_specs_for_params` (where closure signers are usable) and `None`
/// for the static `arg_specs()`.
fn arg_spec_item(field: &syn::Field, params_ty: Option<&Type>) -> syn::Result<TokenStream2> {
    let field_name_str = field.ident.as_ref().unwrap().to_string();

    let signer_info = extract_signer_attr(&field.attrs)?;
    let custom_arg_type = extract_arg_type_attr(&field.attrs)?;

    if signer_info.is_some() && custom_arg_type.is_some() {
        return Err(syn::Error::new_spanned(
            field,
            "#[signer(..)] and #[arg_type(..)] cannot both be applied to one field",
        ));
    }

    let arg_type_expr = if let Some(expr) = custom_arg_type {
        quote! { ::std::sync::Arc::new(#expr) }
    } else {
        match (signer_info, params_ty) {
            (Some(SignerAttrInfo::Closure(closure)), Some(params_ty)) => quote! {
                ::std::sync::Arc::new(::mattrs::argtypes::SignerType::new({
                    let f: fn(&#params_ty) -> _ = #closure;
                    f(params)
                }))
            },
            (Some(SignerAttrInfo::Closure(_)), None) => {
                // Unreachable from the derive (closure signers suppress the static
                // arg_specs()), but keep a real error rather than a panic.
                return Err(syn::Error::new_spanned(
                    field,
                    "a `#[signer(|p| ..)]` field cannot appear in a static arg_specs()",
                ));
            }
            (Some(SignerAttrInfo::Static(expr)), _) => {
                quote! { ::std::sync::Arc::new(::mattrs::argtypes::SignerType::new(#expr)) }
            }
            (None, _) => infer_arg_type(&field.ty),
        }
    };

    Ok(quote! {
        ::mattrs::contracts::ArgSpec {
            name: #field_name_str.to_string(),
            arg_type: #arg_type_expr,
        }
    })
}

/// Information about a #[signer(...)] attribute
enum SignerAttrInfo {
    /// Static expression: #[signer(pubkey_bytes)]
    Static(TokenStream2),
    /// Closure expression: #[signer(|p| p.field.serialize())]
    Closure(TokenStream2),
}

/// Extract `#[clause_args(params = Type)]` from struct attributes.
fn extract_params_type(attrs: &[syn::Attribute]) -> syn::Result<Option<Type>> {
    struct ParamsArg(Type);
    impl syn::parse::Parse for ParamsArg {
        fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
            let ident: syn::Ident = input.parse()?;
            if ident != "params" {
                return Err(syn::Error::new(ident.span(), "expected `params = <Type>`"));
            }
            input.parse::<syn::Token![=]>()?;
            Ok(ParamsArg(input.parse()?))
        }
    }

    for attr in attrs {
        if attr.path().is_ident("clause_args") {
            let ParamsArg(ty) = attr.parse_args()?;
            return Ok(Some(ty));
        }
    }
    Ok(None)
}

/// Extract #[signer(...)] attribute info.
fn extract_signer_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<SignerAttrInfo>> {
    for attr in attrs {
        if attr.path().is_ident("signer") {
            let expr: syn::Expr = attr.parse_args()?;
            return Ok(Some(match expr {
                syn::Expr::Closure(_) => SignerAttrInfo::Closure(quote! { #expr }),
                _ => SignerAttrInfo::Static(quote! { #expr }),
            }));
        }
    }
    Ok(None)
}

/// Extract #[arg_type(...)] attribute.
fn extract_arg_type_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<TokenStream2>> {
    for attr in attrs {
        if attr.path().is_ident("arg_type") {
            let expr: syn::Expr = attr.parse_args()?;
            return Ok(Some(quote! { #expr }));
        }
    }
    Ok(None)
}

/// Whether a type is a path of exactly one segment named `ident` with no generics
/// (`u8`, `i64`, ...).
fn is_plain_ident(ty: &Type, ident: &str) -> bool {
    matches!(ty, Type::Path(tp) if tp.qself.is_none()
        && tp.path.segments.len() == 1
        && tp.path.segments[0].ident == ident
        && tp.path.segments[0].arguments.is_none())
}

/// Infer the ArgType from a Rust type.
fn infer_arg_type(ty: &Type) -> TokenStream2 {
    // [u8; N] — one Bytes element.
    if let Type::Array(arr) = ty {
        if is_plain_ident(&arr.elem, "u8") {
            return quote! { ::std::sync::Arc::new(::mattrs::argtypes::BytesType) };
        }
    }

    // i32 / i64 — one script-number element.
    if is_plain_ident(ty, "i32") || is_plain_ident(ty, "i64") {
        return quote! { ::std::sync::Arc::new(::mattrs::argtypes::IntType) };
    }

    if let Type::Path(tp) = ty {
        if let Some(last) = tp.path.segments.last() {
            // Vec<u8> (any path prefix) — one Bytes element.
            if last.ident == "Vec" {
                if let PathArguments::AngleBracketed(args) = &last.arguments {
                    if args.args.len() == 1 {
                        if let GenericArgument::Type(elem) = &args.args[0] {
                            if is_plain_ident(elem, "u8") {
                                return quote! {
                                    ::std::sync::Arc::new(::mattrs::argtypes::BytesType)
                                };
                            }
                        }
                    }
                }
            }

            // WitProof<N> — a depth-N Merkle proof occupying 2N+1 elements.
            if last.ident == "WitProof" {
                if let PathArguments::AngleBracketed(args) = &last.arguments {
                    if args.args.len() == 1 {
                        let depth = &args.args[0];
                        return quote! {
                            ::std::sync::Arc::new(::mattrs::merkle::MerkleProofType::new(#depth))
                        };
                    }
                }
            }
        }
    }

    // Refuse to guess: an unrecognized field type is a compile error rather than
    // a silently-wrong BytesType. The user can add #[arg_type(..)]/#[signer(..)].
    let msg = format!(
        "#[derive(ClauseArgs)]: cannot infer an ArgType for field type `{}`; \
         annotate the field with #[arg_type(..)] or #[signer(..)] \
         (auto-inferred types: Vec<u8>, [u8; N], i32, i64, WitProof<N>)",
        quote!(#ty)
    );
    quote! {
        {
            compile_error!(#msg);
            ::std::sync::Arc::new(::mattrs::argtypes::BytesType)
        }
    }
}

/// Derive macro for the ContractParams trait.
///
/// Implements the params' internal (non-consensus) serialization: it also derives
/// [`ParamEncodable`](../mattrs/contracts/trait.ParamEncodable.html) for the struct,
/// then frames each field's elements (length-prefixed) into a single byte vector.
/// Because params use `ParamEncodable` — the superset that also covers the
/// fixed-width unsigned integers — a params field may be a `u32` (e.g. a CSV
/// delay), unlike a clause argument or a state leaf, which must be witness elements.
#[proc_macro_derive(ContractParams)]
pub fn derive_contract_params(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_contract_params(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_contract_params(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let fields = named_fields(input, "ContractParams")?;

    let encode_param_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            result.extend(::mattrs::contracts::ParamEncodable::encode_param(
                &self.#field_name,
            ));
        }
    });

    let decode_param_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        quote! {
            let (#field_name, consumed) = <#field_type as ::mattrs::contracts::ParamEncodable>::decode_param(&elements[offset..])?;
            offset += consumed;
        }
    });

    let encode_to_bytes_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            // Encode field and prepend its element count and sizes.
            let field_elements =
                ::mattrs::contracts::ParamEncodable::encode_param(&self.#field_name);
            // Write number of elements as a u32.
            bytes.extend(&(field_elements.len() as u32).to_le_bytes());
            // Write each element with its length prefix.
            for elem in field_elements {
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
                    return Err(::mattrs::contracts::WitnessError::InsufficientData);
                }
                let mut count_bytes = [0u8; 4];
                count_bytes.copy_from_slice(&bytes[byte_offset..byte_offset+4]);
                let element_count = u32::from_le_bytes(count_bytes) as usize;
                let mut local_offset = byte_offset + 4;

                // Read witness elements
                let mut temp_witness = Vec::new();
                for _ in 0..element_count {
                    if local_offset + 4 > bytes.len() {
                        return Err(::mattrs::contracts::WitnessError::InsufficientData);
                    }
                    let mut len_bytes = [0u8; 4];
                    len_bytes.copy_from_slice(&bytes[local_offset..local_offset+4]);
                    let elem_len = u32::from_le_bytes(len_bytes) as usize;
                    local_offset += 4;

                    if local_offset + elem_len > bytes.len() {
                        return Err(::mattrs::contracts::WitnessError::InsufficientData);
                    }
                    temp_witness.push(bytes[local_offset..local_offset+elem_len].to_vec());
                    local_offset += elem_len;
                }

                let (value, _) = <#field_type as ::mattrs::contracts::ParamEncodable>::decode_param(&temp_witness)?;
                (value, local_offset - byte_offset)
            };
            byte_offset += consumed_bytes;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);
    let field_names_for_bytes = fields.iter().map(|f| &f.ident);

    Ok(quote! {
        impl ::mattrs::contracts::ParamEncodable for #name {
            fn encode_param(&self) -> Vec<Vec<u8>> {
                let mut result = Vec::new();
                #(#encode_param_fields)*
                result
            }

            fn decode_param(elements: &[Vec<u8>]) -> ::core::result::Result<(Self, usize), ::mattrs::contracts::WitnessError> {
                let mut offset = 0;
                #(#decode_param_fields)*
                Ok((Self {
                    #(#field_names),*
                }, offset))
            }
        }

        impl ::mattrs::contracts::ContractParams for #name {
            fn encode(&self) -> Vec<u8> {
                let mut bytes = Vec::new();
                #(#encode_to_bytes_fields)*
                bytes
            }

            fn decode(bytes: &[u8]) -> ::core::result::Result<Self, ::mattrs::contracts::WitnessError> {
                let mut byte_offset = 0;
                #(#decode_from_bytes_fields)*

                Ok(Self {
                    #(#field_names_for_bytes),*
                })
            }
        }
    })
}

/// How a `#[commit(merkle)]` state field contributes Merkle leaves.
enum LeafKind {
    /// The field is a `[u8; 32]`, used directly as one leaf.
    Raw,
    /// One leaf: the sha256 of the field's witness encoding (e.g. for an `i64`,
    /// `sha256(bn2vch(v))`).
    Sha256,
    /// The field iterates over `[u8; 32]` leaves (e.g. `Vec<[u8; 32]>`).
    Each,
}

/// Extract `#[leaf(sha256)]` / `#[leaf(each)]` from a state field.
fn extract_leaf_kind(field: &syn::Field) -> syn::Result<LeafKind> {
    for attr in &field.attrs {
        if attr.path().is_ident("leaf") {
            let ident: syn::Ident = attr.parse_args()?;
            return match ident.to_string().as_str() {
                "sha256" => Ok(LeafKind::Sha256),
                "each" => Ok(LeafKind::Each),
                other => Err(syn::Error::new(
                    ident.span(),
                    format!("unknown leaf kind `{}` (expected `sha256` or `each`)", other),
                )),
            };
        }
    }
    Ok(LeafKind::Raw)
}

/// Derive macro for ContractState trait.
///
/// # Default: single-field identity encoding
///
/// Without attributes, `encode()` is the field's raw witness bytes and `decode()`
/// reconstructs it from them. That round-trip is only invertible when the struct
/// has exactly one field, so the attribute-less derive rejects multi-field state
/// at compile time.
///
/// # `#[commit(merkle)]`: hash-committed (lossy) state
///
/// With `#[commit(merkle)]` on the struct, `encode()` is the Merkle root (see
/// `mattrs::merkle::MerkleTree`) of the fields' leaves, in declaration order, and
/// `decode()` fails — the state cannot be recovered from its commitment and rides
/// along as the instance's expanded state instead. Per-field leaf forms:
///
/// - default: the field is a `[u8; 32]`, used directly as one leaf;
/// - `#[leaf(sha256)]`: one leaf, the sha256 of the field's witness encoding
///   (for an `i64`, `sha256(bn2vch(v))`);
/// - `#[leaf(each)]`: the field iterates over `[u8; 32]` leaves (e.g.
///   `Vec<[u8; 32]>`).
///
/// ```ignore
/// #[derive(Debug, Clone, ContractState)]
/// #[commit(merkle)]
/// pub struct G256S2State {
///     pub t_a: [u8; 32],
///     #[leaf(sha256)]
///     pub y: i64,
///     #[leaf(sha256)]
///     pub x: i64,
/// }
/// ```
#[proc_macro_derive(ContractState, attributes(commit, leaf))]
pub fn derive_contract_state(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_contract_state(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_contract_state(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let fields = named_fields(input, "ContractState")?;

    // #[commit(merkle)] on the struct selects the hash-committed form.
    let mut merkle_commit = false;
    for attr in &input.attrs {
        if attr.path().is_ident("commit") {
            let ident: syn::Ident = attr.parse_args()?;
            if ident != "merkle" {
                return Err(syn::Error::new(
                    ident.span(),
                    format!("unknown commitment `{}` (expected `merkle`)", ident),
                ));
            }
            merkle_commit = true;
        }
    }

    if merkle_commit {
        return expand_merkle_state(name, fields);
    }

    // A #[leaf(..)] attribute only makes sense under #[commit(merkle)].
    for f in fields {
        if f.attrs.iter().any(|a| a.path().is_ident("leaf")) {
            return Err(syn::Error::new_spanned(
                f,
                "#[leaf(..)] requires #[commit(merkle)] on the struct",
            ));
        }
    }

    // Identity encoding: the byte-blob round-trip is only invertible for a
    // single field. Reject the rest at compile time instead of decoding wrongly.
    if fields.len() != 1 {
        return Err(syn::Error::new_spanned(
            name,
            format!(
                "#[derive(ContractState)] without #[commit(merkle)] supports exactly \
                 one field (got {}); commit multi-field state with #[commit(merkle)] \
                 or implement ContractState by hand",
                fields.len()
            ),
        ));
    }

    let encode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            result.extend(::mattrs::contracts::WitnessEncodable::encode_to_witness(
                &self.#field_name,
            ));
        }
    });

    let decode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        quote! {
            let (#field_name, consumed) = <#field_type as ::mattrs::contracts::WitnessEncodable>::decode_from_witness(&witness[offset..])?;
            offset += consumed;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);

    Ok(quote! {
        impl ::mattrs::contracts::WitnessEncodable for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                let mut result = Vec::new();
                #(#encode_fields)*
                result
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> ::core::result::Result<(Self, usize), ::mattrs::contracts::WitnessError> {
                let mut offset = 0;
                #(#decode_fields)*
                Ok((Self {
                    #(#field_names),*
                }, offset))
            }
        }

        impl ::mattrs::contracts::ContractState for #name {
            fn encode(&self) -> Vec<u8> {
                ::mattrs::contracts::WitnessEncodable::encode_to_witness(self)
                    .into_iter()
                    .flatten()
                    .collect()
            }

            fn decode(bytes: &[u8]) -> ::core::result::Result<Self, ::mattrs::contracts::WitnessError> {
                // Convert bytes to witness format (single element)
                let witness = vec![bytes.to_vec()];
                let (state, _) =
                    <Self as ::mattrs::contracts::WitnessEncodable>::decode_from_witness(&witness)?;
                Ok(state)
            }
        }
    })
}

/// The `#[commit(merkle)]` expansion: encode = Merkle root of the fields' leaves,
/// decode = error (the commitment is lossy; the logical state rides along as the
/// instance's expanded state).
fn expand_merkle_state(
    name: &syn::Ident,
    fields: &Punctuated<syn::Field, syn::Token![,]>,
) -> syn::Result<TokenStream2> {
    let mut leaf_pushes = Vec::new();
    for f in fields {
        let field_name = &f.ident;
        leaf_pushes.push(match extract_leaf_kind(f)? {
            LeafKind::Raw => quote! {
                leaves.push(self.#field_name);
            },
            LeafKind::Sha256 => quote! {
                leaves.push(::bitcoin::hashes::Hash::to_byte_array(
                    <::bitcoin::hashes::sha256::Hash as ::bitcoin::hashes::Hash>::hash(
                        &::mattrs::contracts::WitnessEncodable::encode_to_witness(
                            &self.#field_name,
                        )
                        .concat(),
                    ),
                ));
            },
            LeafKind::Each => quote! {
                leaves.extend(self.#field_name.iter().copied());
            },
        });
    }

    let decode_msg = format!(
        "{} cannot be recovered from its Merkle-root commitment",
        name
    );

    Ok(quote! {
        impl ::mattrs::contracts::ContractState for #name {
            fn encode(&self) -> Vec<u8> {
                let mut leaves: Vec<[u8; 32]> = Vec::new();
                #(#leaf_pushes)*
                ::mattrs::merkle::MerkleTree::new(leaves).root().to_vec()
            }

            fn decode(_bytes: &[u8]) -> ::core::result::Result<Self, ::mattrs::contracts::WitnessError> {
                Err(::mattrs::contracts::WitnessError::InvalidData(#decode_msg.to_string()))
            }
        }
    })
}
