use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

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
///                 // shorthand for `#[signer(|p| p.unvault_pk)]`
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
/// Optional `validate |p| ...;` performs contract-wide checks before keys,
/// scripts, or child contracts are built. It returns `Result<(), ContractError>`
/// and receives `(&params, &ctx)` when construction context is declared.
/// Use it to reject invalid shared parameters before nested constructors run.
///
/// Every builder section (`script`, `timelock`, `args raw`, `internal_key`, a
/// dynamic `tree`) may evaluate to its value or to a `Result<_, ContractError>`
/// of it: a script that needs a child
/// contract's taptree root writes `Child::new(..)?.taptree_root()` and the
/// failure surfaces from `Name::new` instead of panicking.
///
/// A clause's `timelock |p| ...;` returns a block count (`u32`) in 1..=65,535.
/// Construction rejects invalid delays; valid delays prepend `CSV DROP` to
/// the script and set metadata used to validate the spending input's sequence.
///
/// Three optional forms cover contracts whose shape is only known at runtime
/// (see `mattrs::fraud` for a worked example of all three):
///
/// - **`ctx <Type>;`** — construction context kept apart from the params (script fragments,
///   factories, timeouts...). `new` becomes `new(params, ctx)` and stores the
///   ctx on the contract struct (`Type` must be `Clone`). Script/spec builder
///   exprs are then called with `(&params, &ctx)`, and `next` bodies (as well
///   as a dynamic `tree |p| ..` body) can reference the context as `ctx`.
///
/// - **`args raw <expr>;`** — a clause whose witness layout is only known at
///   runtime. `<expr>` is called like a script builder and evaluates to the
///   clause's `Vec<ArgSpec>`; the clause uses `RawArgs`, and no `*Args` struct
///   or handle method is generated (add ergonomic spend methods in a plain
///   `impl NameHandle` block).
///
/// - **`#[from_state]`** on an `args` field — the generated handle method omits
///   the argument and fills it from the instance's typed state (the same-named
///   state field). For clauses that re-reveal state committed on-chain, this
///   keeps the method's parameters down to the genuinely new values. Requires a
///   `state` section.
///
/// A contract with a `state <Type>;` section is *augmented*: `fund` and
/// `address` take the state, the handle gains `state()`, and a clause's
/// `next(p, a, s)` receives `s: &Type`. Without one the state type is `()`.
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
/// - `#[signer(expr)]` - Creates a SignerType for the given `XOnlyPublicKey` expression.
///   If `expr` is a closure like `|p| p.unvault_pk`, it will be used in `arg_specs_for_params`.
/// - `#[arg_type(expr)]` - Uses a custom ArgType expression
///
/// # Witness layout
///
/// A field without an attribute may be of any `WitnessEncodable` type —
/// integers, byte arrays, `bool`, `XOnlyPublicKey`, `Option<T>`, `WitProof<N>`,
/// a type alias, or your own type. Its spec is `TypedArg<FieldType>`: the
/// layout is whatever the type's own codec consumes, so it cannot disagree
/// with the encoding.
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
///     #[signer(|p| p.unvault_pk)]
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
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

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
    let element_counts = fields.iter().map(|f| {
        let ty = &f.ty;
        quote! { <#ty as ::mattrs::contracts::WitnessEncodable>::ELEMENTS }
    });

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
        impl #impl_generics ::mattrs::contracts::WitnessEncodable for #name #ty_generics #where_clause {
            const ELEMENTS: ::core::option::Option<usize> =
                ::mattrs::contracts::__sum_elements(&[#(#element_counts),*]);

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

        impl #impl_generics ::mattrs::contracts::ClauseArgs for #name #ty_generics #where_clause {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                <Self as ::mattrs::contracts::WitnessEncodable>::encode_to_witness(self)
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> ::core::result::Result<Self, ::mattrs::contracts::WitnessError>
            where
                Self: Sized
            {
                let (args, consumed) = <Self as ::mattrs::contracts::WitnessEncodable>::decode_from_witness(witness)?;
                if consumed != witness.len() {
                    return Err(::mattrs::contracts::WitnessError::InvalidData(
                        format!(
                            "{} decoded {} of {} witness element(s)",
                            ::core::stringify!(#name),
                            consumed,
                            witness.len(),
                        ),
                    ));
                }
                Ok(args)
            }
        }

        impl #impl_generics #name #ty_generics #where_clause {
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
    if signer_info.is_some()
        && !matches!(
            &field.ty,
            Type::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "Signature")
        )
    {
        return Err(syn::Error::new_spanned(
            &field.ty,
            "a `#[signer(..)]` field must have type `Signature`",
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
    /// Closure expression: #[signer(|p| p.field)]
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

    let mut result = None;
    for attr in attrs {
        if attr.path().is_ident("clause_args") {
            let ParamsArg(ty) = attr.parse_args()?;
            if result.replace(ty).is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[clause_args(..)]` attribute",
                ));
            }
        }
    }
    Ok(result)
}

/// Extract #[signer(...)] attribute info.
fn extract_signer_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<SignerAttrInfo>> {
    let mut result = None;
    for attr in attrs {
        if attr.path().is_ident("signer") {
            let expr: syn::Expr = attr.parse_args()?;
            let value = match expr {
                syn::Expr::Closure(_) => SignerAttrInfo::Closure(quote! { #expr }),
                _ => SignerAttrInfo::Static(quote! { #expr }),
            };
            if result.replace(value).is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[signer(..)]` attribute",
                ));
            }
        }
    }
    Ok(result)
}

/// Extract #[arg_type(...)] attribute.
fn extract_arg_type_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<TokenStream2>> {
    let mut result = None;
    for attr in attrs {
        if attr.path().is_ident("arg_type") {
            let expr: syn::Expr = attr.parse_args()?;
            if result.replace(quote! { #expr }).is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[arg_type(..)]` attribute",
                ));
            }
        }
    }
    Ok(result)
}

/// The ArgType of a plain field: its own witness codec (`TypedArg<T>`), so any
/// `WitnessEncodable` type works and the layout cannot drift from the encoding.
fn infer_arg_type(ty: &Type) -> TokenStream2 {
    quote! { ::std::sync::Arc::new(::mattrs::argtypes::TypedArg::<#ty>::new()) }
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
    let mut result = None;
    for attr in &field.attrs {
        if attr.path().is_ident("leaf") {
            let ident: syn::Ident = attr.parse_args()?;
            let kind = match ident.to_string().as_str() {
                "sha256" => LeafKind::Sha256,
                "each" => LeafKind::Each,
                other => Err(syn::Error::new(
                    ident.span(),
                    format!(
                        "unknown leaf kind `{}` (expected `sha256` or `each`)",
                        other
                    ),
                ))?,
            };
            if result.replace(kind).is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[leaf(..)]` attribute",
                ));
            }
        }
    }
    Ok(result.unwrap_or(LeafKind::Raw))
}

/// Derive macro for ContractState trait.
///
/// An explicit `#[commit(identity)]`, `#[commit(sha256)]`, or `#[commit(merkle)]`
/// is required; there is no length-dependent default.
///
/// # Single-field identity or SHA256 commitments
///
/// `identity` commits the field's one witness element verbatim. `sha256` hashes
/// that element regardless of its length. Both also implement the independent
/// `StateCodec` trait: `encode()` serializes the field's witness element and
/// `decode()` reconstructs it from those serialized bytes (not from the hash).
/// The field type must implement
/// `SingleWitnessElement`; variable- and multi-element encodings are rejected.
/// These two forms accept exactly one field. Multi-field state must
/// use `#[commit(merkle)]` or a manual implementation.
///
/// # `#[commit(merkle)]`: hash-committed (lossy) state
///
/// With `#[commit(merkle)]` on the struct, `commitment()` is the Merkle root (see
/// `mattrs::merkle::MerkleTree`) of the fields' leaves, in declaration order, and
/// no `StateCodec` is generated — the state cannot be recovered from its
/// commitment and rides along as the instance's expanded state instead.
/// Applications may implement a separate codec for those leaves. Per-field forms:
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
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let fields = named_fields(input, "ContractState")?;

    let mut commitment = None;
    for attr in &input.attrs {
        if attr.path().is_ident("commit") {
            if commitment.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[commit(..)]` attribute",
                ));
            }
            let ident: syn::Ident = attr.parse_args()?;
            if ident != "merkle" && ident != "identity" && ident != "sha256" {
                return Err(syn::Error::new(
                    ident.span(),
                    format!(
                        "unknown commitment `{}` (expected `identity`, `sha256`, or `merkle`)",
                        ident
                    ),
                ));
            }
            commitment = Some(ident);
        }
    }

    let commitment = commitment.ok_or_else(|| syn::Error::new_spanned(
        name, "ContractState requires an explicit #[commit(identity)], #[commit(sha256)], or #[commit(merkle)]"
    ))?;
    if commitment == "merkle" {
        return expand_merkle_state(name, fields, &impl_generics, &ty_generics, where_clause);
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
    let element_counts = fields.iter().map(|f| {
        let ty = &f.ty;
        quote! { <#ty as ::mattrs::contracts::WitnessEncodable>::ELEMENTS }
    });
    let only_field = fields.first().expect("length checked above");
    let field_type = &only_field.ty;
    let state_field_name = only_field.ident.as_ref().expect("named fields");
    let commit_expr = if commitment == "identity" {
        quote! { ::mattrs::contracts::StateCommitment::identity(bytes) }
    } else {
        quote! { ::mattrs::contracts::StateCommitment::sha256(&bytes) }
    };

    Ok(quote! {
        impl #impl_generics ::mattrs::contracts::WitnessEncodable for #name #ty_generics #where_clause {
            const ELEMENTS: ::core::option::Option<usize> =
                ::mattrs::contracts::__sum_elements(&[#(#element_counts),*]);

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

        impl #impl_generics ::mattrs::contracts::ContractState for #name #ty_generics #where_clause {
            fn commitment(&self) -> ::mattrs::contracts::StateCommitment {
                let bytes = <Self as ::mattrs::contracts::StateCodec>::encode(self);
                #commit_expr
            }
        }

        impl #impl_generics ::mattrs::contracts::StateCodec for #name #ty_generics #where_clause {
            fn encode(&self) -> Vec<u8> {
                fn assert_single<T: ::mattrs::contracts::SingleWitnessElement>() {}
                assert_single::<#field_type>();
                <#field_type as ::mattrs::contracts::SingleWitnessElement>::encode_single(
                    &self.#state_field_name
                ).expect("SingleWitnessElement contract violated")
            }

            fn decode(bytes: &[u8]) -> ::core::result::Result<Self, ::mattrs::contracts::WitnessError> {
                fn assert_single<T: ::mattrs::contracts::SingleWitnessElement>() {}
                assert_single::<#field_type>();
                let value = <#field_type as ::mattrs::contracts::SingleWitnessElement>::decode_single(
                    bytes.to_vec()
                )?;
                Ok(Self { #state_field_name: value })
            }
        }
    })
}

/// The `#[commit(merkle)]` expansion: commitment = Merkle root of the fields'
/// leaves. No serialization codec is generated for this lossy commitment.
fn expand_merkle_state(
    name: &syn::Ident,
    fields: &Punctuated<syn::Field, syn::Token![,]>,
    impl_generics: &syn::ImplGenerics<'_>,
    ty_generics: &syn::TypeGenerics<'_>,
    where_clause: Option<&syn::WhereClause>,
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

    Ok(quote! {
        impl #impl_generics ::mattrs::contracts::ContractState for #name #ty_generics #where_clause {
            fn commitment(&self) -> ::mattrs::contracts::StateCommitment {
                let mut leaves: Vec<[u8; 32]> = Vec::new();
                #(#leaf_pushes)*
                ::mattrs::contracts::StateCommitment::identity(
                    ::mattrs::merkle::MerkleTree::new(leaves).root().to_vec()
                )
            }
        }
    })
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn commitment_strategy_is_required_and_validated() {
        for (input, expected) in [
            (
                syn::parse_quote!(
                    struct State {
                        value: [u8; 32],
                    }
                ),
                "requires an explicit",
            ),
            (
                syn::parse_quote!(
                    #[commit(unknown)]
                    struct State {
                        value: [u8; 32],
                    }
                ),
                "unknown commitment",
            ),
            (
                syn::parse_quote!(
                    #[commit(identity)]
                    #[commit(sha256)]
                    struct State {
                        value: [u8; 32],
                    }
                ),
                "duplicate",
            ),
            (
                syn::parse_quote!(
                    #[commit(identity)]
                    struct State {
                        a: i64,
                        b: i64,
                    }
                ),
                "exactly one field",
            ),
            (
                syn::parse_quote!(
                    #[commit(sha256)]
                    struct State {
                        #[leaf(sha256)]
                        value: i64,
                    }
                ),
                "requires #[commit(merkle)]",
            ),
        ] {
            let error = expand_contract_state(&input).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn all_explicit_strategies_expand() {
        for input in [
            syn::parse_quote!(
                #[commit(identity)]
                struct State {
                    value: [u8; 32],
                }
            ),
            syn::parse_quote!(
                #[commit(sha256)]
                struct State {
                    value: i64,
                }
            ),
            syn::parse_quote!(
                #[commit(merkle)]
                struct State {
                    value: [u8; 32],
                }
            ),
        ] {
            assert!(expand_contract_state(&input).is_ok());
        }
    }
}
