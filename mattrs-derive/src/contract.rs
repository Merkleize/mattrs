//! Implementation of the `contract! { .. }` function-like macro.
//!
//! The macro parses a small DSL describing a MATT contract — its params/state
//! types, taproot internal key, clauses (typed args + a script-builder fn + an
//! optional `next` outputs body), and the taptree shape — and expands it to the
//! ordinary `mattrs` primitives (`StandardClause`, `ClauseTree`, `StandardP2TR` /
//! `StandardAugmentedP2TR`) plus a typed handle with one spend method per clause.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{
    braced, bracketed, parenthesized, Attribute, Block, Expr, Field, Ident, Pat, Token, Type,
};

/// A parsed `contract! { contract Name { .. } }` definition.
struct ContractDef {
    name: Ident,
    params_ty: Type,
    state_ty: Option<Type>,
    ikey_param: Ident,
    ikey_body: Expr,
    clauses: Vec<ClauseDef>,
    tree_tokens: TokenStream2,
}

struct ClauseDef {
    name: Ident,
    fields: Vec<ClauseField>,
    script_expr: Expr,
    next: Option<NextDef>,
}

struct ClauseField {
    attrs: Vec<Attribute>,
    is_signer: bool,
    name: Ident,
    ty: Type,
}

struct NextDef {
    p: Ident,
    a: Ident,
    s: Option<Ident>,
    body: Block,
}

impl Parse for ContractDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let kw: Ident = input.parse()?;
        if kw != "contract" {
            return Err(syn::Error::new(kw.span(), "expected `contract`"));
        }
        let name: Ident = input.parse()?;
        let name_span = name.span();

        let body;
        braced!(body in input);

        let mut params_ty: Option<Type> = None;
        let mut state_ty: Option<Type> = None;
        let mut ikey: Option<(Ident, Expr)> = None;
        let mut clauses: Vec<ClauseDef> = Vec::new();
        let mut tree_tokens: Option<TokenStream2> = None;

        while !body.is_empty() {
            let section: Ident = body.parse()?;
            match section.to_string().as_str() {
                "params" => {
                    params_ty = Some(body.parse()?);
                    body.parse::<Token![;]>()?;
                }
                "state" => {
                    state_ty = Some(body.parse()?);
                    body.parse::<Token![;]>()?;
                }
                "internal_key" => {
                    let closure: syn::ExprClosure = body.parse()?;
                    let p = closure_ident(&closure)?;
                    ikey = Some((p, *closure.body));
                    body.parse::<Token![;]>()?;
                }
                "clause" => {
                    clauses.push(parse_clause(&body)?);
                }
                "tree" => {
                    let content;
                    bracketed!(content in body);
                    tree_tokens = Some(content.parse()?);
                    body.parse::<Token![;]>()?;
                }
                other => {
                    return Err(syn::Error::new(
                        section.span(),
                        format!("unexpected section `{}`", other),
                    ));
                }
            }
        }

        let (ikey_param, ikey_body) = ikey
            .ok_or_else(|| syn::Error::new(name_span, "missing `internal_key |p| ..;`"))?;

        Ok(ContractDef {
            name,
            params_ty: params_ty
                .ok_or_else(|| syn::Error::new(name_span, "missing `params <Type>;`"))?,
            state_ty,
            ikey_param,
            ikey_body,
            clauses,
            tree_tokens: tree_tokens
                .ok_or_else(|| syn::Error::new(name_span, "missing `tree [ .. ];`"))?,
        })
    }
}

fn parse_clause(input: ParseStream) -> syn::Result<ClauseDef> {
    let name: Ident = input.parse()?;
    let name_span = name.span();
    let body;
    braced!(body in input);

    let mut fields: Vec<ClauseField> = Vec::new();
    let mut script_expr: Option<Expr> = None;
    let mut next: Option<NextDef> = None;

    while !body.is_empty() {
        let section: Ident = body.parse()?;
        match section.to_string().as_str() {
            "args" => {
                let args_body;
                braced!(args_body in body);
                while !args_body.is_empty() {
                    let field = args_body.call(Field::parse_named)?;
                    let is_signer = field.attrs.iter().any(|a| a.path().is_ident("signer"));
                    let ident = field
                        .ident
                        .clone()
                        .ok_or_else(|| syn::Error::new_spanned(&field, "clause args need names"))?;
                    fields.push(ClauseField {
                        attrs: field.attrs.clone(),
                        is_signer,
                        name: ident,
                        ty: field.ty.clone(),
                    });
                    if !args_body.is_empty() {
                        args_body.parse::<Token![,]>()?;
                    }
                }
            }
            "script" => {
                script_expr = Some(body.parse()?);
                body.parse::<Token![;]>()?;
            }
            "next" => {
                let params;
                parenthesized!(params in body);
                let idents: syn::punctuated::Punctuated<Ident, Token![,]> =
                    params.parse_terminated(Ident::parse, Token![,])?;
                let mut it = idents.into_iter();
                let p = it
                    .next()
                    .ok_or_else(|| syn::Error::new(name_span, "next(p, a) needs a params ident"))?;
                let a = it
                    .next()
                    .ok_or_else(|| syn::Error::new(name_span, "next(p, a) needs an args ident"))?;
                let s = it.next();
                let block: Block = body.parse()?;
                next = Some(NextDef { p, a, s, body: block });
            }
            other => {
                return Err(syn::Error::new(
                    section.span(),
                    format!("unexpected clause section `{}`", other),
                ));
            }
        }
    }

    Ok(ClauseDef {
        name,
        fields,
        script_expr: script_expr
            .ok_or_else(|| syn::Error::new(name_span, "clause is missing `script <fn>;`"))?,
        next,
    })
}

fn closure_ident(c: &syn::ExprClosure) -> syn::Result<Ident> {
    if c.inputs.len() != 1 {
        return Err(syn::Error::new_spanned(
            c,
            "internal_key closure must take exactly one parameter",
        ));
    }
    match &c.inputs[0] {
        Pat::Ident(pi) => Ok(pi.ident.clone()),
        other => Err(syn::Error::new_spanned(other, "expected a simple identifier")),
    }
}

fn to_camel(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

pub fn expand(input: TokenStream) -> TokenStream {
    let def = syn::parse_macro_input!(input as ContractDef);
    codegen(def).into()
}

fn codegen(def: ContractDef) -> TokenStream2 {
    let name = &def.name;
    let params_ty = &def.params_ty;
    let handle_ident = format_ident!("{}Handle", name);

    let augmented = def.state_ty.is_some();
    let state_ty: Type = def
        .state_ty
        .clone()
        .unwrap_or_else(|| syn::parse_quote!(()));

    let contract_ty: TokenStream2 = if augmented {
        quote! { ::mattrs::contracts::StandardAugmentedP2TR<#params_ty, #state_ty> }
    } else {
        quote! { ::mattrs::contracts::StandardP2TR<#params_ty> }
    };

    let ikey_param = &def.ikey_param;
    let ikey_body = &def.ikey_body;
    let tree_tokens = &def.tree_tokens;

    let mut args_structs: Vec<TokenStream2> = Vec::new();
    let mut clause_locals: Vec<TokenStream2> = Vec::new();
    let mut methods: Vec<TokenStream2> = Vec::new();

    for clause in &def.clauses {
        let cname = &clause.name;
        let args_ident = format_ident!("{}{}Args", name, to_camel(&cname.to_string()));

        // --- The typed *Args struct (ClauseArgs is derived) ---
        let struct_fields = clause.fields.iter().map(|f| {
            let attrs = &f.attrs;
            let fname = &f.name;
            let fty = &f.ty;
            quote! { #(#attrs)* pub #fname: #fty }
        });
        args_structs.push(quote! {
            #[derive(::core::fmt::Debug, ::core::clone::Clone, ::mattrs_derive::ClauseArgs)]
            #[clause_args(params = #params_ty)]
            pub struct #args_ident {
                #(#struct_fields),*
            }
        });

        // --- The clause object, built inside `Name::new` ---
        let next_fn = match &clause.next {
            Some(nd) => {
                let p = &nd.p;
                let a = &nd.a;
                let s = nd.s.clone().unwrap_or_else(|| format_ident!("_state"));
                let block = &nd.body;
                // The body may evaluate to a Result of Vec<ClauseOutput>, a
                // CtvTemplate, or a NextOutputs; convert whatever it yields into
                // NextOutputs (all three implement Into<NextOutputs>).
                quote! {
                    ::core::option::Option::Some(::std::sync::Arc::new(
                        |#p: &#params_ty, #a: &#args_ident, #s: ::core::option::Option<&#state_ty>|
                        -> ::core::result::Result<
                            ::mattrs::contracts::NextOutputs,
                            ::mattrs::contracts::ClauseError,
                        > {
                            // Pin the error type so a bare `Ok(..)` body isn't
                            // ambiguous between the identity and WitnessError `From`s.
                            let __result: ::core::result::Result<
                                _,
                                ::mattrs::contracts::ClauseError,
                            > = #block;
                            let __next: ::mattrs::contracts::NextOutputs =
                                ::core::convert::Into::into(__result?);
                            ::core::result::Result::Ok(__next)
                        }
                    ))
                }
            }
            None => quote! { ::core::option::Option::None },
        };
        let script_expr = &clause.script_expr;
        clause_locals.push(quote! {
            let #cname: ::std::sync::Arc<dyn ::mattrs::contracts::ErasedClause> =
                ::std::sync::Arc::new(
                    ::mattrs::contracts::StandardClause::<#params_ty, #state_ty, #args_ident>::new(
                        ::core::stringify!(#cname).to_string(),
                        (#script_expr)(&params),
                        <#args_ident>::arg_specs_for_params(&params),
                        #next_fn,
                    ),
                );
        });

        // --- The per-clause method on the typed handle ---
        let method_params = clause.fields.iter().filter(|f| !f.is_signer).map(|f| {
            let fname = &f.name;
            let fty = &f.ty;
            quote! { #fname: #fty }
        });
        let ctor_args = clause.fields.iter().filter(|f| !f.is_signer).map(|f| {
            let fname = &f.name;
            quote! { #fname }
        });
        methods.push(quote! {
            pub fn #cname(&self, #(#method_params),*) -> ::mattrs::manager::SpendBuilder {
                let args = #args_ident::new(#(#ctor_args),*);
                self.0.spend_clause(
                    ::core::stringify!(#cname),
                    <#args_ident as ::mattrs::contracts::ClauseArgs>::encode_to_witness(&args),
                )
            }
        });
    }

    // `fund` differs: augmented contracts need an initial state.
    let fund_fn = if augmented {
        quote! {
            pub fn fund(
                manager: &mut ::mattrs::manager::ContractManager,
                amount: ::bitcoin::Amount,
                params: #params_ty,
                state: #state_ty,
            ) -> ::core::result::Result<#handle_ident, ::mattrs::manager::ManagerError> {
                let this = Self::new(params);
                let handle = manager.fund_instance(
                    this.as_erased(),
                    ::core::option::Option::Some(
                        ::std::boxed::Box::new(state)
                            as ::std::boxed::Box<dyn ::mattrs::contracts::ErasedState>,
                    ),
                    amount,
                )?;
                ::core::result::Result::Ok(#handle_ident(handle))
            }
        }
    } else {
        quote! {
            pub fn fund(
                manager: &mut ::mattrs::manager::ContractManager,
                amount: ::bitcoin::Amount,
                params: #params_ty,
            ) -> ::core::result::Result<#handle_ident, ::mattrs::manager::ManagerError> {
                let this = Self::new(params);
                let handle = manager.fund_instance(
                    this.as_erased(),
                    ::core::option::Option::None,
                    amount,
                )?;
                ::core::result::Result::Ok(#handle_ident(handle))
            }
        }
    };

    quote! {
        #(#args_structs)*

        /// Contract template (params + built taproot contract), generated by `contract!`.
        pub struct #name {
            pub params: #params_ty,
            pub contract: #contract_ty,
        }

        impl #name {
            /// Build the contract from its params.
            pub fn new(params: #params_ty) -> Self {
                let internal_key: ::bitcoin::XOnlyPublicKey = {
                    let #ikey_param = &params;
                    #ikey_body
                };
                #(#clause_locals)*
                let tree = ::mattrs::clause_tree![ #tree_tokens ];
                let contract = <#contract_ty>::new(internal_key, &params, tree);
                Self { params, contract }
            }

            /// The contract as a type-erased `ErasedContract`.
            pub fn as_erased(&self) -> ::std::sync::Arc<dyn ::mattrs::contracts::ErasedContract> {
                ::std::sync::Arc::new(self.contract.clone())
            }

            #fund_fn
        }

        /// Typed handle to a funded instance of this contract, with one spend method
        /// per clause. Generated by `contract!`.
        #[derive(::core::clone::Clone)]
        pub struct #handle_ident(pub ::mattrs::manager::InstanceHandle);

        impl #handle_ident {
            /// The underlying generic instance handle.
            pub fn handle(&self) -> &::mattrs::manager::InstanceHandle {
                &self.0
            }

            #(#methods)*
        }

        impl ::core::convert::TryFrom<::mattrs::manager::InstanceHandle> for #handle_ident {
            type Error = ::mattrs::manager::WrongContractType;

            fn try_from(
                handle: ::mattrs::manager::InstanceHandle,
            ) -> ::core::result::Result<Self, Self::Error> {
                if handle.contract_type_id() == ::core::any::TypeId::of::<#contract_ty>() {
                    ::core::result::Result::Ok(#handle_ident(handle))
                } else {
                    ::core::result::Result::Err(::mattrs::manager::WrongContractType {
                        expected: ::core::stringify!(#name),
                    })
                }
            }
        }
    }
}
