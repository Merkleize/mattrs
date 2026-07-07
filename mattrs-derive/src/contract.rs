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
    /// Outer attributes (doc comments, ...) before the `contract` keyword,
    /// forwarded onto the generated contract struct.
    attrs: Vec<Attribute>,
    name: Ident,
    params_ty: Type,
    /// The optional `ctx <Type>;` section: non-encodable construction context
    /// (script fragments, factories, timeouts...) passed to `new` alongside the
    /// params. Unlike params it never round-trips through `ParamEncodable`:
    /// scripts receive it as a second argument and `next` bodies capture a clone.
    ctx_ty: Option<Type>,
    state_ty: Option<Type>,
    /// The `internal_key |p| ..` closure; `None` defaults to the NUMS key.
    ikey: Option<(Ident, Expr)>,
    clauses: Vec<ClauseDef>,
    tree: TreeDef,
}

/// The `tree ..;` section: either a static nested-bracket list, or a closure
/// computing the [`ClauseTree`](mattrs::contracts::ClauseTree) from the params
/// (for contracts whose clause set / taptree shape depends on runtime params).
enum TreeDef {
    /// `tree [ a, [b, c] ];` — the token tree fed to `clause_tree!`.
    Static(TokenStream2),
    /// `tree |p| { .. };` — `p` is bound to `&params`; the body evaluates to a
    /// `ClauseTree`, with every clause in scope as a local.
    Dynamic { p: Ident, body: Expr },
}

struct ClauseDef {
    name: Ident,
    args: ClauseArgsDef,
    script_expr: Expr,
    next: Option<NextDef>,
}

/// A clause's `args` section.
enum ClauseArgsDef {
    /// `args { name: Ty, .. }` — a typed `*Args` struct is generated, plus a
    /// handle method taking the non-signer (and non-`#[from_state]`) fields.
    Typed(Vec<ClauseField>),
    /// `args raw <expr>;` — for witness layouts only known at runtime. `<expr>`
    /// is called with `&params` (and `&ctx`, when the contract has one) and
    /// evaluates to the clause's `Vec<ArgSpec>`. The clause uses `RawArgs` and
    /// no handle method is generated; the module owner adds ergonomic spend
    /// methods in a plain `impl NameHandle` block.
    Raw(Expr),
}

struct ClauseField {
    attrs: Vec<Attribute>,
    is_signer: bool,
    /// `#[from_state]`: the generated handle method omits this argument and
    /// fills it from the instance's typed state (same-named state field).
    is_from_state: bool,
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
        let attrs = input.call(Attribute::parse_outer)?;
        let kw: Ident = input.parse()?;
        if kw != "contract" {
            return Err(syn::Error::new(kw.span(), "expected `contract`"));
        }
        let name: Ident = input.parse()?;
        let name_span = name.span();

        let body;
        braced!(body in input);

        let mut params_ty: Option<Type> = None;
        let mut ctx_ty: Option<Type> = None;
        let mut state_ty: Option<Type> = None;
        let mut ikey: Option<(Ident, Expr)> = None;
        let mut clauses: Vec<ClauseDef> = Vec::new();
        let mut tree: Option<TreeDef> = None;

        while !body.is_empty() {
            let section: Ident = body.parse()?;
            match section.to_string().as_str() {
                "params" => {
                    params_ty = Some(body.parse()?);
                    body.parse::<Token![;]>()?;
                }
                "ctx" => {
                    ctx_ty = Some(body.parse()?);
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
                    if body.peek(Token![|]) || body.peek(Token![move]) {
                        // Dynamic form: `tree |p| <expr>;`.
                        let closure: syn::ExprClosure = body.parse()?;
                        let p = closure_ident(&closure)?;
                        tree = Some(TreeDef::Dynamic {
                            p,
                            body: *closure.body,
                        });
                    } else {
                        // Static form: `tree [ .. ];`.
                        let content;
                        bracketed!(content in body);
                        tree = Some(TreeDef::Static(content.parse()?));
                    }
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

        let tree =
            tree.ok_or_else(|| syn::Error::new(name_span, "missing `tree [ .. ];`"))?;
        // The static form's clause references are resolved at macro-expansion
        // time, so validate them here for a spanned error. The dynamic form's
        // references are ordinary locals, checked by the compiler.
        if let TreeDef::Static(tree_tokens) = &tree {
            validate_tree_names(tree_tokens, &clauses)?;
        }

        // `#[from_state]` fills args from the instance's typed state, so it needs
        // a `state` section to read from.
        if state_ty.is_none() {
            for clause in &clauses {
                if let ClauseArgsDef::Typed(fields) = &clause.args {
                    if let Some(f) = fields.iter().find(|f| f.is_from_state) {
                        return Err(syn::Error::new(
                            f.name.span(),
                            "#[from_state] requires a `state <Type>;` section",
                        ));
                    }
                }
            }
        }

        Ok(ContractDef {
            attrs,
            name,
            params_ty: params_ty
                .ok_or_else(|| syn::Error::new(name_span, "missing `params <Type>;`"))?,
            ctx_ty,
            state_ty,
            ikey,
            clauses,
            tree,
        })
    }
}

/// Check that every name in `tree [ .. ]` is a declared clause, with a spanned
/// error on the offending identifier (instead of a "cannot find value" error
/// deep inside the generated code).
fn validate_tree_names(tree_tokens: &TokenStream2, clauses: &[ClauseDef]) -> syn::Result<()> {
    use syn::parse::Parser;

    let names: std::collections::HashSet<String> =
        clauses.iter().map(|c| c.name.to_string()).collect();

    fn check_level(
        input: ParseStream,
        names: &std::collections::HashSet<String>,
    ) -> syn::Result<()> {
        while !input.is_empty() {
            if input.peek(syn::token::Bracket) {
                let inner;
                bracketed!(inner in input);
                check_level(&inner, names)?;
            } else {
                let ident: Ident = input.parse()?;
                if !names.contains(&ident.to_string()) {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown clause `{}` in `tree [..]`", ident),
                    ));
                }
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(())
    }

    let parser = |input: ParseStream| check_level(input, &names);
    parser.parse2(tree_tokens.clone())
}

/// Rewrite the `#[signer(p.field)]` shorthand into the full closure form
/// `#[signer(|p| p.field.serialize())]` (the params binding is taken from the
/// user's own expression). Closures and other expressions pass through untouched.
fn expand_signer_shorthand(attr: &Attribute) -> syn::Result<Attribute> {
    if !attr.path().is_ident("signer") {
        return Ok(attr.clone());
    }
    let expr: Expr = attr.parse_args()?;
    if let Expr::Field(field_access) = &expr {
        if let Expr::Path(base) = &*field_access.base {
            if let Some(param) = base.path.get_ident() {
                let rewritten: Expr = syn::parse_quote!(|#param| #expr.serialize());
                let mut attr = attr.clone();
                attr.meta = syn::parse_quote!(signer(#rewritten));
                return Ok(attr);
            }
        }
    }
    Ok(attr.clone())
}

fn parse_clause(input: ParseStream) -> syn::Result<ClauseDef> {
    let name: Ident = input.parse()?;
    let name_span = name.span();
    let body;
    braced!(body in input);

    let mut args: Option<ClauseArgsDef> = None;
    let mut script_expr: Option<Expr> = None;
    let mut next: Option<NextDef> = None;

    while !body.is_empty() {
        let section: Ident = body.parse()?;
        match section.to_string().as_str() {
            "args" if body.peek(syn::token::Brace) => {
                let args_body;
                braced!(args_body in body);
                let mut fields: Vec<ClauseField> = Vec::new();
                while !args_body.is_empty() {
                    let field = args_body.call(Field::parse_named)?;
                    let is_signer = field.attrs.iter().any(|a| a.path().is_ident("signer"));
                    let is_from_state =
                        field.attrs.iter().any(|a| a.path().is_ident("from_state"));
                    if is_signer && is_from_state {
                        return Err(syn::Error::new_spanned(
                            &field,
                            "#[signer(..)] and #[from_state] cannot both be applied to one \
                             field (signatures are already filled at spend time)",
                        ));
                    }
                    let ident = field
                        .ident
                        .clone()
                        .ok_or_else(|| syn::Error::new_spanned(&field, "clause args need names"))?;
                    // `#[from_state]` only drives handle-method codegen; strip it so
                    // the emitted struct (and the ClauseArgs derive) never sees it.
                    let attrs = field
                        .attrs
                        .iter()
                        .filter(|a| !a.path().is_ident("from_state"))
                        .map(expand_signer_shorthand)
                        .collect::<syn::Result<Vec<_>>>()?;
                    fields.push(ClauseField {
                        attrs,
                        is_signer,
                        is_from_state,
                        name: ident,
                        ty: field.ty.clone(),
                    });
                    if !args_body.is_empty() {
                        args_body.parse::<Token![,]>()?;
                    }
                }
                args = Some(ClauseArgsDef::Typed(fields));
            }
            "args" => {
                // Raw form: `args raw <expr>;`.
                let kw: Ident = body.parse()?;
                if kw != "raw" {
                    return Err(syn::Error::new(
                        kw.span(),
                        "expected `args { .. }` or `args raw <specs-expr>;`",
                    ));
                }
                args = Some(ClauseArgsDef::Raw(body.parse()?));
                body.parse::<Token![;]>()?;
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
        args: args.unwrap_or(ClauseArgsDef::Typed(Vec::new())),
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

/// The `Option<NextOutputsFn>` tokens for one clause: `None` for terminal
/// clauses, otherwise the typed closure wrapping the user's `next` body. With a
/// `ctx` section the closure is `move` and captures a clone of the ctx, rebound
/// as `ctx` inside the body.
fn next_fn_tokens(
    clause: &ClauseDef,
    params_ty: &Type,
    state_ty: &Type,
    ctx_ty: Option<&Type>,
    args_ty: &TokenStream2,
) -> TokenStream2 {
    let Some(nd) = &clause.next else {
        return quote! { ::core::option::Option::None };
    };
    let p = &nd.p;
    let a = &nd.a;
    let s = nd.s.clone().unwrap_or_else(|| format_ident!("_state"));
    let block = &nd.body;
    // The body may evaluate to a Result of Vec<ClauseOutput>, a CtvTemplate, or
    // a NextOutputs; convert whatever it yields into NextOutputs (all three
    // implement Into<NextOutputs>). The error type is pinned so a bare `Ok(..)`
    // body isn't ambiguous between the identity and WitnessError `From`s.
    let body = quote! {
        let __result: ::core::result::Result<
            _,
            ::mattrs::contracts::ClauseError,
        > = #block;
        let __next: ::mattrs::contracts::NextOutputs =
            ::core::convert::Into::into(__result?);
        ::core::result::Result::Ok(__next)
    };
    let ret = quote! {
        ::core::result::Result<
            ::mattrs::contracts::NextOutputs,
            ::mattrs::contracts::ClauseError,
        >
    };
    match ctx_ty {
        Some(ctx_ty) => quote! {
            ::core::option::Option::Some({
                let __ctx = ctx.clone();
                ::std::sync::Arc::new(
                    move |#p: &#params_ty, #a: &#args_ty, #s: ::core::option::Option<&#state_ty>|
                    -> #ret {
                        #[allow(unused_variables)]
                        let ctx: &#ctx_ty = &__ctx;
                        #body
                    }
                )
            })
        },
        None => quote! {
            ::core::option::Option::Some(::std::sync::Arc::new(
                |#p: &#params_ty, #a: &#args_ty, #s: ::core::option::Option<&#state_ty>|
                -> #ret {
                    #body
                }
            ))
        },
    }
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

    // The taproot internal key: the user's closure, or the NUMS key by default.
    let ikey_init: TokenStream2 = match &def.ikey {
        Some((param, body)) => quote! {
            let internal_key: ::bitcoin::XOnlyPublicKey = {
                let #param = &params;
                #body
            };
        },
        None => quote! {
            let internal_key: ::bitcoin::XOnlyPublicKey = ::mattrs::nums_key();
        },
    };
    // The taptree: either the static nested-bracket list handed to `clause_tree!`,
    // or a params-derived closure body evaluating to a `ClauseTree`. Both run after
    // the clause locals are emitted, so either can reference clauses by name.
    let tree_init: TokenStream2 = match &def.tree {
        TreeDef::Static(tree_tokens) => quote! {
            let tree = ::mattrs::clause_tree![ #tree_tokens ];
        },
        TreeDef::Dynamic { p, body } => quote! {
            let tree: ::mattrs::contracts::ClauseTree = {
                let #p = &params;
                #body
            };
        },
    };

    // The optional construction context: an extra `new` argument whose value is
    // handed to the script/spec builder exprs and captured (cloned) by `next`
    // closures; unlike params it never round-trips through `ParamEncodable`.
    let ctx_ty = def.ctx_ty.as_ref();
    // Invoke a script (or raw-args spec) builder expr inside `new`. The `&dyn Fn`
    // coercion pins the expected type, so closure exprs infer their parameter
    // types (a bare `(#expr)(&params, ..)` call would not).
    let call_builder = |expr: &Expr, ret: TokenStream2| -> TokenStream2 {
        match ctx_ty {
            Some(c) => quote! {{
                let __f: &dyn ::core::ops::Fn(&#params_ty, &#c) -> #ret = &(#expr);
                __f(&params, &ctx)
            }},
            None => quote! {{
                let __f: &dyn ::core::ops::Fn(&#params_ty) -> #ret = &(#expr);
                __f(&params)
            }},
        }
    };

    let mut args_structs: Vec<TokenStream2> = Vec::new();
    let mut clause_locals: Vec<TokenStream2> = Vec::new();
    let mut methods: Vec<TokenStream2> = Vec::new();

    for clause in &def.clauses {
        let cname = &clause.name;
        let script_expr = &clause.script_expr;

        let fields = match &clause.args {
            // A raw-args clause: runtime witness layout via `RawArgs`, no *Args
            // struct and no handle method (the module owner writes ergonomic
            // spend methods on the generated handle instead).
            ClauseArgsDef::Raw(specs_expr) => {
                let raw_ty = quote! { ::mattrs::contracts::RawArgs };
                let next_fn = next_fn_tokens(clause, params_ty, &state_ty, ctx_ty, &raw_ty);
                let script_call = call_builder(script_expr, quote! { ::bitcoin::ScriptBuf });
                let specs_call = call_builder(
                    specs_expr,
                    quote! { ::std::vec::Vec<::mattrs::contracts::ArgSpec> },
                );
                clause_locals.push(quote! {
                    let #cname: ::std::sync::Arc<dyn ::mattrs::contracts::ErasedClause> =
                        ::std::sync::Arc::new(
                            ::mattrs::contracts::StandardClause::<
                                #params_ty,
                                #state_ty,
                                ::mattrs::contracts::RawArgs,
                            >::new(
                                ::core::stringify!(#cname).to_string(),
                                #script_call,
                                #specs_call,
                                #next_fn,
                            ),
                        );
                });
                continue;
            }
            ClauseArgsDef::Typed(fields) => fields,
        };

        let args_ident = format_ident!("{}{}Args", name, to_camel(&cname.to_string()));

        // --- The typed *Args struct (ClauseArgs is derived) ---
        let struct_fields = fields.iter().map(|f| {
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
        let args_ty = quote! { #args_ident };
        let next_fn = next_fn_tokens(clause, params_ty, &state_ty, ctx_ty, &args_ty);
        let script_call = call_builder(script_expr, quote! { ::bitcoin::ScriptBuf });
        clause_locals.push(quote! {
            let #cname: ::std::sync::Arc<dyn ::mattrs::contracts::ErasedClause> =
                ::std::sync::Arc::new(
                    ::mattrs::contracts::StandardClause::<#params_ty, #state_ty, #args_ident>::new(
                        ::core::stringify!(#cname).to_string(),
                        #script_call,
                        <#args_ident>::arg_specs_for_params(&params),
                        #next_fn,
                    ),
                );
        });

        // --- The per-clause method on the typed handle ---
        // Signer args are filled by the manager at spend time and `#[from_state]`
        // args from the instance's typed state; the method takes the rest.
        let method_params = fields
            .iter()
            .filter(|f| !f.is_signer && !f.is_from_state)
            .map(|f| {
                let fname = &f.name;
                let fty = &f.ty;
                quote! { #fname: #fty }
            });
        // `Args::new` takes the non-signer fields, in declaration order.
        let ctor_args = fields.iter().filter(|f| !f.is_signer).map(|f| {
            let fname = &f.name;
            if f.is_from_state {
                quote! { __state.#fname }
            } else {
                quote! { #fname }
            }
        });
        if fields.iter().any(|f| f.is_from_state) {
            methods.push(quote! {
                // A clause can have many arguments; the generated method mirrors them.
                #[allow(clippy::too_many_arguments)]
                pub fn #cname(
                    &self,
                    #(#method_params),*
                ) -> ::core::result::Result<
                    ::mattrs::manager::SpendBuilder,
                    ::mattrs::manager::MissingStateError,
                > {
                    let __state = self.state().ok_or(::mattrs::manager::MissingStateError {
                        contract: ::core::stringify!(#name),
                    })?;
                    let args = #args_ident::new(#(#ctor_args),*);
                    ::core::result::Result::Ok(self.0.spend_clause(
                        ::core::stringify!(#cname),
                        <#args_ident as ::mattrs::contracts::ClauseArgs>::encode_to_witness(&args),
                    ))
                }
            });
        } else {
            methods.push(quote! {
                // A clause can have many arguments; the generated method mirrors them.
                #[allow(clippy::too_many_arguments)]
                pub fn #cname(&self, #(#method_params),*) -> ::mattrs::manager::SpendBuilder {
                    let args = #args_ident::new(#(#ctor_args),*);
                    self.0.spend_clause(
                        ::core::stringify!(#cname),
                        <#args_ident as ::mattrs::contracts::ClauseArgs>::encode_to_witness(&args),
                    )
                }
            });
        }
    }

    // `fund` and `address` differ: augmented contracts need the state.
    let fund_fn = if augmented {
        quote! {
            /// Fund a new on-chain instance of this contract carrying `state`,
            /// returning its typed handle.
            pub fn fund(
                &self,
                manager: &mut ::mattrs::manager::ContractManager,
                amount: ::bitcoin::Amount,
                state: #state_ty,
            ) -> ::core::result::Result<#handle_ident, ::mattrs::manager::ManagerError> {
                let handle = manager.fund_instance(
                    self.as_erased(),
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
            /// Fund a new on-chain instance of this contract, returning its
            /// typed handle.
            pub fn fund(
                &self,
                manager: &mut ::mattrs::manager::ContractManager,
                amount: ::bitcoin::Amount,
            ) -> ::core::result::Result<#handle_ident, ::mattrs::manager::ManagerError> {
                let handle = manager.fund_instance(
                    self.as_erased(),
                    ::core::option::Option::None,
                    amount,
                )?;
                ::core::result::Result::Ok(#handle_ident(handle))
            }
        }
    };

    // Augmented handles know their state type; expose it without a turbofish.
    let state_fn = if augmented {
        quote! {
            /// This instance's typed state, if available.
            pub fn state(&self) -> ::core::option::Option<#state_ty> {
                self.0.state::<#state_ty>()
            }
        }
    } else {
        quote! {}
    };

    let address_fn = if augmented {
        quote! {
            /// The contract's address for the given state commitment.
            pub fn address(
                &self,
                state: &#state_ty,
                network: ::bitcoin::Network,
            ) -> ::core::result::Result<::bitcoin::Address, ::mattrs::contracts::ContractError> {
                let script_pubkey = self.contract.script_pubkey(state)?;
                ::core::result::Result::Ok(
                    ::bitcoin::Address::from_script(&script_pubkey, network.params())
                        .expect("a taproot script is always addressable"),
                )
            }
        }
    } else {
        quote! {
            /// The contract's address.
            pub fn address(&self, network: ::bitcoin::Network) -> ::bitcoin::Address {
                ::bitcoin::Address::from_script(&self.contract.script_pubkey(), network.params())
                    .expect("a taproot script is always addressable")
            }
        }
    };

    // The ctx-dependent pieces of the contract struct and its `new`.
    let (ctx_struct_field, ctx_new_param, ctx_self_field) = match ctx_ty {
        Some(c) => (
            quote! { pub ctx: #c, },
            quote! { , ctx: #c },
            quote! { ctx, },
        ),
        None => (quote! {}, quote! {}, quote! {}),
    };

    let attrs = &def.attrs;

    quote! {
        #(#args_structs)*

        #(#attrs)*
        /// Contract template (params + built taproot contract), generated by `contract!`.
        pub struct #name {
            pub params: #params_ty,
            #ctx_struct_field
            pub contract: #contract_ty,
        }

        impl #name {
            /// Build the contract from its params (and, if the contract declares
            /// one, its construction context).
            pub fn new(params: #params_ty #ctx_new_param) -> Self {
                #ikey_init
                #(#clause_locals)*
                #tree_init
                let contract = <#contract_ty>::new(
                    ::core::stringify!(#name),
                    internal_key,
                    &params,
                    tree,
                );
                Self { params, #ctx_self_field contract }
            }

            /// The contract as a type-erased `ErasedContract`.
            pub fn as_erased(&self) -> ::std::sync::Arc<dyn ::mattrs::contracts::ErasedContract> {
                ::std::sync::Arc::new(self.contract.clone())
            }

            /// The merkle root of the contract's script taptree (e.g. to commit
            /// this contract as a `CHECKCONTRACTVERIFY` output of another).
            pub fn taptree_root(&self) -> [u8; 32] {
                self.contract.taptree().root_hash()
            }

            #address_fn

            #fund_fn
        }

        /// Typed handle to a funded instance of this contract, with one spend method
        /// per clause. Generated by `contract!`. Obtained from the contract's
        /// `fund` method, or by checked conversion (`try_into`) from an untyped
        /// `InstanceHandle`.
        #[derive(::core::clone::Clone)]
        pub struct #handle_ident(::mattrs::manager::InstanceHandle);

        impl #handle_ident {
            /// The underlying generic instance handle.
            pub fn handle(&self) -> &::mattrs::manager::InstanceHandle {
                &self.0
            }

            /// The instance's decoded contract parameters (contracts are
            /// self-describing).
            pub fn params(
                &self,
            ) -> ::core::result::Result<#params_ty, ::mattrs::contracts::WitnessError> {
                <#params_ty as ::mattrs::contracts::ContractParams>::decode(
                    &self.0.params_bytes(),
                )
            }

            #state_fn

            #(#methods)*
        }

        impl ::core::convert::TryFrom<::mattrs::manager::InstanceHandle> for #handle_ident {
            type Error = ::mattrs::manager::WrongContractType;

            fn try_from(
                handle: ::mattrs::manager::InstanceHandle,
            ) -> ::core::result::Result<Self, Self::Error> {
                // The name breaks ties between contracts erasing to the same
                // `StandardP2TR`/`StandardAugmentedP2TR` instantiation.
                if handle.contract_type_id() == ::core::any::TypeId::of::<#contract_ty>()
                    && handle.contract_name() == ::core::stringify!(#name)
                {
                    ::core::result::Result::Ok(#handle_ident(handle))
                } else {
                    ::core::result::Result::Err(::mattrs::manager::WrongContractType {
                        expected: ::core::stringify!(#name),
                    })
                }
            }
        }

        impl ::mattrs::protocol::TypedContract for #name {
            type Handle = #handle_ident;
            const NAME: &'static str = ::core::stringify!(#name);

            fn kind_id() -> ::core::any::TypeId {
                ::core::any::TypeId::of::<#contract_ty>()
            }
        }
    }
}
