use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derive macro for ClauseArgs trait.
/// Automatically implements encoding/decoding to witness stack.
#[proc_macro_derive(ClauseArgs)]
pub fn derive_clause_args(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

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
            let #field_name = *#field_name;
            offset += consumed;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);

    // Use fully qualified paths that work both from within crate and outside
    let expanded = quote! {
        impl WitnessEncodable for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                let mut stack = Vec::new();
                #(#encode_fields)*
                stack
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Box<Self>, usize), Box<dyn std::error::Error>> {
                let mut offset = 0;
                #(#decode_fields)*
                Ok((Box::new(Self {
                    #(#field_names),*
                }), offset))
            }
        }

        impl ClauseArgs for #name {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                <Self as WitnessEncodable>::encode_to_witness(self)
            }
        }
    };

    TokenStream::from(expanded)
}
