use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

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
            offset += consumed;
        }
    });

    let field_names = fields.iter().map(|f| &f.ident);

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
    };

    TokenStream::from(expanded)
}

/// Derive macro for ContractParams trait.
/// Automatically implements encoding/decoding for contract parameters.
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

    let encode_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            result.extend(self.#field_name.encode_to_witness().into_iter().flatten());
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

        impl ContractParams for #name {
            fn encode(&self) -> Vec<u8> {
                self.encode_to_witness().into_iter().flatten().collect()
            }

            fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
                // Convert bytes to witness format (single element)
                let witness = vec![bytes.to_vec()];
                let (params, _) = Self::decode_from_witness(&witness)?;
                Ok(params)
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
            result.extend(self.#field_name.encode_to_witness().into_iter().flatten());
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
