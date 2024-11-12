use bitcoin::{blockdata::opcodes::Opcode, opcodes, opcodes::all::OP_RESERVED};
use proc_macro2::{
    Delimiter, Span, TokenStream,
    TokenTree::{self, *},
};
use quote::quote;
use std::iter::Peekable;
use std::str::FromStr;

#[derive(Debug)]
pub enum Syntax {
    Opcode(Opcode),
    Escape(TokenStream),
    Bytes(Vec<u8>),
    Int(i64),
}

trait MyFromStr {
    fn from_str(s: &str) -> Result<Self, ()>
    where
        Self: Sized;
}

impl MyFromStr for Opcode {
    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "OP_0" => Ok(opcodes::OP_0),
            "OP_TRUE" | "TRUE" => Ok(opcodes::OP_TRUE),
            "OP_FALSE" | "FALSE" => Ok(opcodes::OP_FALSE),
            "OP_NOP2" | "NOP2" => Ok(opcodes::OP_NOP2),
            "OP_NOP3" | "NOP3" => Ok(opcodes::OP_NOP3),
            "OP_1" => Ok(opcodes::all::OP_PUSHNUM_1),
            "OP_2" => Ok(opcodes::all::OP_PUSHNUM_2),
            "OP_3" => Ok(opcodes::all::OP_PUSHNUM_3),
            "OP_4" => Ok(opcodes::all::OP_PUSHNUM_4),
            "OP_5" => Ok(opcodes::all::OP_PUSHNUM_5),
            "OP_6" => Ok(opcodes::all::OP_PUSHNUM_6),
            "OP_7" => Ok(opcodes::all::OP_PUSHNUM_7),
            "OP_8" => Ok(opcodes::all::OP_PUSHNUM_8),
            "OP_9" => Ok(opcodes::all::OP_PUSHNUM_9),
            "OP_10" => Ok(opcodes::all::OP_PUSHNUM_10),
            "OP_11" => Ok(opcodes::all::OP_PUSHNUM_11),
            "OP_12" => Ok(opcodes::all::OP_PUSHNUM_12),
            "OP_13" => Ok(opcodes::all::OP_PUSHNUM_13),
            "OP_14" => Ok(opcodes::all::OP_PUSHNUM_14),
            "OP_15" => Ok(opcodes::all::OP_PUSHNUM_15),
            "OP_16" => Ok(opcodes::all::OP_PUSHNUM_16),
            "OP_NOP" => Ok(opcodes::all::OP_NOP),
            "OP_IF" => Ok(opcodes::all::OP_IF),
            "OP_NOTIF" => Ok(opcodes::all::OP_NOTIF),
            "OP_ELSE" => Ok(opcodes::all::OP_ELSE),
            "OP_ENDIF" => Ok(opcodes::all::OP_ENDIF),
            "OP_VERIFY" => Ok(opcodes::all::OP_VERIFY),
            "OP_RETURN" => Ok(opcodes::all::OP_RETURN),
            "OP_TOALTSTACK" => Ok(opcodes::all::OP_TOALTSTACK),
            "OP_FROMALTSTACK" => Ok(opcodes::all::OP_FROMALTSTACK),
            "OP_2DROP" => Ok(opcodes::all::OP_2DROP),
            "OP_2DUP" => Ok(opcodes::all::OP_2DUP),
            "OP_3DUP" => Ok(opcodes::all::OP_3DUP),
            "OP_2OVER" => Ok(opcodes::all::OP_2OVER),
            "OP_2ROT" => Ok(opcodes::all::OP_2ROT),
            "OP_2SWAP" => Ok(opcodes::all::OP_2SWAP),
            "OP_IFDUP" => Ok(opcodes::all::OP_IFDUP),
            "OP_DEPTH" => Ok(opcodes::all::OP_DEPTH),
            "OP_DROP" => Ok(opcodes::all::OP_DROP),
            "OP_DUP" => Ok(opcodes::all::OP_DUP),
            "OP_NIP" => Ok(opcodes::all::OP_NIP),
            "OP_OVER" => Ok(opcodes::all::OP_OVER),
            "OP_PICK" => Ok(opcodes::all::OP_PICK),
            "OP_ROLL" => Ok(opcodes::all::OP_ROLL),
            "OP_ROT" => Ok(opcodes::all::OP_ROT),
            "OP_SWAP" => Ok(opcodes::all::OP_SWAP),
            "OP_TUCK" => Ok(opcodes::all::OP_TUCK),
            "OP_CAT" => Ok(opcodes::all::OP_CAT),
            "OP_SIZE" => Ok(opcodes::all::OP_SIZE),
            "OP_EQUAL" => Ok(opcodes::all::OP_EQUAL),
            "OP_EQUALVERIFY" => Ok(opcodes::all::OP_EQUALVERIFY),
            "OP_1ADD" => Ok(opcodes::all::OP_1ADD),
            "OP_1SUB" => Ok(opcodes::all::OP_1SUB),
            "OP_NEGATE" => Ok(opcodes::all::OP_NEGATE),
            "OP_ABS" => Ok(opcodes::all::OP_ABS),
            "OP_NOT" => Ok(opcodes::all::OP_NOT),
            "OP_0NOTEQUAL" => Ok(opcodes::all::OP_0NOTEQUAL),
            "OP_ADD" => Ok(opcodes::all::OP_ADD),
            "OP_SUB" => Ok(opcodes::all::OP_SUB),
            "OP_BOOLAND" => Ok(opcodes::all::OP_BOOLAND),
            "OP_BOOLOR" => Ok(opcodes::all::OP_BOOLOR),
            "OP_NUMEQUAL" => Ok(opcodes::all::OP_NUMEQUAL),
            "OP_NUMEQUALVERIFY" => Ok(opcodes::all::OP_NUMEQUALVERIFY),
            "OP_NUMNOTEQUAL" => Ok(opcodes::all::OP_NUMNOTEQUAL),
            "OP_LESSTHAN" => Ok(opcodes::all::OP_LESSTHAN),
            "OP_GREATERTHAN" => Ok(opcodes::all::OP_GREATERTHAN),
            "OP_LESSTHANOREQUAL" => Ok(opcodes::all::OP_LESSTHANOREQUAL),
            "OP_GREATERTHANOREQUAL" => Ok(opcodes::all::OP_GREATERTHANOREQUAL),
            "OP_MIN" => Ok(opcodes::all::OP_MIN),
            "OP_MAX" => Ok(opcodes::all::OP_MAX),
            "OP_WITHIN" => Ok(opcodes::all::OP_WITHIN),
            "OP_RIPEMD160" => Ok(opcodes::all::OP_RIPEMD160),
            "OP_SHA1" => Ok(opcodes::all::OP_SHA1),
            "OP_SHA256" => Ok(opcodes::all::OP_SHA256),
            "OP_HASH160" => Ok(opcodes::all::OP_HASH160),
            "OP_HASH256" => Ok(opcodes::all::OP_HASH256),
            "OP_CODESEPARATOR" => Ok(opcodes::all::OP_CODESEPARATOR),
            "OP_CHECKSIG" => Ok(opcodes::all::OP_CHECKSIG),
            "OP_CHECKSIGVERIFY" => Ok(opcodes::all::OP_CHECKSIGVERIFY),
            "OP_CHECKMULTISIG" => Ok(opcodes::all::OP_CHECKMULTISIG),
            "OP_CHECKMULTISIGVERIFY" => Ok(opcodes::all::OP_CHECKMULTISIGVERIFY),
            "OP_CLTV" => Ok(opcodes::all::OP_CLTV),
            "OP_CSV" => Ok(opcodes::all::OP_CSV),
            _ => Err(()),
        }
    }
}

macro_rules! emit_error {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::emit_error!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);

        #[allow(unreachable_code)]
        {
            panic!();
        }
    }}
}

macro_rules! abort {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::abort!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);
    }}
}

pub fn parse(tokens: TokenStream) -> Vec<(Syntax, Span)> {
    let mut tokens = tokens.into_iter().peekable();
    let mut syntax = Vec::with_capacity(2048);

    while let Some(token) = tokens.next() {
        let token_str = token.to_string();
        syntax.push(match (&token, token_str.as_ref()) {
            // Wrap for loops such that they return a Vec<ScriptBuf>
            (Ident(_), ident_str) if ident_str == "for" => parse_for_loop(token, &mut tokens),
            // Wrap if-else statements such that they return a Vec<ScriptBuf>
            (Ident(_), ident_str) if ident_str == "if" => parse_if(token, &mut tokens),
            // Replace DEBUG with OP_RESERVED
            (Ident(_), ident_str) if ident_str == "DEBUG" => {
                (Syntax::Opcode(OP_RESERVED), token.span())
            }

            // identifier, look up opcode
            (Ident(_), _) => {
                match Opcode::from_str(&token_str) {
                    Ok(opcode) => (Syntax::Opcode(opcode), token.span()),
                    // Not a native Bitcoin opcode
                    // Allow functions without arguments to be identified by just their name
                    _ => {
                        let span = token.span();
                        let mut pseudo_stream = TokenStream::from(token);
                        pseudo_stream.extend(TokenStream::from_str("()"));
                        (Syntax::Escape(pseudo_stream), span)
                    }
                }
            }

            (Group(inner), _) => {
                let escape = TokenStream::from(inner.stream().clone());
                (Syntax::Escape(escape), token.span())
            }

            // '<', start of escape (parse until first '>')
            (Punct(_), "<") => parse_escape(token, &mut tokens),

            // '~' start of escape (parse until the next '~') ignores '<' and '>'
            (Punct(_), "~") => parse_escape_extra(token, &mut tokens),

            // literal, push data (int or bytes)
            (Literal(_), _) => parse_data(token),

            // negative sign, parse negative int
            (Punct(_), "-") => parse_negative_int(token, &mut tokens),

            // anything else is invalid
            _ => abort!(token.span(), "unexpected token"),
        });
    }
    syntax
}

fn parse_if<T>(token: TokenTree, tokens: &mut Peekable<T>) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    // Use a Vec here to get rid of warnings when the variable is overwritten
    let mut escape = quote! {
        let mut script_var = Vec::with_capacity(256);
    };
    escape.extend(std::iter::once(token.clone()));

    while let Some(if_token) = tokens.next() {
        match if_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        script_var.extend_from_slice(script! {
                            #inner_block
                        }.as_bytes());
                    }
                });

                match tokens.peek() {
                    Some(else_token) if else_token.to_string().as_str() == "else" => continue,
                    _ => break,
                }
            }
            _ => {
                escape.extend(std::iter::once(if_token));
                continue;
            }
        };
    }
    escape = quote! {
        {
            #escape;
            bitcoin::script::ScriptBuf::from(script_var)
        }
    }
    .into();
    (Syntax::Escape(escape), token.span())
}

fn parse_for_loop<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = quote! {
        let mut script_var = vec![];
    };
    escape.extend(std::iter::once(token.clone()));

    while let Some(for_token) = tokens.next() {
        match for_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        let next_script = script !{
                            #inner_block
                        };
                        script_var.extend_from_slice(next_script.as_bytes());
                    }
                    bitcoin::script::ScriptBuf::from(script_var)
                });
                break;
            }
            _ => {
                escape.extend(std::iter::once(for_token));
                continue;
            }
        };
    }

    (Syntax::Escape(quote! { { #escape } }.into()), token.span())
}

fn parse_escape<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), ">") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_escape_extra<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), "~") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_data(token: TokenTree) -> (Syntax, Span) {
    if token.to_string().starts_with("0x") {
        if token
            .to_string()
            .strip_prefix("0x")
            .unwrap_or_else(|| unreachable!())
            .trim_start_matches('0')
            .len()
            <= 8
        {
            parse_hex_int(token)
        } else {
            parse_bytes(token)
        }
    } else {
        parse_int(token, false)
    }
}

fn parse_bytes(token: TokenTree) -> (Syntax, Span) {
    let hex_bytes = &token.to_string()[2..];
    let bytes = hex::decode(hex_bytes).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex literal ({})", err);
    });
    (Syntax::Bytes(bytes), token.span())
}

fn parse_hex_int(token: TokenTree) -> (Syntax, Span) {
    let token_str = &token.to_string()[2..];
    let n: u32 = u32::from_str_radix(token_str, 16).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex string ({})", err);
    });
    (Syntax::Int(n as i64), token.span())
}

fn parse_int(token: TokenTree, negative: bool) -> (Syntax, Span) {
    let token_str = token.to_string();
    let n: i64 = token_str.parse().unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid number literal ({})", err);
    });
    let n = if negative { n * -1 } else { n };
    (Syntax::Int(n), token.span())
}

fn parse_negative_int<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let fail = || {
        #[allow(unused_variables)]
        let span = token.span();
        emit_error!(
            span,
            "expected negative sign to be followed by number literal"
        );
    };

    let maybe_token = tokens.next();

    if let Some(token) = maybe_token {
        if let Literal(_) = token {
            parse_int(token, true)
        } else {
            fail()
        }
    } else {
        fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::opcodes::all as opcodes;
    use quote::quote;

    #[test]
    fn parse_empty() {
        assert!(parse(quote!()).is_empty());
    }

    #[test]
    #[should_panic(expected = "unexpected token")]
    fn parse_unexpected_token() {
        parse(quote!(OP_CHECKSIG &));
    }

    //#[test]
    //#[should_panic(expected = "unknown opcode \"A\"")]
    //fn parse_invalid_opcode() {
    //    parse(quote!(OP_CHECKSIG A B));
    //}

    #[test]
    fn parse_opcodes() {
        let syntax = parse(quote!(OP_CHECKSIG OP_HASH160));

        if let Syntax::Opcode(opcode) = syntax[0].0 {
            assert_eq!(opcode, opcodes::OP_CHECKSIG);
        } else {
            panic!();
        }

        if let Syntax::Opcode(opcode) = syntax[1].0 {
            assert_eq!(opcode, opcodes::OP_HASH160);
        } else {
            panic!();
        }
    }

    #[test]
    #[should_panic(expected = "unterminated escape")]
    fn parse_unterminated_escape() {
        parse(quote!(OP_CHECKSIG < abc));
    }

    #[test]
    fn parse_escape() {
        let syntax = parse(quote!(OP_CHECKSIG<abc>));

        if let Syntax::Escape(tokens) = &syntax[1].0 {
            let tokens = tokens.clone().into_iter().collect::<Vec<TokenTree>>();

            assert_eq!(tokens.len(), 1);
            if let TokenTree::Ident(_) = tokens[0] {
                assert_eq!(tokens[0].to_string(), "abc");
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "invalid number literal (invalid digit found in string)")]
    fn parse_invalid_int() {
        parse(quote!(OP_CHECKSIG 12g34));
    }

    #[test]
    fn parse_int() {
        let syntax = parse(quote!(OP_CHECKSIG 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, 1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "expected negative sign to be followed by number literal")]
    fn parse_invalid_negative_sign() {
        parse(quote!(OP_CHECKSIG - OP_HASH160));
    }

    #[test]
    fn parse_negative_int() {
        let syntax = parse(quote!(OP_CHECKSIG - 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, -1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    fn parse_hex() {
        let syntax = parse(quote!(OP_CHECKSIG 0x123456789abcde));

        if let Syntax::Bytes(bytes) = &syntax[1].0 {
            assert_eq!(bytes, &vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);
        } else {
            panic!("Unable to cast Syntax as Syntax::Bytes")
        }
    }
}
