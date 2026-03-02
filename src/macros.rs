/// Generates a typed state struct with encode/decode helpers for StateData (Vec<u8>).
///
/// # Example
/// ```ignore
/// define_state! {
///     UnvaultingState {
///         ctv_hash: [u8; 32],
///     }
/// }
/// ```
///
/// This generates:
/// - `UnvaultingState` struct with `pub ctv_hash: [u8; 32]`
/// - `UnvaultingState::encode(&self) -> StateData` (concatenates fields)
/// - `UnvaultingState::decode(data: &StateData) -> Result<Self, ...>` (splits fields)
#[macro_export]
macro_rules! define_state {
    (
        $name:ident {
            $( $field:ident : [ u8 ; $len:expr ] ),* $(,)?
        }
    ) => {
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name {
            $( pub $field: [u8; $len], )*
        }

        impl $name {
            pub fn encode(&self) -> $crate::contracts::StateData {
                let mut buf = Vec::new();
                $( buf.extend_from_slice(&self.$field); )*
                buf
            }

            pub fn decode(data: &$crate::contracts::StateData) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                let mut _offset = 0usize;
                $(
                    if data.len() < _offset + $len {
                        return Err(format!(
                            "StateData too short: need {} bytes for field '{}', have {}",
                            _offset + $len, stringify!($field), data.len()
                        ).into());
                    }
                    let mut $field = [0u8; $len];
                    $field.copy_from_slice(&data[_offset.._offset + $len]);
                    _offset += $len;
                )*
                Ok(Self { $( $field, )* })
            }
        }
    };
}

/// Generates a typed clause-args struct with to_clause_args/from_clause_args helpers.
///
/// Supported field types:
/// - `[u8; N]`: fixed-size byte arrays
/// - `i32`: script integers (encoded via bitcoin's scriptint)
///
/// # Example
/// ```ignore
/// define_clause_args! {
///     TriggerArgs {
///         sig: bytes[64],
///         ctv_hash: bytes[32],
///         out_i: i32,
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_clause_args {
    (
        $name:ident {
            $( $field:ident : $ftype:tt $( [ $len:expr ] )? ),* $(,)?
        }
    ) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            $( pub $field: define_clause_args!(@field_type $ftype $( [ $len ] )? ), )*
        }

        impl $name {
            pub fn to_clause_args(&self) -> $crate::contracts::ClauseArgs {
                let mut args = std::collections::HashMap::new();
                $(
                    define_clause_args!(@encode self, args, $field, $ftype $( [ $len ] )? );
                )*
                args
            }

            pub fn from_clause_args(args: &$crate::contracts::ClauseArgs) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                Ok(Self {
                    $(
                        $field: define_clause_args!(@decode args, $field, $ftype $( [ $len ] )? ),
                    )*
                })
            }

            pub fn arg_names() -> Vec<&'static str> {
                vec![ $( stringify!($field), )* ]
            }
        }
    };

    // Field type resolution
    (@field_type bytes [ $len:expr ]) => { [u8; $len] };
    (@field_type i32) => { i32 };

    // Encoding: bytes
    (@encode $self:ident, $map:ident, $field:ident, bytes [ $len:expr ]) => {
        $map.insert(stringify!($field).to_string(), $self.$field.to_vec());
    };
    // Encoding: i32
    (@encode $self:ident, $map:ident, $field:ident, i32) => {
        let mut buf = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut buf, $self.$field as i64);
        $map.insert(stringify!($field).to_string(), buf[..len].to_vec());
    };

    // Decoding: bytes
    (@decode $map:ident, $field:ident, bytes [ $len:expr ]) => {{
        let v = $map.get(stringify!($field))
            .ok_or_else(|| format!("Missing arg '{}'", stringify!($field)))?;
        let mut arr = [0u8; $len];
        if v.len() != $len {
            return Err(format!("Arg '{}': expected {} bytes, got {}", stringify!($field), $len, v.len()).into());
        }
        arr.copy_from_slice(v);
        arr
    }};
    // Decoding: i32
    (@decode $map:ident, $field:ident, i32) => {{
        let v = $map.get(stringify!($field))
            .ok_or_else(|| format!("Missing arg '{}'", stringify!($field)))?;
        bitcoin::script::read_scriptint(v)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("Arg '{}': {}", stringify!($field), e).into() })?
            as i32
    }};
}
