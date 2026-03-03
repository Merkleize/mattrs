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

/// Generates typed newtype wrappers around instance indices with typed clause methods.
///
/// Each clause method encodes args, calls `manager.spend_instance()`, and returns
/// a tuple of typed next-instances. `self` is consumed so a spent instance can't be reused.
///
/// # Syntax
/// ```ignore
/// typed_instance! {
///     VaultInstance {
///         fn trigger(ctv_hash: bytes[32], out_i: i32) [signed] -> (UnvaultingInstance);
///         fn recover(out_i: i32) -> ();
///     }
/// }
/// ```
///
/// - `[signed]` adds a `signers: &SignerMap` parameter
/// - `-> (Type1, Type2)` returns a tuple of typed instances from `spend_instance` indices
/// - `-> ()` is a terminal clause (no tracked outputs)
#[macro_export]
macro_rules! typed_instance {
    (
        $name:ident {
            $( fn $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* $(,)? ) $( [ $modifier:ident ] )? -> ( $( $ret:ident ),* $(,)? ) ; )*
        }
    ) => {
        pub struct $name(pub usize);

        impl $name {
            /// Fund a new instance of this contract type.
            pub fn fund(
                manager: &mut $crate::manager::ContractManager,
                contract: $crate::contracts::Contract,
                data: $crate::contracts::StateData,
                amount: u64,
            ) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(manager.fund_instance(contract, data, amount)?))
            }

            /// Access the raw instance index for manual tx construction.
            pub fn idx(&self) -> usize { self.0 }

            $(
                typed_instance!(@method $name, $method ( $( $arg : $atype $( [ $alen ] )? ),* ) $( [ $modifier ] )? -> ( $( $ret ),* ) );
            )*
        }
    };

    // Method with [signed] modifier
    (@method $name:ident, $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* ) [ signed ] -> ( $( $ret:ident ),* ) ) => {
        pub fn $method(
            self,
            manager: &mut $crate::manager::ContractManager,
            $( $arg : typed_instance!(@rust_type $atype $( [ $alen ] )? ), )*
            signers: &$crate::signer::SignerMap,
        ) -> Result<( $( $ret, )* ), Box<dyn std::error::Error>> {
            let mut args = std::collections::HashMap::new();
            $(
                typed_instance!(@encode args, $arg, $atype $( [ $alen ] )? );
            )*
            let _indices = manager.spend_instance(self.0, stringify!($method), args, Some(signers))?;
            typed_instance!(@return _indices, 0usize, $( $ret ),* )
        }
    };

    // Method without modifier (unsigned)
    (@method $name:ident, $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* ) -> ( $( $ret:ident ),* ) ) => {
        pub fn $method(
            self,
            manager: &mut $crate::manager::ContractManager,
            $( $arg : typed_instance!(@rust_type $atype $( [ $alen ] )? ), )*
        ) -> Result<( $( $ret, )* ), Box<dyn std::error::Error>> {
            let mut args = std::collections::HashMap::new();
            $(
                typed_instance!(@encode args, $arg, $atype $( [ $alen ] )? );
            )*
            let _indices = manager.spend_instance(self.0, stringify!($method), args, None)?;
            typed_instance!(@return _indices, 0usize, $( $ret ),* )
        }
    };

    // Rust type mapping
    (@rust_type bytes [ $len:expr ]) => { [u8; $len] };
    (@rust_type i32) => { i32 };

    // Arg encoding: bytes
    (@encode $map:ident, $arg:ident, bytes [ $len:expr ]) => {
        $map.insert(stringify!($arg).to_string(), $arg.to_vec());
    };
    // Arg encoding: i32
    (@encode $map:ident, $arg:ident, i32) => {
        {
            let mut _buf = [0u8; 8];
            let _len = bitcoin::script::write_scriptint(&mut _buf, $arg as i64);
            $map.insert(stringify!($arg).to_string(), _buf[.._len].to_vec());
        }
    };

    // Return tuple construction: base case (no more types)
    (@return $indices:ident, $i:expr, ) => {
        Ok(())
    };
    // Return tuple construction: one or more types
    (@return $indices:ident, $i:expr, $first:ident $( , $rest:ident )* ) => {
        {
            let _first_val = $first($indices[$i]);
            typed_instance!(@return_acc $indices, ($i + 1usize), ( _first_val, ) $( $rest ),* )
        }
    };
    // Accumulator: done
    (@return_acc $indices:ident, $i:expr, ( $( $acc:expr, )* ) ) => {
        Ok(( $( $acc, )* ))
    };
    // Accumulator: more types
    (@return_acc $indices:ident, $i:expr, ( $( $acc:expr, )* ) $next:ident $( , $rest:ident )* ) => {
        {
            let _next_val = $next($indices[$i]);
            typed_instance!(@return_acc $indices, ($i + 1usize), ( $( $acc, )* _next_val, ) $( $rest ),* )
        }
    };
}
