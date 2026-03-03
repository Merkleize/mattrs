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

/// Generates a `next_outputs` closure from a compact declaration.
///
/// # Syntax
/// ```ignore
/// // Terminal clause (no outputs):
/// ccv_outputs!()
///
/// // One or more outputs, semicolon-separated:
/// ccv_outputs!(
///     index_arg => contract_expr;                           // basic
///     index_arg => contract_expr, state: state_arg;         // with state
///     index_arg => contract_expr, deduct;                   // deduct amount
///     index_arg => contract_expr, state: state_arg, deduct; // both
/// )
/// ```
#[macro_export]
macro_rules! ccv_outputs {
    // Empty: terminal clause with no outputs
    () => {
        |_args: &$crate::contracts::ClauseArgs,
         _state: &$crate::contracts::StateData|
         -> Result<Vec<$crate::contracts::ClauseOutput>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(vec![])
        }
    };

    // One or more output specs, semicolon-separated
    ( $( $index_arg:ident => $contract:expr $( , $tag:tt $( : $tag_val:ident )? )* );+ $(;)? ) => {
        move |args: &$crate::contracts::ClauseArgs,
              _state: &$crate::contracts::StateData|
              -> Result<Vec<$crate::contracts::ClauseOutput>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(vec![
                $( ccv_outputs!(@single args, $index_arg, $contract $(, $tag $( : $tag_val )? )* ), )+
            ])
        }
    };

    // Internal: single output with state + deduct
    (@single $args:ident, $index_arg:ident, $contract:expr, state: $state_arg:ident, deduct) => {
        $crate::contracts::ClauseOutput {
            n: $crate::contracts::arg_as_int($args, stringify!($index_arg))?,
            next_contract: $contract,
            next_state: $crate::contracts::arg_as_bytes($args, stringify!($state_arg))?.clone(),
            amount_behaviour: $crate::contracts::CcvAmountBehaviour::Deduct,
        }
    };
    // Internal: single output with state only
    (@single $args:ident, $index_arg:ident, $contract:expr, state: $state_arg:ident) => {
        $crate::contracts::ClauseOutput {
            n: $crate::contracts::arg_as_int($args, stringify!($index_arg))?,
            next_contract: $contract,
            next_state: $crate::contracts::arg_as_bytes($args, stringify!($state_arg))?.clone(),
            amount_behaviour: $crate::contracts::CcvAmountBehaviour::Preserve,
        }
    };
    // Internal: single output with deduct only
    (@single $args:ident, $index_arg:ident, $contract:expr, deduct) => {
        $crate::contracts::ClauseOutput {
            n: $crate::contracts::arg_as_int($args, stringify!($index_arg))?,
            next_contract: $contract,
            next_state: vec![],
            amount_behaviour: $crate::contracts::CcvAmountBehaviour::Deduct,
        }
    };
    // Internal: single output, basic (no state, no deduct)
    (@single $args:ident, $index_arg:ident, $contract:expr) => {
        $crate::contracts::ClauseOutput {
            n: $crate::contracts::arg_as_int($args, stringify!($index_arg))?,
            next_contract: $contract,
            next_state: vec![],
            amount_behaviour: $crate::contracts::CcvAmountBehaviour::Preserve,
        }
    };
}

/// Generates a typed instance wrapper and a clause constructor namespace from a single declaration.
///
/// Each clause's arg names and types are declared **once** and used to generate both:
/// 1. Typed spend methods on the instance struct (for the `ContractManager` API)
/// 2. Clause constructor functions on the namespace struct (replacing manual `standard_clause()` calls)
///
/// # Syntax
/// ```ignore
/// contract! {
///     VaultInstance, VaultClause {
///         fn trigger(ctv_hash: bytes[32], out_i: i32) [signed(sig)] -> (UnvaultingInstance);
///         fn recover(out_i: i32) -> ();
///     }
/// }
/// ```
///
/// - `[signed(sig)]` means the clause has a 64-byte signature arg named `sig`
///   - Adds `signers: &SignerMap` to the typed spend method
///   - Adds `sig: XOnlyPublicKey` parameter to the clause constructor
/// - `-> (Type1, Type2)` returns typed instances from `spend_instance` indices
/// - `-> ()` is a terminal clause (no tracked outputs)
#[macro_export]
macro_rules! contract {
    // ── Main entry point ────────────────────────────────────────────────
    (
        $instance:ident, $clause_ns:ident {
            $( fn $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* $(,)? ) $( [ signed( $signer:ident ) ] )? -> ( $( $ret:ident ),* $(,)? ) ; )*
        }
    ) => {
        // 1. Typed instance struct with spend methods
        pub struct $instance(pub usize);

        impl $instance {
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
                contract!(@method $instance, $method ( $( $arg : $atype $( [ $alen ] )? ),* ) $( [ signed( $signer ) ] )? -> ( $( $ret ),* ) );
            )*
        }

        // 2. Clause constructor namespace
        pub struct $clause_ns;

        impl $clause_ns {
            $(
                contract!(@clause_method $method ( $( $arg : $atype $( [ $alen ] )? ),* ) $( [ signed( $signer ) ] )? );
            )*
        }
    };

    // ── Typed spend methods (instance struct) ───────────────────────────

    // Method with [signed(name)] modifier
    (@method $name:ident, $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* ) [ signed( $signer:ident ) ] -> ( $( $ret:ident ),* ) ) => {
        pub fn $method(
            self,
            manager: &mut $crate::manager::ContractManager,
            $( $arg : contract!(@rust_type $atype $( [ $alen ] )? ), )*
            signers: &$crate::signer::SignerMap,
        ) -> Result<( $( $ret, )* ), Box<dyn std::error::Error>> {
            let mut args = std::collections::HashMap::new();
            $(
                contract!(@encode args, $arg, $atype $( [ $alen ] )? );
            )*
            let _indices = manager.spend_instance(self.0, stringify!($method), args, Some(signers))?;
            contract!(@return _indices, 0usize, $( $ret ),* )
        }
    };

    // Method without modifier (unsigned)
    (@method $name:ident, $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* ) -> ( $( $ret:ident ),* ) ) => {
        pub fn $method(
            self,
            manager: &mut $crate::manager::ContractManager,
            $( $arg : contract!(@rust_type $atype $( [ $alen ] )? ), )*
        ) -> Result<( $( $ret, )* ), Box<dyn std::error::Error>> {
            let mut args = std::collections::HashMap::new();
            $(
                contract!(@encode args, $arg, $atype $( [ $alen ] )? );
            )*
            let _indices = manager.spend_instance(self.0, stringify!($method), args, None)?;
            contract!(@return _indices, 0usize, $( $ret ),* )
        }
    };

    // ── Clause constructor methods (namespace struct) ───────────────────

    // Signed clause: adds signer key parameter
    (@clause_method $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* ) [ signed( $signer:ident ) ] ) => {
        #[allow(clippy::too_many_arguments)]
        pub fn $method(
            script: bitcoin::ScriptBuf,
            $signer: bitcoin::XOnlyPublicKey,
            next_outputs: impl Fn(&$crate::contracts::ClauseArgs, &$crate::contracts::StateData) -> Result<Vec<$crate::contracts::ClauseOutput>, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
        ) -> $crate::contracts::Clause {
            $crate::contracts::standard_clause(
                stringify!($method),
                script,
                vec![
                    (stringify!($signer), $crate::contracts::ArgType::Signer($signer)),
                    $( (stringify!($arg), contract!(@arg_spec $atype $( [ $alen ] )? )), )*
                ],
                next_outputs,
            )
        }
    };

    // Unsigned clause
    (@clause_method $method:ident ( $( $arg:ident : $atype:tt $( [ $alen:expr ] )? ),* ) ) => {
        pub fn $method(
            script: bitcoin::ScriptBuf,
            next_outputs: impl Fn(&$crate::contracts::ClauseArgs, &$crate::contracts::StateData) -> Result<Vec<$crate::contracts::ClauseOutput>, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
        ) -> $crate::contracts::Clause {
            $crate::contracts::standard_clause(
                stringify!($method),
                script,
                vec![
                    $( (stringify!($arg), contract!(@arg_spec $atype $( [ $alen ] )? )), )*
                ],
                next_outputs,
            )
        }
    };

    // ── ArgType mapping (for clause constructors) ───────────────────────
    (@arg_spec bytes [ $len:expr ]) => { $crate::contracts::ArgType::Bytes($len) };
    (@arg_spec i32) => { $crate::contracts::ArgType::Int };

    // ── Rust type mapping (for spend methods) ───────────────────────────
    (@rust_type bytes [ $len:expr ]) => { [u8; $len] };
    (@rust_type i32) => { i32 };

    // ── Arg encoding (for spend methods) ────────────────────────────────
    (@encode $map:ident, $arg:ident, bytes [ $len:expr ]) => {
        $map.insert(stringify!($arg).to_string(), $arg.to_vec());
    };
    (@encode $map:ident, $arg:ident, i32) => {
        {
            let mut _buf = [0u8; 8];
            let _len = bitcoin::script::write_scriptint(&mut _buf, $arg as i64);
            $map.insert(stringify!($arg).to_string(), _buf[.._len].to_vec());
        }
    };

    // ── Return tuple construction ───────────────────────────────────────
    // Base case: no return types
    (@return $indices:ident, $i:expr, ) => {
        Ok(())
    };
    // One or more return types
    (@return $indices:ident, $i:expr, $first:ident $( , $rest:ident )* ) => {
        {
            let _first_val = $first($indices[$i]);
            contract!(@return_acc $indices, ($i + 1usize), ( _first_val, ) $( $rest ),* )
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
            contract!(@return_acc $indices, ($i + 1usize), ( $( $acc, )* _next_val, ) $( $rest ),* )
        }
    };
}
