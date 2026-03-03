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
/// Uses the `ClauseArg` trait for type-extensible encoding/decoding.
///
/// # Example
/// ```ignore
/// define_clause_args! {
///     TriggerArgs {
///         sig: [u8; 64],
///         ctv_hash: [u8; 32],
///         out_i: i32,
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_clause_args {
    (
        $name:ident {
            $( $field:ident : $ftype:ty ),* $(,)?
        }
    ) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            $( pub $field: $ftype, )*
        }

        impl $name {
            pub fn to_clause_args(&self) -> $crate::contracts::ClauseArgs {
                let mut args = std::collections::HashMap::new();
                $(
                    args.insert(stringify!($field).to_string(), $crate::contracts::ClauseArg::to_bytes(&self.$field));
                )*
                args
            }

            pub fn from_clause_args(args: &$crate::contracts::ClauseArgs) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                Ok(Self {
                    $(
                        $field: {
                            let v = args.get(stringify!($field))
                                .ok_or_else(|| format!("Missing arg '{}'", stringify!($field)))?;
                            <$ftype as $crate::contracts::ClauseArg>::from_bytes(v)?
                        },
                    )*
                })
            }

            pub fn arg_names() -> Vec<&'static str> {
                vec![ $( stringify!($field), )* ]
            }
        }
    };
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
///         fn trigger(ctv_hash: [u8; 32], out_i: i32) [signed(sig)] -> (UnvaultingInstance);
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
            $( fn $method:ident ( $( $arg:ident : $atype:ty ),* $(,)? ) $( [ signed( $signer:ident ) ] )? -> ( $( $ret:ident ),* $(,)? ) ; )*
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
                contract!(@method $instance, $method ( $( $arg : $atype ),* ) $( [ signed( $signer ) ] )? -> ( $( $ret ),* ) );
            )*
        }

        // 2. Clause constructor namespace
        pub struct $clause_ns;

        impl $clause_ns {
            $(
                contract!(@clause_method $method ( $( $arg : $atype ),* ) $( [ signed( $signer ) ] )? );
            )*
        }
    };

    // ── Typed spend methods (instance struct) ───────────────────────────

    // Method with [signed(name)] modifier
    (@method $name:ident, $method:ident ( $( $arg:ident : $atype:ty ),* ) [ signed( $signer:ident ) ] -> ( $( $ret:ident ),* ) ) => {
        pub fn $method(
            self,
            manager: &mut $crate::manager::ContractManager,
            $( $arg : $atype, )*
            signers: &$crate::signer::SignerMap,
        ) -> Result<( $( $ret, )* ), Box<dyn std::error::Error>> {
            let mut args = std::collections::HashMap::new();
            $(
                args.insert(stringify!($arg).to_string(), <$atype as $crate::contracts::ClauseArg>::to_bytes(&$arg));
            )*
            let _indices = manager.spend_instance(self.0, stringify!($method), args, Some(signers))?;
            contract!(@return _indices, 0usize, $( $ret ),* )
        }
    };

    // Method without modifier (unsigned)
    (@method $name:ident, $method:ident ( $( $arg:ident : $atype:ty ),* ) -> ( $( $ret:ident ),* ) ) => {
        pub fn $method(
            self,
            manager: &mut $crate::manager::ContractManager,
            $( $arg : $atype, )*
        ) -> Result<( $( $ret, )* ), Box<dyn std::error::Error>> {
            let mut args = std::collections::HashMap::new();
            $(
                args.insert(stringify!($arg).to_string(), <$atype as $crate::contracts::ClauseArg>::to_bytes(&$arg));
            )*
            let _indices = manager.spend_instance(self.0, stringify!($method), args, None)?;
            contract!(@return _indices, 0usize, $( $ret ),* )
        }
    };

    // ── Clause constructor methods (namespace struct) ───────────────────

    // Signed clause: adds signer key parameter
    (@clause_method $method:ident ( $( $arg:ident : $atype:ty ),* ) [ signed( $signer:ident ) ] ) => {
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
                    $( (stringify!($arg), <$atype as $crate::contracts::ClauseArg>::arg_type()), )*
                ],
                next_outputs,
            )
        }
    };

    // Unsigned clause
    (@clause_method $method:ident ( $( $arg:ident : $atype:ty ),* ) ) => {
        pub fn $method(
            script: bitcoin::ScriptBuf,
            next_outputs: impl Fn(&$crate::contracts::ClauseArgs, &$crate::contracts::StateData) -> Result<Vec<$crate::contracts::ClauseOutput>, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
        ) -> $crate::contracts::Clause {
            $crate::contracts::standard_clause(
                stringify!($method),
                script,
                vec![
                    $( (stringify!($arg), <$atype as $crate::contracts::ClauseArg>::arg_type()), )*
                ],
                next_outputs,
            )
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
