#[macro_export]
macro_rules! ccv_list {
    (
        $(
            $behaviour:ident ( $n:expr ) => $contract:expr $( ; $state:expr )? $(,)?
        )*
    ) => {
        $crate::contracts::ClauseOutputs::CcvList(vec![
            $(
                $crate::contracts::CcvOutputDescription {
                    n: $n,
                    next_contract: Box::new($contract.clone()),
                    next_state: ccv_list!(@optional_state $( $state )? ),
                    behaviour: ccv_list!(@parse_behaviour $behaviour),
                }
            ),*
        ])
    };
    (@optional_state $state:expr) => {
        Some(Box::new($state))
    };
    (@optional_state) => {
        None
    };
    (@parse_behaviour deduct) => { $crate::contracts::CcvClauseOutputAmountBehaviour::DeductOutput };
    (@parse_behaviour ignore) => { $crate::contracts::CcvClauseOutputAmountBehaviour::IgnoreOutput };
    (@parse_behaviour preserve) => { $crate::contracts::CcvClauseOutputAmountBehaviour::PreserveOutput };
}

#[macro_export]
macro_rules! define_clause {
    (
        $clause_struct_name:ident,
        $clause_args_struct_name:ident,
        $clause_string_name:expr,
        $contract_params:ty,
        $contract_state:ty,
        args { $( $arg_name:ident : $arg_type:ty => $arg_spec:expr ),* $(,)? },
        script($script_params:tt) $script_body:block,
        next_outputs($no_params:tt,$no_args:tt,$no_state:tt) $next_outputs_body:block
    ) => {
        #[derive(Debug, Clone)]
        pub struct $clause_struct_name {}

        #[derive(Debug, Clone)]
        pub struct $clause_args_struct_name {
            $(pub $arg_name: $arg_type),*
        }

        impl $crate::contracts::ClauseArguments for $clause_args_struct_name {
            fn as_arg_specs() -> $crate::contracts::ArgSpecs {
                vec![
                    $(
                        (stringify!($arg_name).to_string(), $arg_spec),
                    )*
                ]
            }
        }

        impl $crate::contracts::Clause<$contract_params, $clause_args_struct_name, $contract_state> for $clause_struct_name {
            fn name() -> String {
                $clause_string_name.into()
            }

            fn script($script_params: &$contract_params) -> bitcoin::ScriptBuf {
                $script_body
            }

            fn arg_specs() -> $crate::contracts::ArgSpecs {
                <$clause_args_struct_name>::as_arg_specs()
            }

            fn next_outputs(
                $no_params: &$contract_params,
                $no_args: &$clause_args_struct_name,
                $no_state: &$contract_state,
            ) -> $crate::contracts::ClauseOutputs {
                $next_outputs_body
            }
        }
    };
}

#[macro_export]
macro_rules! define_contract {
    (
        $contract_struct_name:ident,
        $contract_params:ty,
        $contract_state:ty,
        $( get_pk($params_name:ident) $get_pk_block:block, )?
        taptree: $taptree:tt
    ) => {
        #[derive(Debug, Clone)]
        pub struct $contract_struct_name {
            pub params: $contract_params,
            pub pk: XOnlyPublicKey,
        }

        impl $contract_struct_name {
            pub fn new(params: $contract_params) -> Self {
                let pk = define_contract!(@get_pk params $( get_pk($params_name): $get_pk_block )? );
                Self {
                    params,
                    pk,
                }
            }
        }

        impl $crate::contracts::Contract<$contract_params, $contract_state> for $contract_struct_name {
            fn get_taptree(&self) -> $crate::contracts::TapTree {
                define_contract!(@process_taptree self, $taptree)
            }

            fn get_naked_internal_key(&self) -> XOnlyPublicKey {
                self.pk
            }
        }
    };

    // Helper to process the optional get_pk block
    (@get_pk $params:ident get_pk($params_name:ident): $get_pk_block:block ) => {{
        let $params_name = &$params;
        $get_pk_block
    }};

    // Default implementation if get_pk is omitted
    (@get_pk $params:ident) => {
        XOnlyPublicKey::from_slice(&NUMS_KEY).expect("Valid default key")
    };

    // Process a single clause (leaf node)
    (@process_taptree $self:ident, $clause:ident) => {{
        let script = $clause::script(&$self.params);
        let name = $clause::name().to_string();
        $crate::contracts::TapTree::Leaf($crate::contracts::TapLeaf {
            name,
            script,
            leaf_version: bitcoin::taproot::LeafVersion::TapScript,
        })
    }};

    // Process a tuple representing a TapTree branch
    (@process_taptree $self:ident, ( $left:tt , $right:tt ) ) => {{
        let left = define_contract!(@process_taptree $self, $left);
        let right = define_contract!(@process_taptree $self, $right);
        $crate::contracts::TapTree::Branch {
            left: Box::new(left),
            right: Box::new(right),
        }
    }};
}
