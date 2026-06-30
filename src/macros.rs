/// Helper macro for creating StandardClause instances with less boilerplate.
///
/// # Examples
///
/// ```ignore
/// // Create a clause with next outputs (auto arg_specs)
/// let trigger_clause = clause!(
///     "trigger",
///     TriggerArgs,
///     script,
///     |params: &VaultParams, args: &TriggerArgs, state: Option<&()>| {
///         // compute next outputs...
///         Ok(vec![...])
///     }
/// );
///
/// // Create a terminal clause (no next outputs)
/// let recover_clause = clause!(
///     "recover",
///     RecoverArgs,
///     script
/// );
///
/// // Create a terminal clause with explicit types (for Unvaulting etc)
/// let withdraw_clause: Arc<dyn ErasedClause> = clause!(
///     "withdraw",
///     WithdrawArgs,
///     script;
///     UnvaultingParams,  // <- note the semicolon before types
///     UnvaultingState
/// );
///
/// // Create a clause with params for arg_specs_for_params (preferred when args depend on params)
/// let trigger_clause = clause!(
///     "trigger",
///     TriggerArgs,
///     script,
///     &params,  // params reference triggers arg_specs_for_params call
///     |params: &VaultParams, args: &TriggerArgs, state: Option<&()>| {
///         Ok(vec![...])
///     }
/// );
///
/// // Create a clause with explicit arg_specs (legacy)
/// let trigger_clause = clause!(
///     "trigger",
///     TriggerArgs,
///     script,
///     explicit_arg_specs_vec,
///     |params: &VaultParams, args: &TriggerArgs, state: Option<&()>| {
///         Ok(vec![...])
///     }
/// );
/// ```
#[macro_export]
macro_rules! clause {
    // Clause with params reference for arg_specs_for_params (preferred)
    ($name:expr, $args_type:ty, $script:expr, &$params:expr, $next_outputs:expr) => {
        ::std::sync::Arc::new($crate::contracts::StandardClause::<_, _, $args_type>::new(
            $name.to_string(),
            $script,
            <$args_type>::arg_specs_for_params(&$params),
            Some(::std::sync::Arc::new($next_outputs)),
        ))
    };

    // Clause with explicit arg_specs and next outputs (legacy)
    ($name:expr, $args_type:ty, $script:expr, $arg_specs:expr, $next_outputs:expr) => {
        ::std::sync::Arc::new($crate::contracts::StandardClause::<_, _, $args_type>::new(
            $name.to_string(),
            $script,
            $arg_specs,
            Some(::std::sync::Arc::new($next_outputs)),
        ))
    };

    // Clause with next outputs function (auto arg_specs from type)
    ($name:expr, $args_type:ty, $script:expr, $next_outputs:expr) => {
        ::std::sync::Arc::new($crate::contracts::StandardClause::<_, _, $args_type>::new(
            $name.to_string(),
            $script,
            <$args_type>::arg_specs(),
            Some(::std::sync::Arc::new($next_outputs)),
        ))
    };

    // Terminal clause with explicit Params and State types (for augmented contracts)
    // Uses semicolon to separate script from types
    ($name:expr, $args_type:ty, $script:expr; $params_type:ty, $state_type:ty) => {
        ::std::sync::Arc::new($crate::contracts::StandardClause::<
            $params_type,
            $state_type,
            $args_type,
        >::new(
            $name.to_string(),
            $script,
            <$args_type>::arg_specs(),
            None,
        ))
    };

    // Terminal clause (no next outputs) - uses () for Params and State
    ($name:expr, $args_type:ty, $script:expr) => {
        ::std::sync::Arc::new(
            $crate::contracts::StandardClause::<(), (), $args_type>::new(
                $name.to_string(),
                $script,
                <$args_type>::arg_specs(),
                None,
            ),
        )
    };
}

/// Helper macro for building contract instances with minimal boilerplate.
///
/// This macro helps construct the StandardP2TR, clause map, and associated structures
/// needed for a contract.
///
/// # Example
///
/// ```ignore
/// build_contract!(
///     params: vault_params,
///     internal_key: internal_key,
///     taptree: taptree,
///     clauses: [
///         ("trigger", trigger_clause),
///         ("recover", recover_clause),
///     ]
/// )
/// ```
#[macro_export]
macro_rules! build_contract {
    (
        params: $params:expr,
        internal_key: $internal_key:expr,
        taptree: $taptree:expr,
        clauses: [ $(($clause_name:expr, $clause:expr)),* $(,)? ]
    ) => {{
        let mut clause_vec: Vec<::std::sync::Arc<dyn $crate::contracts::ErasedClause>> = Vec::new();
        let mut clause_map = ::std::collections::HashMap::new();

        $(
            let clause_arc: ::std::sync::Arc<dyn $crate::contracts::ErasedClause> = $clause;
            clause_vec.push(clause_arc.clone());
            clause_map.insert($clause_name.to_string(), clause_arc);
        )*

        let contract = $crate::contracts::StandardP2TR::new(
            $internal_key,
            $taptree.clone(),
            clause_vec,
        );

        (contract, clause_map)
    }};
}

/// Helper macro for building taproot trees from clauses with nested list syntax.
///
/// Takes clause objects and builds a `TapTree` structure, returning both the tree
/// and a HashMap of clauses by name. Uses clone semantics - clauses should be `Arc<dyn ErasedClause>`.
///
/// # Syntax
///
/// - `taptree![clause1, clause2]` - Creates a balanced tree from multiple clauses
/// - `taptree![clause1, [clause2, clause3]]` - Creates explicit tree structure:
///   ```text
///        root
///       /    \
///   clause1  branch
///            /    \
///        clause2  clause3
///   ```
///
/// # Examples
///
/// ```ignore
/// // Simple flat list - creates balanced tree
/// let (tree, clauses) = taptree![trigger.clone(), recover.clone()];
///
/// // Explicit nesting - matches Python's list syntax
/// let (tree, clauses) = taptree![
///     trigger.clone(),
///     [trigger_and_revault.clone(), recover.clone()]
/// ];
/// ```
///
/// # Returns
///
/// Returns `(Arc<TapTree>, HashMap<String, Arc<dyn ErasedClause>>)`.
/// Runtime debug assertion checks for duplicate clause names.
#[macro_export]
macro_rules! taptree {
    // Single clause (base case) - expr pattern
    (@node $clause:expr) => {{
        let clause: ::std::sync::Arc<dyn $crate::contracts::ErasedClause> = $clause;
        let tree = $crate::contracts::TapTree::Leaf($crate::contracts::TapLeaf {
            name: clause.name().to_string(),
            script: clause.script().clone(),
        });
        let mut map: ::std::collections::HashMap<String, ::std::sync::Arc<dyn $crate::contracts::ErasedClause>> = ::std::collections::HashMap::new();
        map.insert(clause.name().to_string(), clause);
        (::std::sync::Arc::new(tree), map)
    }};

    // Nested branch (recursive case) - square brackets create a subtree
    (@node [$($inner:tt),+ $(,)?]) => {{
        $crate::taptree!($($inner),+)
    }};

    // Two elements where second is a nested branch
    ($left:expr, [$($right:tt),+ $(,)?]) => {{
        let (left_tree, mut left_map): (::std::sync::Arc<$crate::contracts::TapTree>, ::std::collections::HashMap<String, ::std::sync::Arc<dyn $crate::contracts::ErasedClause>>) = $crate::taptree!(@node $left);
        let (right_tree, right_map): (::std::sync::Arc<$crate::contracts::TapTree>, ::std::collections::HashMap<String, ::std::sync::Arc<dyn $crate::contracts::ErasedClause>>) = $crate::taptree!($($right),+);

        // Check for duplicate names
        for name in right_map.keys() {
            debug_assert!(
                !left_map.contains_key(name),
                "Duplicate clause name in taptree: {}",
                name
            );
        }

        left_map.extend(right_map);
        let tree = $crate::contracts::TapTree::Branch {
            left: left_tree,
            right: right_tree,
        };
        (::std::sync::Arc::new(tree), left_map)
    }};

    // Two simple expressions - create a branch
    ($left:expr, $right:expr) => {{
        let (left_tree, mut left_map): (::std::sync::Arc<$crate::contracts::TapTree>, ::std::collections::HashMap<String, ::std::sync::Arc<dyn $crate::contracts::ErasedClause>>) = $crate::taptree!(@node $left);
        let (right_tree, right_map): (::std::sync::Arc<$crate::contracts::TapTree>, ::std::collections::HashMap<String, ::std::sync::Arc<dyn $crate::contracts::ErasedClause>>) = $crate::taptree!(@node $right);

        // Check for duplicate names
        for name in right_map.keys() {
            debug_assert!(
                !left_map.contains_key(name),
                "Duplicate clause name in taptree: {}",
                name
            );
        }

        left_map.extend(right_map);
        let tree = $crate::contracts::TapTree::Branch {
            left: left_tree,
            right: right_tree,
        };
        (::std::sync::Arc::new(tree), left_map)
    }};

    // Three or more elements - balance the tree
    ($first:expr, $($rest:tt),+ $(,)?) => {{
        let (left_tree, mut left_map): (::std::sync::Arc<$crate::contracts::TapTree>, ::std::collections::HashMap<String, ::std::sync::Arc<dyn $crate::contracts::ErasedClause>>) = $crate::taptree!(@node $first);
        let (right_tree, right_map): (::std::sync::Arc<$crate::contracts::TapTree>, ::std::collections::HashMap<String, ::std::sync::Arc<dyn $crate::contracts::ErasedClause>>) = $crate::taptree!($($rest),+);

        // Check for duplicate names
        for name in right_map.keys() {
            debug_assert!(
                !left_map.contains_key(name),
                "Duplicate clause name in taptree: {}",
                name
            );
        }

        left_map.extend(right_map);
        let tree = $crate::contracts::TapTree::Branch {
            left: left_tree,
            right: right_tree,
        };
        (::std::sync::Arc::new(tree), left_map)
    }};

    // Single clause at top level
    ($clause:expr) => {{
        $crate::taptree!(@node $clause)
    }};
}
