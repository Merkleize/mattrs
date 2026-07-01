/// Helper macro for creating `StandardClause` instances with less boilerplate.
///
/// Returns `Arc<StandardClause<P, S, ArgsType>>`. Bind it to
/// `Arc<dyn ErasedClause>` to type-erase it for a `clause_tree!`.
///
/// # Forms
///
/// ```ignore
/// // Param-dependent arg specs (preferred when an arg is a `#[signer(|p| ..)]`):
/// // the `&params` triggers `ArgsType::arg_specs_for_params(&params)`.
/// let trigger = clause!("trigger", TriggerArgs, script, &params,
///     |p: &VaultParams, a: &TriggerArgs, _s: Option<&()>| { Ok(vec![/* ... */]) });
///
/// // Static arg specs + next-outputs function:
/// let recover = clause!("recover", RecoverArgs, script,
///     |p: &VaultParams, a: &RecoverArgs, _s: Option<&()>| { Ok(vec![]) });
///
/// // Terminal clause with explicit Params/State types (note the `;`):
/// let withdraw: Arc<dyn ErasedClause> =
///     clause!("withdraw", WithdrawArgs, script; UnvaultingParams, UnvaultingState);
///
/// // Terminal clause for a stateless/paramless contract (uses `()` for P and S):
/// let recover = clause!("recover", RecoverArgs, script);
/// ```
#[macro_export]
macro_rules! clause {
    // Clause with params reference for arg_specs_for_params (preferred).
    ($name:expr, $args_type:ty, $script:expr, &$params:expr, $next_outputs:expr) => {
        ::std::sync::Arc::new($crate::contracts::StandardClause::<_, _, $args_type>::new(
            $name.to_string(),
            $script,
            <$args_type>::arg_specs_for_params(&$params),
            Some(::std::sync::Arc::new($next_outputs)),
        ))
    };

    // Clause with explicit arg_specs and next outputs.
    ($name:expr, $args_type:ty, $script:expr, $arg_specs:expr, $next_outputs:expr) => {
        ::std::sync::Arc::new($crate::contracts::StandardClause::<_, _, $args_type>::new(
            $name.to_string(),
            $script,
            $arg_specs,
            Some(::std::sync::Arc::new($next_outputs)),
        ))
    };

    // Clause with next-outputs function (auto arg_specs from type).
    ($name:expr, $args_type:ty, $script:expr, $next_outputs:expr) => {
        ::std::sync::Arc::new($crate::contracts::StandardClause::<_, _, $args_type>::new(
            $name.to_string(),
            $script,
            <$args_type>::arg_specs(),
            Some(::std::sync::Arc::new($next_outputs)),
        ))
    };

    // Terminal clause with explicit Params and State types (separated by `;`).
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

    // Terminal clause for a stateless/paramless contract (uses `()` for P and S).
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

/// Build a [`ClauseTree`](crate::contracts::ClauseTree) from clauses, with nested
/// list syntax that mirrors the taproot tree shape.
///
/// Each element is an `Arc<dyn ErasedClause>` (e.g. from [`clause!`]). A bracketed
/// group `[a, b]` forms a subtree. The resulting `ClauseTree` is the single source
/// of truth handed to `StandardP2TR::new` / `StandardAugmentedP2TR::new`, which
/// derive both the address-bearing script taptree and the spend-time clause lookup
/// from it.
///
/// ```ignore
/// // trigger
/// //   \_ [trigger_and_revault, recover]
/// let tree = clause_tree![trigger, [trigger_and_revault, recover]];
/// let contract = StandardP2TR::new(internal_key, tree);
/// ```
#[macro_export]
macro_rules! clause_tree {
    // A bracketed group is its own subtree.
    (@node [$($inner:tt),+ $(,)?]) => {
        $crate::clause_tree!($($inner),+)
    };

    // A bare expression is a leaf.
    (@node $clause:expr) => {
        $crate::contracts::ClauseTree::leaf($clause)
    };

    // Bracketed left subtree, then the rest (must precede the `$left:expr` arms so
    // the leading bracket isn't captured as an array expression).
    ([$($left:tt),+ $(,)?], $($rest:tt),+ $(,)?) => {
        $crate::contracts::ClauseTree::branch(
            $crate::clause_tree!($($left),+),
            $crate::clause_tree!($($rest),+),
        )
    };

    // left expr, bracketed right subtree.
    ($left:expr, [$($right:tt),+ $(,)?]) => {
        $crate::contracts::ClauseTree::branch(
            $crate::clause_tree!(@node $left),
            $crate::clause_tree!($($right),+),
        )
    };

    // Two expressions -> a branch.
    ($left:expr, $right:expr $(,)?) => {
        $crate::contracts::ClauseTree::branch(
            $crate::clause_tree!(@node $left),
            $crate::clause_tree!(@node $right),
        )
    };

    // Three or more -> first as the left leaf, the rest balanced to the right.
    ($first:expr, $($rest:tt),+ $(,)?) => {
        $crate::contracts::ClauseTree::branch(
            $crate::clause_tree!(@node $first),
            $crate::clause_tree!($($rest),+),
        )
    };

    // Single clause.
    ($clause:expr) => {
        $crate::clause_tree!(@node $clause)
    };
}
