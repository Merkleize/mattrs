//! Declarative helper below the `contract!` DSL: `clause_tree!` arranges
//! (type-erased) clauses into a `ClauseTree` with nested-bracket syntax. The
//! `contract!` macro expands to it; use it directly (alongside
//! [`StandardClause::new`](crate::contracts::StandardClause::new)) when a
//! contract doesn't fit the DSL — e.g. the runtime-shaped clauses of
//! [`mattrs::fraud`](crate::fraud).

/// Build a [`ClauseTree`](crate::contracts::ClauseTree) from clauses, with nested
/// list syntax that mirrors the taproot tree shape.
///
/// Each element is an `Arc<dyn ErasedClause>` (e.g. from
/// [`StandardClause::new`](crate::contracts::StandardClause::new)). A bracketed
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
