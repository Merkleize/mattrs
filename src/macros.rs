//! Declarative helper below the `contract!` DSL: `clause_tree!` arranges
//! (type-erased) clauses into a `ClauseTree` with nested-bracket syntax. The
//! `contract!` macro expands to it; use it directly (alongside
//! [`StandardClause::new`](crate::contracts::StandardClause::new)) when a
//! contract doesn't fit the DSL — e.g. the runtime-shaped clauses of
//! [`mattrs::fraud`](crate::fraud).

/// Build a [`ClauseTree`](crate::contracts::ClauseTree) from clauses, with
/// bracket syntax mirroring the taproot tree grammar:
///
/// ```text
/// TREE := clause              (a leaf)
///       | [ TREE, TREE ]      (a branch)
/// ```
///
/// Each leaf is an `Arc<dyn ErasedClause>` (e.g. from
/// [`StandardClause::new`](crate::contracts::StandardClause::new)); a bracketed
/// pair forms a branch anywhere a leaf can appear, so any binary tree is
/// expressible — `[[a, b], [c, d]]` is the balanced four-leaf tree. The macro's
/// own brackets stand in for the outermost pair's: `clause_tree![a, [b, c]]`
/// is the tree `[a, [b, c]]`. Every branch is written out: a level with three
/// or more entries is a compile error, not an implicit shape.
///
/// The resulting `ClauseTree` is the single source of truth handed to
/// `StandardP2TR::new` / `StandardAugmentedP2TR::new`, which derive both the
/// address-bearing script taptree and the spend-time clause lookup from it.
///
/// ```ignore
/// // trigger
/// //   \_ [trigger_and_revault, recover]
/// let tree = clause_tree![trigger, [trigger_and_revault, recover]];
/// let contract = StandardP2TR::new(internal_key, tree);
/// ```
#[macro_export]
macro_rules! clause_tree {
    // A branch: exactly two subtrees, each a clause expression or a bracketed
    // pair. Group interiors are captured as raw tokens and re-split by the
    // recursion (an `$:expr` fragment stops at a top-level comma, so entries
    // may be arbitrary expressions). The group-headed arms must precede the
    // `$:expr` ones so a leading bracket isn't captured as an array expression.
    ([$($left:tt)+], [$($right:tt)+] $(,)?) => {
        $crate::contracts::ClauseTree::branch(
            $crate::clause_tree!($($left)+),
            $crate::clause_tree!($($right)+),
        )
    };
    ([$($left:tt)+], $right:expr $(,)?) => {
        $crate::contracts::ClauseTree::branch(
            $crate::clause_tree!($($left)+),
            $crate::contracts::ClauseTree::leaf($right),
        )
    };
    ($left:expr, [$($right:tt)+] $(,)?) => {
        $crate::contracts::ClauseTree::branch(
            $crate::contracts::ClauseTree::leaf($left),
            $crate::clause_tree!($($right)+),
        )
    };
    ($left:expr, $right:expr $(,)?) => {
        $crate::contracts::ClauseTree::branch(
            $crate::contracts::ClauseTree::leaf($left),
            $crate::contracts::ClauseTree::leaf($right),
        )
    };

    // A lone bracketed pair wraps the whole (sub)tree. Must precede the lone
    // expression arm, which would otherwise capture it as an array literal.
    ([$($inner:tt)+] $(,)?) => {
        $crate::clause_tree!($($inner)+)
    };

    // A single clause: the tree is one leaf.
    ($clause:expr $(,)?) => {
        $crate::contracts::ClauseTree::leaf($clause)
    };

    // Anything else — e.g. three entries at one level — is not a tree shape.
    ($($rest:tt)+) => {
        ::core::compile_error!(
            "clause_tree!: a tree level is one clause or exactly two subtrees; \
             write branches explicitly, e.g. `[a, [b, c]]`"
        )
    };
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitcoin::ScriptBuf;
    use mattrs_derive::{contract, ContractParams};

    use crate::contracts::{ClauseTree, ErasedClause, RawArgs, StandardClause};

    /// A named do-nothing clause; tree shape is all these tests care about.
    fn clause(name: &str) -> Arc<dyn ErasedClause> {
        Arc::new(StandardClause::<(), (), RawArgs>::new(
            name.into(),
            ScriptBuf::new(),
            vec![],
            None,
        ))
    }

    /// Render the tree as `((a b) c)`-style nesting of leaf names.
    fn shape(tree: &ClauseTree) -> String {
        match tree {
            ClauseTree::Leaf(clause) => clause.name().to_string(),
            ClauseTree::Branch(left, right) => format!("({} {})", shape(left), shape(right)),
        }
    }

    #[test]
    fn any_binary_tree_is_expressible() {
        // The two grammar productions: a leaf, and a branch of two subtrees.
        assert_eq!(shape(&clause_tree![clause("a")]), "a");
        assert_eq!(shape(&clause_tree![clause("a"), clause("b")]), "(a b)");

        // A branch may sit on either side of a level.
        assert_eq!(
            shape(&clause_tree![clause("a"), [clause("b"), clause("c")]]),
            "(a (b c))"
        );
        assert_eq!(
            shape(&clause_tree![[clause("a"), clause("b")], clause("c")]),
            "((a b) c)"
        );

        // A bracketed pair as the sole remainder of a level used to fall
        // through to an array-literal arm; the balanced tree is the smallest
        // such case.
        assert_eq!(
            shape(&clause_tree![
                [clause("a"), clause("b")],
                [clause("c"), clause("d")]
            ]),
            "((a b) (c d))"
        );
        assert_eq!(
            shape(&clause_tree![
                [clause("a"), [clause("b"), clause("c")]],
                [clause("d"), clause("e")]
            ]),
            "((a (b c)) (d e))"
        );

        // A group may also wrap the whole tree.
        assert_eq!(shape(&clause_tree![[clause("a"), clause("b")]]), "(a b)");
    }

    // The same shapes through `contract!`'s static `tree [..];` section, whose
    // tokens are handed to `clause_tree!` verbatim. The two contracts share
    // the same four leaf scripts and differ only in tree shape, so shape alone
    // decides whether the taproot roots match.

    #[derive(Debug, Clone, ContractParams)]
    pub struct TreeParams {
        pub tag: i64,
    }

    contract! {
        contract BalancedTree {
            params TreeParams;
            clause a { args { x: i64, } script |_p| ScriptBuf::from(vec![0x51u8]); }
            clause b { args { x: i64, } script |_p| ScriptBuf::from(vec![0x52u8]); }
            clause c { args { x: i64, } script |_p| ScriptBuf::from(vec![0x53u8]); }
            clause d { args { x: i64, } script |_p| ScriptBuf::from(vec![0x54u8]); }
            tree [[a, b], [c, d]];
        }
    }

    contract! {
        contract FoldedTree {
            params TreeParams;
            clause a { args { x: i64, } script |_p| ScriptBuf::from(vec![0x51u8]); }
            clause b { args { x: i64, } script |_p| ScriptBuf::from(vec![0x52u8]); }
            clause c { args { x: i64, } script |_p| ScriptBuf::from(vec![0x53u8]); }
            clause d { args { x: i64, } script |_p| ScriptBuf::from(vec![0x54u8]); }
            tree [a, [b, [c, d]]];
        }
    }

    #[test]
    fn contract_taptrees_follow_the_written_shape() {
        let balanced = BalancedTree::new(TreeParams { tag: 0 });
        let folded = FoldedTree::new(TreeParams { tag: 0 });
        assert_ne!(balanced.taptree_root(), folded.taptree_root());
    }
}
