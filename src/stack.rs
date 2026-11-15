//! A symbolic stack tracker for assembling tapscripts.
//!
//! MATT tapscripts juggle many witness elements (state leaves, Merkle proofs,
//! carried context), and hand-counting `OP_PICK`/`OP_ROLL` depths across them
//! is error-prone. A [`StackScript`] is written against *named* stack items
//! instead: the tracker knows where every element lives and emits the right
//! depth constants, panicking at script-build time on any stack-discipline
//! mistake. Start it from the clause's own [`ArgSpec`] list
//! ([`StackScript::from_specs`]) so the witness layout and the tracked names
//! have a single source of truth.
//!
//! Items are only ever *copied* up with `pick` (consumed copies excepted), and
//! whatever is left is dropped by [`StackScript::into_script`] — a couple of
//! extra opcodes in exchange for scripts that read as a sequence of
//! intentions. See `examples/aggregate_exits/contracts/` for contracts written
//! entirely this way.
//!
//! Relative timelocks are deliberately not offered here: declare them with the
//! `contract!` DSL's `timelock` section, which prepends the
//! [`older`](crate::script::older) fragment *and* seeds the spend's
//! `nSequence`, so the script and the transaction cannot disagree.

use crate::ccv::{CcvData, CcvIndex, CcvKey, CcvMode, CcvTaptree};
use crate::contracts::ArgSpec;
use crate::script;
use crate::script::{concat, drop as script_drop, merkle_root};
use bitcoin::ScriptBuf;

/// Untyped operand for [`StackScript::ccv_raw`]. Prefer the slot-specific types
/// in [`crate::ccv`] with [`StackScript::ccv`].
#[derive(Debug, Clone, Copy)]
pub enum RawCcvSource<'a> {
    /// A tracked stack item, copied to the top.
    Item(&'a str),
    /// A 32-byte constant pushed by the script.
    Const([u8; 32]),
    /// Arbitrary pushed bytes; no CCV argument validation is performed.
    Bytes(&'a bitcoin::script::PushBytes),
    /// "None" (`0`): no data / NUMS key / no taptree, depending on the slot.
    None,
    /// "Same as the current input" (`-1`): key or taptree slots only.
    Current,
}

/// A script under construction, tracking the names of the elements on the
/// main stack (bottom → top) and the altstack.
pub struct StackScript {
    stack: Vec<String>,
    alt: Vec<String>,
    parts: Vec<ScriptBuf>,
}

impl StackScript {
    /// Start from the witness stack: `names` bottom → top (i.e. in the order
    /// the elements appear in the clause's `ArgSpec` list).
    pub fn with_witness(names: &[&str]) -> Self {
        Self {
            stack: names.iter().map(|s| s.to_string()).collect(),
            alt: Vec::new(),
            parts: Vec::new(),
        }
    }

    /// Start from a clause's own `ArgSpec` list, so the witness layout and the
    /// tracked names have a single source of truth.
    pub fn from_specs(specs: &[ArgSpec]) -> Self {
        let mut stack = Vec::new();
        for spec in specs {
            let count = spec.arg_type.witness_elements().unwrap_or_else(|| {
                panic!(
                    "argument `{}` has a value-dependent witness layout",
                    spec.name
                )
            });
            assert!(
                count > 0,
                "argument `{}` has an empty witness layout",
                spec.name
            );
            for slot in 0..count {
                if slot + 1 == count {
                    stack.push(spec.name.clone());
                } else {
                    stack.push(format!("<{}:{}>", spec.name, slot));
                }
            }
        }
        Self {
            stack,
            alt: Vec::new(),
            parts: Vec::new(),
        }
    }

    fn depth(&self, name: &str) -> usize {
        let pos = self
            .stack
            .iter()
            .rposition(|n| n == name)
            .unwrap_or_else(|| panic!("stack item `{name}` not found (stack: {:?})", self.stack));
        self.stack.len() - 1 - pos
    }

    /// Copy `name` (its topmost occurrence) to the top of the stack.
    pub fn pick(&mut self, name: &str) {
        let depth = self.depth(name);
        self.parts.push(match depth {
            0 => script! { OP_DUP },
            1 => script! { OP_OVER },
            d => script! {
                { i64::try_from(d).expect("stack depth exceeds script-number range") }
                OP_PICK
            },
        });
        self.stack.push(name.to_string());
    }

    /// Move `name` (its topmost occurrence) to the top of the stack.
    pub fn roll(&mut self, name: &str) {
        let depth = self.depth(name);
        match depth {
            0 => {}
            1 => self.parts.push(script! { OP_SWAP }),
            2 => self.parts.push(script! { OP_ROT }),
            d => self.parts.push(script! {
                { i64::try_from(d).expect("stack depth exceeds script-number range") }
                OP_ROLL
            }),
        }
        let pos = self.stack.len() - 1 - depth;
        let item = self.stack.remove(pos);
        self.stack.push(item);
    }

    /// Push a 32-byte constant, tracked as `name`.
    pub fn push_const(&mut self, name: &str, value: [u8; 32]) {
        self.parts.push(script! { { value.to_vec() } });
        self.stack.push(name.to_string());
    }

    /// Push a script-number constant, tracked as `name`.
    pub fn push_num(&mut self, name: &str, value: i64) {
        self.parts.push(script! { { value } });
        self.stack.push(name.to_string());
    }

    /// Move the top element to the altstack.
    pub fn to_alt(&mut self) {
        self.parts.push(script! { OP_TOALTSTACK });
        let item = self.stack.pop().expect("to_alt on empty stack");
        self.alt.push(item);
    }

    /// Move the top altstack element back to the stack.
    pub fn from_alt(&mut self) {
        self.parts.push(script! { OP_FROMALTSTACK });
        let item = self.alt.pop().expect("from_alt on empty altstack");
        self.stack.push(item);
    }

    /// Append a raw fragment that pops `pops` elements and pushes the elements
    /// named in `pushes` (bottom → top). The fragment must not touch anything
    /// deeper and must leave the altstack as it found it.
    pub fn raw(&mut self, fragment: ScriptBuf, pops: usize, pushes: &[&str]) {
        self.parts.push(fragment);
        for _ in 0..pops {
            self.stack
                .pop()
                .expect("raw fragment pops past stack bottom");
        }
        for name in pushes {
            self.stack.push(name.to_string());
        }
    }

    /// Rename the top element (e.g. after a raw fragment transformed it).
    pub fn rename_top(&mut self, name: &str) {
        *self.stack.last_mut().expect("rename on empty stack") = name.to_string();
    }

    /// `OP_SHA256` the top element, renaming it.
    pub fn sha256_top(&mut self, name: &str) {
        self.parts.push(script! { OP_SHA256 });
        self.rename_top(name);
    }

    /// Copy `items` to the top (in order) and hash their concatenation:
    /// `name = sha256(items[0] || items[1] || ...)`.
    pub fn sha_cat(&mut self, items: &[&str], name: &str) {
        assert!(!items.is_empty());
        self.pick(items[0]);
        // The running concatenation is not `items[0]` any more: under that
        // name, a later pick of the same item would copy the concatenation
        // instead of the item. Its temporary name must not be one a pick
        // could ask for, so it is one that neither the stack nor `items` use.
        let mut cat = String::from("<cat>");
        while self.stack.contains(&cat) || items.contains(&cat.as_str()) {
            cat.push('\'');
        }
        self.rename_top(&cat);
        for item in &items[1..] {
            self.pick(item);
            self.parts.push(script! { OP_CAT });
            self.stack.pop();
        }
        self.sha256_top(name);
    }

    /// Copy `leaves` to the top (leaf 0 first) and reduce them to their Merkle
    /// root, tracked as `name`. The counterpart of committing a
    /// `#[commit(merkle)]` state whose fields are `leaves` in order.
    pub fn merkle_of(&mut self, leaves: &[&str], name: &str) {
        for leaf in leaves {
            self.pick(leaf);
        }
        self.merkle_top(leaves.len(), name);
    }

    /// Reduce the top `n` elements (already in leaf order, deepest = leaf 0)
    /// to their Merkle root, tracked as `name`.
    pub fn merkle_top(&mut self, n: usize, name: &str) {
        assert!(n > 0, "cannot reduce an empty Merkle tree on the stack");
        self.parts.push(merkle_root(n));
        for _ in 0..n {
            self.stack.pop().expect("merkle_top past stack bottom");
        }
        self.stack.push(name.to_string());
    }

    /// Pop the top two elements and `OP_EQUALVERIFY` them.
    pub fn equal_verify(&mut self) {
        self.parts.push(script! { OP_EQUALVERIFY });
        self.stack.pop().expect("equal_verify on empty stack");
        self.stack.pop().expect("equal_verify on empty stack");
    }

    /// Copy two items to the top and `OP_EQUALVERIFY` them.
    pub fn expect_equal(&mut self, a: &str, b: &str) {
        self.pick(a);
        self.pick(b);
        self.equal_verify();
    }

    fn push_source(&mut self, source: RawCcvSource<'_>) {
        match source {
            RawCcvSource::Item(name) => self.pick(name),
            RawCcvSource::Const(value) => self.push_const("<const>", value),
            RawCcvSource::Bytes(value) => {
                self.parts.push(
                    bitcoin::script::Builder::new()
                        .push_slice(value)
                        .into_script(),
                );
                self.stack.push("<bytes>".into());
            }
            RawCcvSource::None => self.push_num("<none>", 0),
            RawCcvSource::Current => self.push_num("<current>", -1),
        }
    }

    /// Emit a full `OP_CHECKCONTRACTVERIFY`: `<data> <index> <pk> <taptree>
    /// <mode>`. Slot-specific arguments prevent mixing up sentinel meanings,
    /// and the mode cannot be an undefined value. Named stack items are copied,
    /// not consumed; their values still need to be constrained by the script.
    /// This method does not generate host-side `next` metadata.
    ///
    /// ```
    /// use mattrs::ccv::{CcvData, CcvIndex, CcvKey, CcvMode, CcvTaptree};
    /// use mattrs::stack::StackScript;
    /// let mut script = StackScript::with_witness(&["state"]);
    /// script.ccv(CcvData::Item("state"), CcvIndex::CURRENT,
    ///     CcvKey::Nums, CcvTaptree::Current, CcvMode::CheckInput);
    /// let script = script.into_script();
    /// ```
    ///
    /// Modes are not raw integers or combinable flags:
    /// ```compile_fail
    /// use mattrs::ccv::{CcvData, CcvIndex, CcvKey, CcvTaptree};
    /// use mattrs::stack::StackScript;
    /// StackScript::with_witness(&[]).ccv(CcvData::Empty, CcvIndex::CURRENT,
    ///     CcvKey::Nums, CcvTaptree::None, 3);
    /// ```
    /// Key/taptree sentinels cannot be supplied in the data slot:
    /// ```compile_fail
    /// use mattrs::ccv::{CcvIndex, CcvKey, CcvMode, CcvTaptree};
    /// use mattrs::stack::StackScript;
    /// StackScript::with_witness(&[]).ccv(CcvKey::CurrentInternalKey, CcvIndex::CURRENT,
    ///     CcvKey::Nums, CcvTaptree::None, CcvMode::Preserve);
    /// ```
    pub fn ccv(
        &mut self,
        data: CcvData<'_>,
        index: impl Into<CcvIndex>,
        pk: CcvKey<'_>,
        taptree: CcvTaptree<'_>,
        mode: CcvMode,
    ) {
        let data = match data {
            CcvData::Item(name) => RawCcvSource::Item(name),
            CcvData::Const(value) => RawCcvSource::Const(value),
            CcvData::Bytes(value) => RawCcvSource::Bytes(value),
            CcvData::Empty => RawCcvSource::None,
        };
        let pk = match pk {
            CcvKey::Item(name) => RawCcvSource::Item(name),
            CcvKey::Const(value) => RawCcvSource::Const(value.serialize()),
            CcvKey::Nums => RawCcvSource::None,
            CcvKey::CurrentInternalKey => RawCcvSource::Current,
        };
        let taptree = match taptree {
            CcvTaptree::Item(name) => RawCcvSource::Item(name),
            CcvTaptree::Const(value) => RawCcvSource::Const(value),
            CcvTaptree::None => RawCcvSource::None,
            CcvTaptree::Current => RawCcvSource::Current,
        };
        self.ccv_raw(data, index.into().as_i64(), pk, taptree, mode.as_i32());
    }

    /// Emit CCV with unchecked operands, for low-level script experiments.
    ///
    /// **Warning:** undefined modes immediately succeed validation for the
    /// current input; they do not merely disable amount checks. No index,
    /// key, data, or taptree validation is performed here. Prefer [`Self::ccv`].
    /// `RawCcvSource::Current` emits `-1` even in the data slot, where it is
    /// ordinary data rather than a sentinel. Stack tracking assumes the usual
    /// five-operand consumption; undefined modes actually terminate execution.
    pub fn ccv_raw(
        &mut self,
        data: RawCcvSource<'_>,
        index: i64,
        pk: RawCcvSource<'_>,
        taptree: RawCcvSource<'_>,
        mode: i32,
    ) {
        self.push_source(data);
        self.push_num("<index>", index);
        self.push_source(pk);
        self.push_source(taptree);
        self.push_num("<mode>", mode as i64);
        self.parts.push(script! { CHECKCONTRACTVERIFY });
        for _ in 0..5 {
            self.stack.pop();
        }
    }

    /// Finish the script: drop everything still tracked on the stack and leave
    /// a single `OP_TRUE`. Panics if the altstack is not empty (a tracker-use
    /// bug: altstack leftovers would make the script fail on-chain).
    pub fn into_script(mut self) -> ScriptBuf {
        assert!(
            self.alt.is_empty(),
            "altstack not empty at end of script: {:?}",
            self.alt
        );
        if !self.stack.is_empty() {
            self.parts.push(script_drop(self.stack.len()));
        }
        self.parts.push(script! { OP_TRUE });
        concat(&self.parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argtypes::BytesType;
    use crate::merkle::MerkleProofType;
    use std::sync::Arc;

    #[test]
    fn from_specs_accounts_for_multi_element_arguments() {
        let specs = vec![
            ArgSpec {
                name: "prefix".to_string(),
                arg_type: Arc::new(BytesType),
            },
            ArgSpec {
                name: "proof".to_string(),
                arg_type: Arc::new(MerkleProofType::new(1)),
            },
            ArgSpec {
                name: "suffix".to_string(),
                arg_type: Arc::new(BytesType),
            },
        ];

        assert_eq!(specs[1].arg_type.witness_elements(), Some(3));
        let stack = StackScript::from_specs(&specs);
        assert_eq!(stack.depth("prefix"), 4);
        assert_eq!(stack.depth("proof"), 1);
        assert_eq!(stack.depth("suffix"), 0);
    }

    #[test]
    fn sha_cat_picks_a_repeated_item_not_the_running_concatenation() {
        // sha256(a || b || a): the second `a` is the witness element, two
        // below the concatenation `a || b`.
        let mut s = StackScript::with_witness(&["a", "b"]);
        s.sha_cat(&["a", "b", "a"], "h");
        assert_eq!(s.stack, ["a", "b", "h"]);
        assert_eq!(
            s.into_script(),
            script! {
                OP_OVER OP_OVER OP_CAT
                2 OP_PICK OP_CAT
                OP_SHA256
                OP_2DROP OP_DROP OP_TRUE
            }
        );
    }

    #[test]
    fn sha_cat_does_not_shadow_an_item_named_like_its_temporary() {
        // sha256(a || <cat>): `<cat>` is the witness element on top, not the
        // copy of `a` that starts the concatenation.
        let mut s = StackScript::with_witness(&["a", "<cat>"]);
        s.sha_cat(&["a", "<cat>"], "h");
        assert_eq!(s.stack, ["a", "<cat>", "h"]);
        assert_eq!(
            s.into_script(),
            script! {
                OP_OVER OP_OVER OP_CAT
                OP_SHA256
                OP_2DROP OP_DROP OP_TRUE
            }
        );
    }

    #[test]
    #[should_panic(expected = "cannot reduce an empty Merkle tree")]
    fn merkle_top_rejects_an_empty_tree() {
        StackScript::with_witness(&[]).merkle_top(0, "root");
    }

    #[test]
    fn typed_ccv_preserves_raw_script_bytes_and_stack_tracking() {
        use RawCcvSource as Raw;
        let bytes = <&bitcoin::script::PushBytes>::from(&[0x61, 0x62, 0x63]);
        let data = [
            (CcvData::Empty, Raw::None),
            (CcvData::Item("data"), Raw::Item("data")),
            (CcvData::Const([0x42; 32]), Raw::Const([0x42; 32])),
            (CcvData::Bytes(bytes), Raw::Bytes(bytes)),
        ];
        let keys = [
            (CcvKey::Nums, Raw::None),
            (CcvKey::CurrentInternalKey, Raw::Current),
            (CcvKey::Item("key"), Raw::Item("key")),
            (
                CcvKey::Const(crate::nums_key()),
                Raw::Const(crate::NUMS_KEY),
            ),
        ];
        let trees = [
            (CcvTaptree::None, Raw::None),
            (CcvTaptree::Current, Raw::Current),
            (CcvTaptree::Item("tree"), Raw::Item("tree")),
            (CcvTaptree::Const([0x24; 32]), Raw::Const([0x24; 32])),
        ];
        for (data, raw_data) in data {
            for (key, raw_key) in keys {
                for (tree, raw_tree) in trees {
                    for number in [-1, 0, 128, i64::from(i32::MAX)] {
                        for mode in [
                            CcvMode::CheckInput,
                            CcvMode::Preserve,
                            CcvMode::IgnoreAmount,
                            CcvMode::DeductAmount,
                        ] {
                            let mut typed = StackScript::with_witness(&["data", "key", "tree"]);
                            let mut raw = StackScript::with_witness(&["data", "key", "tree"]);
                            typed.ccv(data, CcvIndex::try_from(number).unwrap(), key, tree, mode);
                            raw.ccv_raw(raw_data, number, raw_key, raw_tree, mode.as_i32());
                            assert_eq!(typed.stack, ["data", "key", "tree"]);
                            // A subsequent named operation must see the original depths.
                            typed.pick("data");
                            raw.pick("data");
                            assert_eq!(typed.into_script(), raw.into_script());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn typed_ccv_encodes_all_modes_and_sentinels_minimally() {
        for mode in [
            CcvMode::CheckInput,
            CcvMode::Preserve,
            CcvMode::IgnoreAmount,
            CcvMode::DeductAmount,
        ] {
            let mut s = StackScript::with_witness(&[]);
            s.ccv(
                CcvData::Empty,
                CcvIndex::CURRENT,
                CcvKey::Nums,
                CcvTaptree::Current,
                mode,
            );
            assert_eq!(
                s.into_script(),
                script! {
                    OP_0 -1 OP_0 -1 { mode.as_i32() }
                    CHECKCONTRACTVERIFY OP_TRUE
                }
            );
        }
    }

    #[test]
    fn data_bytes_and_key_sentinel_are_emitted_verbatim() {
        let bytes = <&bitcoin::script::PushBytes>::from(&[0x61, 0x62, 0x63]);
        let mut s = StackScript::with_witness(&[]);
        s.ccv(
            CcvData::Bytes(bytes),
            CcvIndex::at(1).unwrap(),
            CcvKey::CurrentInternalKey,
            CcvTaptree::None,
            CcvMode::Preserve,
        );
        assert_eq!(
            s.into_script().as_bytes(),
            &[
                3, 0x61, 0x62, 0x63, // data, without hashing
                0x51, 0x4f, 0, 0, // index 1, current internal key, no tree, preserve
                0xbb, 0x51, // CCV, true
            ]
        );
    }

    #[test]
    fn raw_ccv_explicitly_allows_undefined_modes_and_indices() {
        let mut s = StackScript::with_witness(&[]);
        s.ccv_raw(
            RawCcvSource::Current,
            -2,
            RawCcvSource::None,
            RawCcvSource::None,
            3,
        );
        assert_eq!(
            s.into_script(),
            script! {
                -1 -2 OP_0 OP_0 OP_3 CHECKCONTRACTVERIFY OP_TRUE
            }
        );
    }
}
