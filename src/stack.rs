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

use crate::contracts::ArgSpec;
use crate::script_helpers::{concat, drop as script_drop, merkle_root};
use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};

define_pushable!();

/// How a CCV argument is sourced.
pub enum Source<'a> {
    /// A tracked stack item, copied to the top.
    Item(&'a str),
    /// A 32-byte constant pushed by the script.
    Const([u8; 32]),
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
        Self {
            stack: specs.iter().map(|a| a.name.clone()).collect(),
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
            d => script! { { d as i64 } OP_PICK },
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
            d => self.parts.push(script! { { d as i64 } OP_ROLL }),
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
            self.stack.pop().expect("raw fragment pops past stack bottom");
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

    fn push_source(&mut self, source: Source<'_>) {
        match source {
            Source::Item(name) => self.pick(name),
            Source::Const(value) => self.push_const("<const>", value),
            Source::None => self.push_num("<none>", 0),
            Source::Current => self.push_num("<current>", -1),
        }
    }

    /// Emit a full `OP_CHECKCONTRACTVERIFY`: `<data> <index> <pk> <taptree>
    /// <flags>`, each argument sourced independently. `index` and `flags` are
    /// numeric (`-1` index = same as this input).
    pub fn ccv(&mut self, data: Source<'_>, index: i64, pk: Source<'_>, taptree: Source<'_>, flags: i32) {
        self.push_source(data);
        self.push_num("<index>", index);
        self.push_source(pk);
        self.push_source(taptree);
        self.push_num("<flags>", flags as i64);
        self.parts.push(script! { CHECKCONTRACTVERIFY });
        for _ in 0..5 {
            self.stack.pop();
        }
    }

    /// A relative timelock: `<blocks> CSV DROP`.
    pub fn older(&mut self, blocks: u32) {
        self.parts.push(crate::script_helpers::older(blocks));
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
