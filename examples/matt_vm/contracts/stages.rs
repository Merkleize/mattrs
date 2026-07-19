//! The MATT-VM game stages: Alice claims what a program computed, Bob can
//! dispute it through the generic bisection.
//!
//! ```text
//! VmS0 --claim--> VmS1[t_a, y, pc_a, m_a] --challenge--> Bisect1(0, n-1) -> ...
//!                        \--withdraw (after the timeout)
//! ```
//!
//! The computation itself (program, initial memory, step count) is a *public
//! parameter* carried in the contracts' ctx: both parties know the spec, so —
//! unlike game256, where Bob first picks an input on-chain — the game opens
//! directly with Alice's claim.
//!
//! A claim is the final machine state, revealed by parts: the result `y`
//! (the accumulator), the final `pc`, and the final memory root — plus
//! Alice's trace commitment `t_a`. Revealing the parts (rather than an opaque
//! state hash) is what binds the on-chain wager to the claimed *result*: the
//! challenge clause recomputes `h_end = merkle_root([sha256(pc), sha256(y),
//! m])` for both parties' claims from the revealed components, requires them
//! to differ, and hands `[h_start, h_end_a, h_end_b, t_a, t_b]` to the
//! bisection. `h_start` is a script constant: the initial state `(pc=0,
//! acc=0, mem0)` is public.

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};

use mattrs::contracts::ClauseOutput;
use mattrs::fraud::{Bisect1, BisectCtx, BisectParams, Leaf, LeafFactory, LeafParams};
use mattrs::script_helpers::{
    check_input_contract, check_output_contract, dup, merkle_root, timeout_sig_script,
};
use mattrs::{ContractParams, ContractState, Signature, contract};

use super::computer::vm_computer;
use super::vm::{VmSpec, state_commit};

define_pushable!();

/// The challenge/forfait timeout (blocks), as in game256.
pub const FORFAIT_TIMEOUT: u32 = 10;

#[derive(Debug, Clone, ContractParams)]
pub struct VmParams {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
}

/// The non-encodable construction context: the computation being wagered on.
#[derive(Clone)]
pub struct VmCtx {
    pub spec: VmSpec,
    pub forfait_timeout: u32,
}

impl VmCtx {
    pub fn new(spec: VmSpec) -> Self {
        Self {
            spec,
            forfait_timeout: FORFAIT_TIMEOUT,
        }
    }

    /// The per-step [`Leaf`]: every step re-runs the same [`vm_computer`], so
    /// the step index is ignored.
    fn leaf_factory(&self, p: &VmParams) -> LeafFactory {
        let computer = vm_computer(&self.spec);
        let (alice_pk, bob_pk) = (p.alice_pk, p.bob_pk);
        std::sync::Arc::new(move |_step| {
            Leaf::new(LeafParams { alice_pk, bob_pk }, computer.clone())
                .expect("the VM Leaf contract definition is valid")
        })
    }

    fn bisect_ctx(&self, p: &VmParams) -> BisectCtx {
        BisectCtx::new(self.leaf_factory(p), self.forfait_timeout)
            .expect("the VM forfait timeout is non-zero")
    }

    /// The dispute's entry [`Bisect1`], over the full step range.
    pub fn bisect1(&self, p: &VmParams) -> Bisect1 {
        let params = BisectParams::new(p.alice_pk, p.bob_pk, 0, self.spec.n_steps() as i64 - 1)
            .expect("a VM spec's step count is a power of two >= 2");
        Bisect1::new(params, self.bisect_ctx(p)).expect("Bisect1 contract definition is valid")
    }
}

/// VmS1 state: Alice's claim `{t_a, y, pc_a, m_a}`, committed as
/// `merkle_root([t_a, sha256(y), sha256(pc_a), m_a])`.
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]
pub struct VmS1State {
    /// Alice's trace commitment over the whole computation.
    pub t_a: [u8; 32],
    /// The claimed result (the final accumulator).
    #[leaf(sha256)]
    pub y: i64,
    /// The claimed final program counter.
    #[leaf(sha256)]
    pub pc_a: i64,
    /// The claimed final memory root.
    pub m_a: [u8; 32],
}

/// The on-chain [`VmS1State`] encoder: `[t_a, y, pc_a, m_a]` (top: `m_a`) to
/// the state commitment.
fn s1_state_encoder() -> ScriptBuf {
    script! {
        OP_TOALTSTACK               // [t_a, y, pc_a]            alt: [.., m_a]
        OP_SHA256                   // [t_a, y, H(pc_a)]
        OP_SWAP OP_SHA256 OP_SWAP   // [t_a, H(y), H(pc_a)]
        OP_FROMALTSTACK             // [t_a, H(y), H(pc_a), m_a]
        { merkle_root(4) }
    }
}

contract! {
    /// The opening stage: Alice posts her claim, moving the pot to [`VmS1`].
    contract VmS0 {
        params VmParams;
        ctx VmCtx;

        // <alice_sig> <t_a> <y> <pc_a> <m_a>
        clause claim {
            args {
                #[signer(p.alice_pk)]
                alice_sig: Signature,
                t_a: [u8; 32],
                y: i64,
                pc_a: i64,
                m_a: [u8; 32],
            }
            script |p, c| VmS0::claim_script(p, c);
            next(p, a) {
                Ok(vec![ClauseOutput::at_same_index()
                    .to(VmS1::new(p.clone(), ctx.clone())?.as_erased())
                    .with_state(&VmS1State {
                        t_a: a.t_a,
                        y: a.y,
                        pc_a: a.pc_a,
                        m_a: a.m_a,
                    })
                    .preserve_amount()
                    .build()])
            }
        }

        tree [claim];
    }
}

impl VmS0 {
    fn claim_script(p: &VmParams, c: &VmCtx) -> ScriptBuf {
        let s1_root = VmS1::new(p.clone(), c.clone())
            .expect("VmS1 contract definition is valid")
            .taptree_root();
        script! {
            { s1_state_encoder() }
            { check_output_contract(s1_root, -1, None) }
            { p.alice_pk }
            OP_CHECKSIG
        }
    }
}

contract! {
    /// Alice's posted claim: she withdraws after the timeout, unless Bob
    /// posts a conflicting claim and the pot moves into the bisection.
    contract VmS1 {
        params VmParams;
        ctx VmCtx;
        state VmS1State;

        clause withdraw {
            args {
                #[signer(p.alice_pk)]
                alice_sig: Signature,
            }
            script |p, c| timeout_sig_script(c.forfait_timeout, p.alice_pk);
        }

        // <bob_sig> <t_a> <y> <pc_a> <m_a> <z> <pc_b> <m_b> <t_b>
        clause challenge {
            args {
                #[signer(p.bob_pk)]
                bob_sig: Signature,
                #[from_state] t_a: [u8; 32],
                #[from_state] y: i64,
                #[from_state] pc_a: i64,
                #[from_state] m_a: [u8; 32],
                z: i64,
                pc_b: i64,
                m_b: [u8; 32],
                t_b: [u8; 32],
            }
            script |p, c| VmS1::challenge_script(p, c);
            next(p, a) {
                Ok(vec![ctx.bisect1(p).entry_output(
                    ctx.spec.h_start(),
                    state_commit(a.pc_a, a.y, &a.m_a),
                    state_commit(a.pc_b, a.z, &a.m_b),
                    a.t_a,
                    a.t_b,
                )])
            }
        }

        tree [withdraw, challenge];
    }
}

impl VmS1 {
    fn challenge_script(p: &VmParams, c: &VmCtx) -> ScriptBuf {
        let h_start = c.spec.h_start();
        script! {
            // [t_a, y, pc_a, m_a, z, pc_b, m_b, t_b]
            OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
            //                                          alt: [t_b, m_b, pc_b, z]
            { dup(4) }
            { s1_state_encoder() }
            { check_input_contract(-1, None) }
            // [t_a, y, pc_a, m_a] — Alice's claim, as committed
            { s1_end_commit() }         // [t_a, h_end_a]            alt: [t_b, m_b, pc_b, z]
            OP_FROMALTSTACK             // z
            OP_FROMALTSTACK             // pc_b
            { s1_end_commit_tail() }    // [t_a, h_end_a, h_end_b]   alt: [t_b]
            // the two claimed end states must differ
            OP_2DUP OP_EQUAL OP_NOT OP_VERIFY
            // assemble the bisection entry [h_start, h_end_a, h_end_b, t_a, t_b]
            OP_ROT                      // [h_end_a, h_end_b, t_a]
            OP_FROMALTSTACK             // [h_end_a, h_end_b, t_a, t_b]
            { h_start }
            4 OP_ROLL 4 OP_ROLL 4 OP_ROLL 4 OP_ROLL
            { c.bisect1(p).state_output_script(-1) }
            { p.bob_pk }
            OP_CHECKSIG
        }
    }
}

/// `[.., acc, pc, m]` (top: `m`) to `[.., h_end]`: stash the memory root and
/// defer to [`s1_end_commit_tail`].
fn s1_end_commit() -> ScriptBuf {
    script! {
        // [t_a, y, pc_a, m_a]
        OP_TOALTSTACK               // [t_a, y, pc_a]            alt: [.., m_a]
        { s1_end_commit_tail() }
    }
}

/// `[.., acc, pc]` (top: `pc`, memory root on the altstack) to `[.., h_end]`:
/// `merkle_root([sha256(pc), sha256(acc), m])` — the step-state commitment.
fn s1_end_commit_tail() -> ScriptBuf {
    script! {
        OP_SHA256                   // [.., acc, H(pc)]
        OP_SWAP OP_SHA256           // [.., H(pc), H(acc)]
        OP_FROMALTSTACK             // [.., H(pc), H(acc), m]
        { merkle_root(3) }
    }
}
