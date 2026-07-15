//! The [`Unwind`] pool: direct withdrawals and the entry into a delegated exit.

use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};
use mattrs::ContractState;
use mattrs::contract;
use mattrs::contracts::{
    ArgSpec, CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, ClauseError, ClauseOutput,
    WitnessReader,
};
use mattrs::manager::SpendBuilder;
use mattrs::merkle::{MerkleProof, NIL};
use mattrs::script_utils::bn2vch;

use super::pending_exit::{PendingExit, PendingExitState};
use super::{ExitClaim, PoolParams, PoolTree, bit_root, spec, spec_num};
use mattrs::stack::{Source, StackScript};

define_pushable!();

/// The pool's committed state: the account-tree root (identity commitment).
#[derive(Debug, Clone, PartialEq, Eq, ContractState)]
pub struct UnwindState {
    pub root: [u8; 32],
}

contract! {
    /// The pool in its unwind phase: the only actions are taking money out.
    ///
    /// - `withdraw_direct`: pay one account its balance and zero its leaf
    ///   (output 0 the payout, output 1 the continued pool).
    /// - `start_exit`: Ingrid posts an aggregate-exit claim (the exit-set
    ///   bits, published on-chain and bound to their commitment in-script)
    ///   plus her bond, moving the pool to [`PendingExit`]. Permissionless:
    ///   a false claim is what the challenge clauses are for.
    contract Unwind {
        params PoolParams;
        state UnwindState;

        // witness: <pk> <bal> (<h_l> <d_l>) x depth <root>
        clause withdraw_direct {
            args raw |p| Unwind::withdraw_direct_specs(p);
            script Unwind::withdraw_direct_script;
            next(p, a) {
                Unwind::withdraw_direct_outputs(p, &a.0)
            }
        }

        // witness: <unwind_taptree> <root> <r_prime> <bit_u> x N <ingrid_pk> <trace_i> <x>
        clause start_exit {
            args raw |p| Unwind::start_exit_specs(p);
            script Unwind::start_exit_script;
            next(p, a) {
                Unwind::start_exit_outputs(p, &a.0)
            }
        }

        tree [withdraw_direct, start_exit];
    }
}

/// One level of the leaf→root walk recomputing the *old* and *new* roots at
/// once (the RAM `write` pattern). Expects `<old> <new> <sibling> <direction>`
/// on top; leaves `<old'> <new'>`. `direction = 1` means the current nodes are
/// right children.
///
/// This is the shared-direction dual walk with the one sibling duplicated:
/// `<old> <new> <sib> <d>` becomes `<old> <new> <sib> <sib> <d>`.
fn dual_update_layer() -> ScriptBuf {
    mattrs::script_helpers::concat(&[script! { OP_SWAP OP_DUP OP_ROT }, super::dual_proof_layer()])
}

impl Unwind {
    fn withdraw_direct_specs(p: &PoolParams) -> Vec<ArgSpec> {
        let mut specs = vec![spec("pk"), spec_num("bal")];
        for l in 0..p.depth() {
            specs.push(spec(&format!("h_{l}")));
            specs.push(spec_num(&format!("d_{l}")));
        }
        specs.push(spec("root"));
        specs
    }

    fn withdraw_direct_script(p: &PoolParams) -> ScriptBuf {
        let depth = p.depth();
        let mut s = StackScript::from_specs(&Self::withdraw_direct_specs(p));

        // The claimed root is the input's committed state.
        s.ccv(
            Source::Item("root"),
            -1,
            Source::None,
            Source::Current,
            CCV_FLAG_CHECK_INPUT,
        );

        // Output 0 pays the revealed account key.
        // TODO(OP_AMOUNT): enforce that output 0 carries exactly `bal` sats.
        // Until then a malicious spender could zero the leaf while paying the
        // account less than its balance, which is why withdrawals stay
        // honest-executor-only in the demo.
        s.ccv(
            Source::None,
            0,
            Source::Item("pk"),
            Source::None,
            CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
        );

        // Walk leaf→root recomputing the current root (proving membership) and
        // the root with the leaf zeroed, in lockstep.
        s.sha_cat(&["pk", "bal"], "old_node");
        s.push_const("new_node", NIL);
        for l in (0..depth).rev() {
            s.roll(&format!("h_{l}"));
            s.roll(&format!("d_{l}"));
            s.raw(dual_update_layer(), 4, &["old_node", "new_node"]);
        }
        s.expect_equal("old_node", "root");

        // Output 1 continues the pool committing to the zeroed root.
        s.ccv(
            Source::Item("new_node"),
            1,
            Source::None,
            Source::Current,
            0,
        );
        s.into_script()
    }

    fn withdraw_direct_outputs(
        p: &PoolParams,
        witness: &[Vec<u8>],
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let depth = p.depth();
        let mut w = WitnessReader::new(witness);
        let pk = w.xonly()?;
        let bal = w.num()?;
        let mut hashes = Vec::with_capacity(depth);
        let mut directions = Vec::with_capacity(depth);
        for _ in 0..depth {
            hashes.push(w.bytes32()?);
            directions.push(w.num()? as u8);
        }
        let root = w.bytes32()?;
        w.expect_end()?;

        let proof = MerkleProof {
            hashes,
            directions,
            x: super::balance_leaf(&pk, bal),
        };
        if proof.get_new_root_after_update(proof.x) != root {
            return Err(ClauseError::Other(
                "withdraw_direct: invalid membership proof".to_string(),
            ));
        }
        let new_root = proof.get_new_root_after_update(NIL);

        Ok(vec![
            ClauseOutput::pay_key(0, pk),
            ClauseOutput::at(1)
                .to(Unwind::new(p.clone())?.as_erased())
                .with_state(&UnwindState { root: new_root })
                .preserve_amount()
                .build(),
        ])
    }

    fn start_exit_specs(p: &PoolParams) -> Vec<ArgSpec> {
        let mut specs = vec![spec("unwind_taptree"), spec("root"), spec("r_prime")];
        for u in 0..p.padded_size() {
            specs.push(spec_num(&format!("bit_{u}")));
        }
        specs.extend([spec("ingrid_pk"), spec("trace_i"), spec_num("x")]);
        specs
    }

    // Public so the tests can assert on the generated script (bit guards).
    pub fn start_exit_script(p: &PoolParams) -> ScriptBuf {
        let n = p.padded_size();
        let mut s = StackScript::from_specs(&Self::start_exit_specs(p));

        // Bind the witness copy of our own taptree (a script cannot contain
        // its own hash; the dispute chain needs it later to revert here) and
        // the current root.
        s.ccv(
            Source::Item("root"),
            -1,
            Source::None,
            Source::Item("unwind_taptree"),
            CCV_FLAG_CHECK_INPUT,
        );

        // The exit set is *published* as one bit per slot and bound to its
        // commitment here, so anyone can recompute the honest claim and
        // challenge a false one. O(n) script work at claim time; the rest of
        // the protocol only ever touches single bits by Merkle proof.
        //
        // Each bit must be the *canonical* encoding of 0 or 1 — only `[]` and
        // `[0x01]` survive `x == 0NOTEQUAL(x)` byte-wise. The bit-consuming
        // clauses (ExitLeaf, challenge_delegation) can only prove canonical
        // leaves, so a non-canonical bit would make its step undisputable by
        // either party: an unchallengeable claim. Reject it at the source.
        for u in 0..n {
            s.roll(&format!("bit_{u}"));
            s.raw(
                script! { OP_DUP OP_DUP OP_0NOTEQUAL OP_EQUALVERIFY },
                1,
                &["bit"],
            );
            s.sha256_top(&format!("bitleaf_{u}"));
        }
        s.merkle_top(n, "s_root");

        s.pick("x");
        s.sha256_top("x_leaf");
        s.merkle_of(
            &[
                "unwind_taptree",
                "root",
                "r_prime",
                "s_root",
                "ingrid_pk",
                "trace_i",
                "x_leaf",
            ],
            "pe_state",
        );

        // Output 0 is the claim under challenge period.
        // TODO(OP_AMOUNT): enforce that output 0 carries the pool amount plus
        // Ingrid's bond (`p.bond` sats). Until then posting the bond is
        // honor-system (the demo always posts it via a batched ExitBond input).
        s.ccv(
            Source::Item("pe_state"),
            0,
            Source::None,
            Source::Const(
                PendingExit::new(p.clone())
                    .expect("PendingExit contract definition is valid")
                    .taptree_root(),
            ),
            0,
        );
        s.into_script()
    }

    fn start_exit_outputs(
        p: &PoolParams,
        witness: &[Vec<u8>],
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let n = p.padded_size();
        let mut w = WitnessReader::new(witness);
        let unwind_taptree = w.bytes32()?;
        let r = w.bytes32()?;
        let r_prime = w.bytes32()?;
        let mut bits = Vec::with_capacity(n);
        for _ in 0..n {
            bits.push(w.num()? != 0);
        }
        let ingrid_pk = w.bytes32()?;
        let trace_i = w.bytes32()?;
        let x = w.num()?;
        w.expect_end()?;

        let state = PendingExitState {
            unwind_taptree,
            r,
            r_prime,
            s_root: bit_root(&bits),
            ingrid_pk,
            trace_i,
            x,
        };
        Ok(vec![
            ClauseOutput::at(0)
                .to(PendingExit::new(p.clone())?.as_erased())
                .with_state(&state)
                .preserve_amount()
                .build(),
        ])
    }
}

impl UnwindHandle {
    /// Withdraw account `index` directly: output 0 pays its key, output 1
    /// continues the pool with the leaf zeroed. The caller must set the payout
    /// amount (`.output_amount(0, balance)`).
    pub fn withdraw_direct(&self, pool: &PoolTree, index: usize) -> SpendBuilder {
        let (pk, bal) = pool.accounts[index].expect("withdrawing an empty slot");
        let proof = pool.prove(index);
        let mut witness = vec![pk.serialize().to_vec(), bn2vch(bal)];
        for (h, d) in proof.hashes.iter().zip(&proof.directions) {
            witness.push(h.to_vec());
            witness.push(bn2vch(*d as i64));
        }
        witness.push(pool.root().to_vec());
        self.0.spend_clause("withdraw_direct", witness)
    }

    /// Post `claim` on behalf of `ingrid_pk`, moving the pool to
    /// [`PendingExit`]. Batch with an [`super::ExitBond`] `stake_claim` spend
    /// so the bond joins the pot.
    pub fn start_exit(
        &self,
        claim: &ExitClaim,
        ingrid_pk: &bitcoin::XOnlyPublicKey,
    ) -> SpendBuilder {
        let unwind_taptree = Unwind::new(self.params())
            .expect("Unwind contract definition is valid")
            .taptree_root();
        let mut witness = vec![
            unwind_taptree.to_vec(),
            claim.r.to_vec(),
            claim.r_prime.to_vec(),
        ];
        for bit in &claim.bits {
            witness.push(bn2vch(*bit as i64));
        }
        witness.push(ingrid_pk.serialize().to_vec());
        witness.push(claim.trace.to_vec());
        witness.push(bn2vch(claim.x));
        self.0.spend_clause("start_exit", witness)
    }
}
