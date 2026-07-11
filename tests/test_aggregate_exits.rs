//! Aggregate-exits example tests (`examples/aggregate_exits/`).
//!
//! Three offline tiers (no node): unit tests of the pool/claim/trace model,
//! build-level assertions on the spending transactions, and full protocol
//! walks driven by `build_batch_tx` + `observe_spend`. The `#[ignore]`d e2e
//! test mirrors the walks against a MATT-enabled regtest node.

mod support;

use bitcoin::bip32::Xpriv;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Amount, Network, Transaction, XOnlyPublicKey};
use mattrs::manager::{ContractManager, InstanceHandle, SpendBuilder};
use mattrs::merkle::NIL;
use mattrs::script_helpers::opaque_p2tr;
use mattrs::signer::HotSigner;

use support::aggregate_exits::*;
use support::testkit::{fund_fake, offline_manager, try_handle};

// ============================================================================
// Fixture
// ============================================================================

const BOND: i64 = 10_000;
/// Balances 1000, 2000, ..., 6000 — total 21_000, all sums well under 2^31.
const POOL_TOTAL: u64 = 21_000;

fn params() -> PoolParams {
    PoolParams {
        pool_id: [7u8; 32],
        n_users: 6, // padded to 8
        challenge_period: 10,
        response_timeout: 5,
        bond: BOND,
    }
}

fn user_xpriv(i: usize) -> Xpriv {
    Xpriv::new_master(Network::Regtest, &[10 + i as u8]).unwrap()
}

fn ingrid_xpriv() -> Xpriv {
    Xpriv::new_master(Network::Regtest, &[99]).unwrap()
}

fn xonly(xpriv: &Xpriv) -> XOnlyPublicKey {
    xpriv.to_priv().public_key(&Secp256k1::new()).into()
}

fn keypair(xpriv: &Xpriv) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &xpriv.to_priv().inner)
}

fn pool() -> PoolTree {
    let accounts: Vec<(XOnlyPublicKey, i64)> = (0..6)
        .map(|i| (xonly(&user_xpriv(i)), 1000 * (i as i64 + 1)))
        .collect();
    PoolTree::new(&params(), &accounts)
}

/// The demo exit set: users 1, 2 and 4 (aggregate 2000 + 3000 + 5000).
fn exit_bits() -> Vec<bool> {
    let mut bits = vec![false; 8];
    bits[1] = true;
    bits[2] = true;
    bits[4] = true;
    bits
}

/// Build the batch transaction, then decode it against every input's instance,
/// materializing (deduplicated) children. The offline counterpart of
/// `spend_batch`.
fn apply(
    manager: &mut ContractManager,
    parents: &[&InstanceHandle],
    builders: Vec<SpendBuilder>,
) -> (Transaction, Vec<InstanceHandle>) {
    let tx = manager.build_batch_tx(&builders).expect("build spend tx");
    let mut children: Vec<InstanceHandle> = Vec::new();
    for parent in parents {
        for child in manager.observe_spend(parent, &tx).expect("observe spend") {
            if !children.contains(&child) {
                children.push(child);
            }
        }
    }
    (tx, children)
}

/// Fake-fund the pool and Ingrid's bond, post the claim, and return the merged
/// [`PendingExit`] instance (pool total + bond).
fn claimed_pool(
    manager: &mut ContractManager,
    claim: &ExitClaim,
) -> (PendingExitHandle, PendingExitState) {
    let ingrid_pk = xonly(&ingrid_xpriv());
    let unwind: UnwindHandle = try_handle(fund_fake(
        Unwind::new(params()).as_erased(),
        Some(Box::new(UnwindState { root: pool().root() })),
        POOL_TOTAL,
        1,
    ));
    let bond: ExitBondHandle = try_handle(fund_fake(
        ExitBond::new(ExitBondParams {
            pool: params(),
            owner_pk: ingrid_pk,
        })
        .as_erased(),
        None,
        BOND as u64,
        2,
    ));

    let claim_state = PendingExitState::for_claim(&params(), claim, &ingrid_pk);
    let (tx, children) = apply(
        manager,
        &[unwind.handle(), bond.handle()],
        vec![
            unwind.start_exit(claim, &ingrid_pk),
            bond.stake_claim(&claim_state)
                .sign(HotSigner::new(ingrid_xpriv())),
        ],
    );
    assert_eq!(tx.output.len(), 1, "claim merges into a single output");
    assert_eq!(tx.output[0].value, Amount::from_sat(POOL_TOTAL + BOND as u64));
    assert_eq!(children.len(), 1);
    (try_handle(children[0].clone()), claim_state)
}

/// A challenger's bond instance.
fn challenger_bond(challenger: &Xpriv, seed: u8) -> ExitBondHandle {
    try_handle(fund_fake(
        ExitBond::new(ExitBondParams {
            pool: params(),
            owner_pk: xonly(challenger),
        })
        .as_erased(),
        None,
        BOND as u64,
        seed,
    ))
}

// ============================================================================
// Tier 1: units
// ============================================================================

#[test]
fn padding_and_depth() {
    let mut p = params();
    assert_eq!(p.padded_size(), 8);
    assert_eq!(p.depth(), 3);
    p.n_users = 8;
    assert_eq!(p.padded_size(), 8);
    p.n_users = 9;
    assert_eq!(p.padded_size(), 16);
    assert_eq!(p.depth(), 4);
    p.n_users = 1;
    assert_eq!(p.padded_size(), 2);
    assert_eq!(p.depth(), 1);
}

#[test]
fn honest_claim_computation() {
    let pool = pool();
    let claim = compute_claim(&pool, &exit_bits());
    assert_eq!(claim.x, 10_000);
    assert_eq!(claim.hs.len(), 9);
    assert_eq!(claim.hs[0], step_h(&pool.root(), 0));
    assert_eq!(claim.hs[8], step_h(&claim.r_prime, claim.x));

    // The claimed post-exit root equals the pool with the set zeroed.
    let mut after = pool.clone();
    for (u, bit) in claim.bits.iter().enumerate() {
        if *bit {
            after.zero(u);
        }
    }
    assert_eq!(claim.r_prime, after.root());

    // A set bit on a padding/zeroed slot contributes nothing.
    let mut bits = exit_bits();
    bits[7] = true; // padding
    let padded = compute_claim(&pool, &bits);
    assert_eq!(padded.x, claim.x);
    assert_eq!(padded.r_prime, claim.r_prime);
}

#[test]
fn lying_claim_diverges_at_the_lie() {
    let pool = pool();
    let honest = compute_claim(&pool, &exit_bits());
    let lie = compute_claim_with_lie(&pool, &exit_bits(), Some((4, 2_000)));
    assert_eq!(lie.x, honest.x + 2_000);
    assert_eq!(lie.r_prime, honest.r_prime, "roots stay honest");
    assert_eq!(lie.hs[..5], honest.hs[..5]);
    assert_ne!(lie.hs[5], honest.hs[5]);
    assert_ne!(lie.trace, honest.trace);
}

#[test]
fn delegation_signature_roundtrip() {
    let secp = Secp256k1::new();
    let user = keypair(&user_xpriv(2));
    let ingrid_pk = xonly(&ingrid_xpriv());
    let sig = sign_delegation(&user, &params().pool_id, &ingrid_pk);
    let msg = bitcoin::secp256k1::Message::from_digest(delegation_msg(&params().pool_id, &ingrid_pk));
    secp.verify_schnorr(
        &bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).unwrap(),
        &msg,
        &user.x_only_public_key().0,
    )
    .expect("delegation signature verifies");
}

#[test]
fn carry_commitment_matches_preimage() {
    use bitcoin::hashes::{sha256, Hash};
    let claim = compute_claim(&pool(), &exit_bits());
    let state = PendingExitState::for_claim(&params(), &claim, &xonly(&ingrid_xpriv()));
    let ctx = ChallengeContext {
        resume_state: state,
        pe_taptree: PendingExit::new(params()).taptree_root(),
        challenger_pk: xonly(&user_xpriv(0)).serialize(),
    };
    let mut preimage = Vec::new();
    for field in ctx.carry_fields() {
        preimage.extend_from_slice(&field);
    }
    assert_eq!(ctx.carry(), sha256::Hash::hash(&preimage).to_byte_array());
}

/// Constructing every contract runs every tapscript builder (the symbolic
/// stack tracker panics on any stack-discipline bug), for a couple of pool
/// sizes including a non-power-of-two one.
#[test]
fn all_tapscripts_build() {
    for n_users in [2u32, 5, 6, 8] {
        let mut p = params();
        p.n_users = n_users;
        let n = p.padded_size() as i64;
        Unwind::new(p.clone()).taptree_root();
        PendingExit::new(p.clone()).taptree_root();
        DelegationChallenge::new(p.clone()).taptree_root();
        ExitBond::new(ExitBondParams {
            pool: p.clone(),
            owner_pk: xonly(&ingrid_xpriv()),
        })
        .taptree_root();
        // Every bisection range and every leaf step.
        let mut spans = vec![];
        let mut size = n;
        while size >= 2 {
            for i in (0..n).step_by(size as usize) {
                spans.push((i, i + size - 1));
            }
            size /= 2;
        }
        for (i, j) in spans {
            let range = BisectRangeParams {
                pool: p.clone(),
                i,
                j,
            };
            ExitBisect1::new(range.clone()).taptree_root();
            ExitBisect2::new(range).taptree_root();
        }
        for k in 0..n {
            ExitLeaf::new(LeafStepParams { pool: p.clone(), k }).taptree_root();
        }
    }
}

// ============================================================================
// Tier 2: build-level (offline transactions)
// ============================================================================

#[test]
fn direct_withdrawal_builds_and_chains() {
    let mut manager = offline_manager();
    let pool = pool();
    let unwind: UnwindHandle = try_handle(fund_fake(
        Unwind::new(params()).as_erased(),
        Some(Box::new(UnwindState { root: pool.root() })),
        POOL_TOTAL,
        1,
    ));

    // User 2 exits with 3000 sats.
    let (tx, children) = apply(
        &mut manager,
        &[unwind.handle()],
        vec![unwind
            .withdraw_direct(&pool, 2)
            .output_amount(0, Amount::from_sat(3_000))],
    );
    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].value, Amount::from_sat(3_000));
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(xonly(&user_xpriv(2))));
    assert_eq!(tx.output[1].value, Amount::from_sat(POOL_TOTAL - 3_000));

    // The continued pool commits to the zeroed root, and chains.
    let mut after = pool.clone();
    after.zero(2);
    let next: UnwindHandle = try_handle(children[1].clone());
    assert_eq!(next.state().unwrap().root, after.root());

    let (tx2, _) = apply(
        &mut manager,
        &[next.handle()],
        vec![next
            .withdraw_direct(&after, 5)
            .output_amount(0, Amount::from_sat(6_000))],
    );
    assert_eq!(tx2.output[0].value, Amount::from_sat(6_000));
    assert_eq!(tx2.output[0].script_pubkey, opaque_p2tr(xonly(&user_xpriv(5))));
    assert_eq!(tx2.output[1].value, Amount::from_sat(POOL_TOTAL - 3_000 - 6_000));
}

#[test]
fn claim_merges_pool_and_bond() {
    let mut manager = offline_manager();
    let claim = compute_claim(&pool(), &exit_bits());
    let (pending, claim_state) = claimed_pool(&mut manager, &claim);
    assert_eq!(pending.state().unwrap(), claim_state);
}

// ============================================================================
// Tier 3: offline protocol walks
// ============================================================================

#[test]
fn happy_path_finalizes_after_challenge_period() {
    let mut manager = offline_manager();
    let claim = compute_claim(&pool(), &exit_bits());
    let (pending, _) = claimed_pool(&mut manager, &claim);

    let (tx, children) = apply(
        &mut manager,
        &[pending.handle()],
        vec![pending
            .finalize()
            .output_amount(0, Amount::from_sat((claim.x + BOND) as u64))],
    );
    // Ingrid gets the aggregate plus her bond back; the CSV gap is committed.
    assert_eq!(tx.input[0].sequence.0, params().challenge_period);
    assert_eq!(tx.output[0].value, Amount::from_sat(20_000));
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(xonly(&ingrid_xpriv())));
    // The pool continues with the remaining users' 11_000 sats at R'.
    assert_eq!(tx.output[1].value, Amount::from_sat(11_000));
    let continued: UnwindHandle = try_handle(children[1].clone());
    assert_eq!(continued.state().unwrap().root, claim.r_prime);

    // Remaining user 3 can still exit directly from the continued pool.
    let mut after = pool();
    for (u, bit) in claim.bits.iter().enumerate() {
        if *bit {
            after.zero(u);
        }
    }
    let (tx2, _) = apply(
        &mut manager,
        &[continued.handle()],
        vec![continued
            .withdraw_direct(&after, 3)
            .output_amount(0, Amount::from_sat(4_000))],
    );
    assert_eq!(tx2.output[0].script_pubkey, opaque_p2tr(xonly(&user_xpriv(3))));
}

/// Walk the bisection until the disputed single step, alternating Ingrid's and
/// the challenger's reveals, and return the leaf.
fn bisect_to_leaf(
    manager: &mut ContractManager,
    entry: InstanceHandle,
    ingrid_hs: &[[u8; 32]],
    challenger_hs: &[[u8; 32]],
) -> ExitLeafHandle {
    let mut current = entry;
    loop {
        let b1: ExitBisect1Handle = try_handle(current.clone());
        let (_, children) = apply(manager, &[b1.handle()], vec![b1.ingrid_reveal(ingrid_hs)]);
        let b2: ExitBisect2Handle = try_handle(children[0].clone());
        let (_, children) = apply(
            manager,
            &[b2.handle()],
            vec![b2.challenger_reveal(challenger_hs)],
        );
        match ExitLeafHandle::try_from(children[0].clone()) {
            Ok(leaf) => return leaf,
            Err(_) => current = children[0].clone(),
        }
    }
}

#[test]
fn fraudulent_claim_loses_the_bisection() {
    let mut manager = offline_manager();
    let pool = pool();
    // Ingrid inflates the aggregate by 2000 at step 4.
    let lie = compute_claim_with_lie(&pool, &exit_bits(), Some((4, 2_000)));
    let honest = compute_claim(&pool, &exit_bits());
    let (pending, claim_state) = claimed_pool(&mut manager, &lie);

    // User 0 challenges the claimed amount.
    let challenger = user_xpriv(0);
    let cbond = challenger_bond(&challenger, 3);
    let (tx, children) = apply(
        &mut manager,
        &[pending.handle(), cbond.handle()],
        vec![
            pending.challenge_state(&honest, &xonly(&challenger)),
            cbond
                .stake_state_challenge(&claim_state, &honest, &xonly(&challenger))
                .sign(HotSigner::new(challenger.clone())),
        ],
    );
    assert_eq!(tx.output.len(), 1);
    assert_eq!(
        tx.output[0].value,
        Amount::from_sat(POOL_TOTAL + 2 * BOND as u64)
    );

    // The bisection converges on the lying step...
    let leaf = bisect_to_leaf(&mut manager, children[0].clone(), &lie.hs, &honest.hs);
    assert_eq!(leaf.params().unwrap().k, 4);

    // ...where the challenger re-runs it and wins: bond + half of Ingrid's,
    // half burned, and the withdrawal is reverted.
    let (tx, children) = apply(
        &mut manager,
        &[leaf.handle()],
        vec![leaf
            .reveal(DisputeWinner::Challenger, &honest, &pool)
            .output_amount(0, Amount::from_sat((BOND + BOND / 2) as u64))
            .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))],
    );
    assert_eq!(tx.output[0].value, Amount::from_sat(15_000));
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(xonly(&challenger)));
    assert_eq!(tx.output[1].value, Amount::from_sat(5_000));
    assert_eq!(tx.output[1].script_pubkey, opaque_p2tr(mattrs::nums_key()));
    assert_eq!(tx.output[2].value, Amount::from_sat(POOL_TOTAL));
    let reverted: UnwindHandle = try_handle(children[2].clone());
    assert_eq!(reverted.state().unwrap().root, pool.root());
}

#[test]
fn false_challenge_loses_and_the_claim_resumes() {
    let mut manager = offline_manager();
    let pool = pool();
    let honest = compute_claim(&pool, &exit_bits());
    // The challenger's own committed run is the fabricated one.
    let fabricated = compute_claim_with_lie(&pool, &exit_bits(), Some((2, -1_000)));
    let (pending, claim_state) = claimed_pool(&mut manager, &honest);

    let challenger = user_xpriv(5);
    let cbond = challenger_bond(&challenger, 4);
    let (_, children) = apply(
        &mut manager,
        &[pending.handle(), cbond.handle()],
        vec![
            pending.challenge_state(&fabricated, &xonly(&challenger)),
            cbond
                .stake_state_challenge(&claim_state, &fabricated, &xonly(&challenger))
                .sign(HotSigner::new(challenger.clone())),
        ],
    );

    let leaf = bisect_to_leaf(&mut manager, children[0].clone(), &honest.hs, &fabricated.hs);
    assert_eq!(leaf.params().unwrap().k, 2);

    // Ingrid re-runs the disputed step and wins: half the challenger's bond,
    // half burned, and the claim resumes with a fresh challenge period.
    let (tx, children) = apply(
        &mut manager,
        &[leaf.handle()],
        vec![leaf
            .reveal(DisputeWinner::Ingrid, &honest, &pool)
            .output_amount(0, Amount::from_sat((BOND / 2) as u64))
            .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))],
    );
    assert_eq!(tx.output[0].value, Amount::from_sat(5_000));
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(xonly(&ingrid_xpriv())));
    assert_eq!(tx.output[1].script_pubkey, opaque_p2tr(mattrs::nums_key()));
    assert_eq!(tx.output[2].value, Amount::from_sat(POOL_TOTAL + BOND as u64));
    let resumed: PendingExitHandle = try_handle(children[2].clone());
    assert_eq!(resumed.state().unwrap(), claim_state);

    // ...and can then finalize normally.
    let (tx, _) = apply(
        &mut manager,
        &[resumed.handle()],
        vec![resumed
            .finalize()
            .output_amount(0, Amount::from_sat((honest.x + BOND) as u64))],
    );
    assert_eq!(tx.output[1].value, Amount::from_sat(11_000));
}

#[test]
fn stalled_turns_forfait_both_ways() {
    let mut manager = offline_manager();
    let pool = pool();
    let lie = compute_claim_with_lie(&pool, &exit_bits(), Some((1, 500)));
    let honest = compute_claim(&pool, &exit_bits());
    let (pending, claim_state) = claimed_pool(&mut manager, &lie);

    let challenger = user_xpriv(0);
    let cbond = challenger_bond(&challenger, 3);
    let (_, children) = apply(
        &mut manager,
        &[pending.handle(), cbond.handle()],
        vec![
            pending.challenge_state(&honest, &xonly(&challenger)),
            cbond
                .stake_state_challenge(&claim_state, &honest, &xonly(&challenger))
                .sign(HotSigner::new(challenger.clone())),
        ],
    );

    // Ingrid never responds: the challenger forfaits her after the timeout.
    let b1: ExitBisect1Handle = try_handle(children[0].clone());
    let (tx, children) = apply(
        &mut manager,
        &[b1.handle()],
        vec![b1
            .forfait()
            .output_amount(0, Amount::from_sat((BOND + BOND / 2) as u64))
            .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))],
    );
    assert_eq!(tx.input[0].sequence.0, params().response_timeout);
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(xonly(&challenger)));
    assert_eq!(tx.output[2].value, Amount::from_sat(POOL_TOTAL));
    let reverted: UnwindHandle = try_handle(children[2].clone());
    assert_eq!(reverted.state().unwrap().root, pool.root());

    // The mirror image: the challenger stalls after Ingrid's reveal.
    let mut manager = offline_manager();
    let (pending, claim_state) = claimed_pool(&mut manager, &lie);
    let cbond = challenger_bond(&challenger, 5);
    let (_, children) = apply(
        &mut manager,
        &[pending.handle(), cbond.handle()],
        vec![
            pending.challenge_state(&honest, &xonly(&challenger)),
            cbond
                .stake_state_challenge(&claim_state, &honest, &xonly(&challenger))
                .sign(HotSigner::new(challenger.clone())),
        ],
    );
    let b1: ExitBisect1Handle = try_handle(children[0].clone());
    let (_, children) = apply(&mut manager, &[b1.handle()], vec![b1.ingrid_reveal(&lie.hs)]);
    let b2: ExitBisect2Handle = try_handle(children[0].clone());
    let (tx, children) = apply(
        &mut manager,
        &[b2.handle()],
        vec![b2
            .forfait()
            .output_amount(0, Amount::from_sat((BOND / 2) as u64))
            .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))],
    );
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(xonly(&ingrid_xpriv())));
    let resumed: PendingExitHandle = try_handle(children[2].clone());
    assert_eq!(resumed.state().unwrap(), claim_state);
}

#[test]
fn delegation_challenge_defended() {
    let mut manager = offline_manager();
    let pool = pool();
    let honest = compute_claim(&pool, &exit_bits());
    let (pending, claim_state) = claimed_pool(&mut manager, &honest);
    let ingrid_pk = xonly(&ingrid_xpriv());

    // User 2 (who *did* delegate) challenges anyway.
    let challenger = user_xpriv(2);
    let cbond = challenger_bond(&challenger, 3);
    let (tx, children) = apply(
        &mut manager,
        &[pending.handle(), cbond.handle()],
        vec![
            pending.challenge_delegation(&pool, &honest.bits, 2, &xonly(&challenger)),
            cbond
                .stake_delegation_challenge(&claim_state, &xonly(&challenger), &xonly(&challenger))
                .sign(HotSigner::new(challenger.clone())),
        ],
    );
    assert_eq!(
        tx.output[0].value,
        Amount::from_sat(POOL_TOTAL + 2 * BOND as u64)
    );

    // Ingrid reveals the delegation signature and pockets half the bond.
    let sig = sign_delegation(&keypair(&user_xpriv(2)), &params().pool_id, &ingrid_pk);
    let dc: DelegationChallengeHandle = try_handle(children[0].clone());
    let (tx, children) = apply(
        &mut manager,
        &[dc.handle()],
        vec![dc
            .defend(&sig)
            .output_amount(0, Amount::from_sat((BOND / 2) as u64))
            .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))],
    );
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(ingrid_pk));
    assert_eq!(tx.output[1].script_pubkey, opaque_p2tr(mattrs::nums_key()));
    assert_eq!(tx.output[2].value, Amount::from_sat(POOL_TOTAL + BOND as u64));
    let resumed: PendingExitHandle = try_handle(children[2].clone());
    assert_eq!(resumed.state().unwrap(), claim_state);
}

#[test]
fn unanswerable_delegation_challenge_reverts_the_claim() {
    let mut manager = offline_manager();
    let pool = pool();
    // Ingrid includes user 3, who never delegated.
    let mut bits = exit_bits();
    bits[3] = true;
    let claim = compute_claim(&pool, &bits);
    let (pending, claim_state) = claimed_pool(&mut manager, &claim);

    let challenger = user_xpriv(3);
    let cbond = challenger_bond(&challenger, 3);
    let (_, children) = apply(
        &mut manager,
        &[pending.handle(), cbond.handle()],
        vec![
            pending.challenge_delegation(&pool, &claim.bits, 3, &xonly(&challenger)),
            cbond
                .stake_delegation_challenge(&claim_state, &xonly(&challenger), &xonly(&challenger))
                .sign(HotSigner::new(challenger.clone())),
        ],
    );

    // Ingrid has no signature to reveal; the challenger collects on timeout.
    let dc: DelegationChallengeHandle = try_handle(children[0].clone());
    let (tx, children) = apply(
        &mut manager,
        &[dc.handle()],
        vec![dc
            .challenger_wins()
            .output_amount(0, Amount::from_sat((BOND + BOND / 2) as u64))
            .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))],
    );
    assert_eq!(tx.input[0].sequence.0, params().response_timeout);
    assert_eq!(tx.output[0].value, Amount::from_sat(15_000));
    assert_eq!(tx.output[0].script_pubkey, opaque_p2tr(xonly(&challenger)));
    assert_eq!(tx.output[2].value, Amount::from_sat(POOL_TOTAL));
    let reverted: UnwindHandle = try_handle(children[2].clone());
    assert_eq!(reverted.state().unwrap().root, pool.root());
}

#[test]
fn nil_step_dispute_is_defensible() {
    // Ingrid claims a set including slot 6 (a zeroed/padding slot) and lies
    // about that very step; the challenger wins with the NIL-case reveal.
    let mut manager = offline_manager();
    let pool = pool();
    let mut bits = exit_bits();
    bits[6] = true; // padding slot: contributes nothing
    let lie = compute_claim_with_lie(&pool, &bits, Some((6, 700)));
    let honest = compute_claim(&pool, &bits);
    let (pending, claim_state) = claimed_pool(&mut manager, &lie);

    let challenger = user_xpriv(1);
    let cbond = challenger_bond(&challenger, 3);
    let (_, children) = apply(
        &mut manager,
        &[pending.handle(), cbond.handle()],
        vec![
            pending.challenge_state(&honest, &xonly(&challenger)),
            cbond
                .stake_state_challenge(&claim_state, &honest, &xonly(&challenger))
                .sign(HotSigner::new(challenger.clone())),
        ],
    );
    let leaf = bisect_to_leaf(&mut manager, children[0].clone(), &lie.hs, &honest.hs);
    assert_eq!(leaf.params().unwrap().k, 6);

    let (tx, _) = apply(
        &mut manager,
        &[leaf.handle()],
        vec![leaf
            .reveal(DisputeWinner::Challenger, &honest, &pool)
            .output_amount(0, Amount::from_sat((BOND + BOND / 2) as u64))
            .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))],
    );
    assert_eq!(tx.output[2].value, Amount::from_sat(POOL_TOTAL));

    // The NIL leaf value really is the zero hash (a documented invariant the
    // tapscripts push as a constant).
    assert_eq!(NIL, [0u8; 32]);
}

// ============================================================================
// End-to-end (regtest): validated by a MATT-enabled node.
// ============================================================================

/// Regtest fixture: a funded pool and Ingrid's bond, real manager.
#[allow(clippy::type_complexity)]
fn regtest_setup(
    wallet: &str,
) -> Result<(ContractManager, mattrs::report::Report), Box<dyn std::error::Error>> {
    let client = support::testkit::regtest_client(wallet);
    let manager = ContractManager::new(client, Network::Regtest);
    Ok((manager, mattrs::report::Report::new()))
}

#[test]
#[ignore = "requires a running MATT-enabled regtest bitcoind"]
fn direct_and_happy_path_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use support::testkit::report_spend;
    let (mut manager, mut report) = regtest_setup("testwallet")?;
    let pool = pool();
    let ingrid_pk = xonly(&ingrid_xpriv());

    let unwind = Unwind::new(params()).fund(
        &mut manager,
        Amount::from_sat(POOL_TOTAL),
        UnwindState { root: pool.root() },
    )?;

    // User 2 exits directly with a Merkle proof.
    let children = unwind
        .withdraw_direct(&pool, 2)
        .output_amount(0, Amount::from_sat(3_000))
        .exec(&mut manager)?;
    report_spend(&mut report, "AggregateExits", "withdraw_direct (user 2)", unwind.handle());
    let mut after = pool.clone();
    after.zero(2);
    let unwind: UnwindHandle = try_handle(children[1].clone());
    assert_eq!(unwind.state().unwrap().root, after.root());

    // Ingrid claims the aggregate of users 1 and 4 with her bond.
    let mut bits = vec![false; 8];
    bits[1] = true;
    bits[4] = true;
    let claim = compute_claim(&after, &bits);
    assert_eq!(claim.x, 7_000);
    let bond = ExitBond::new(ExitBondParams {
        pool: params(),
        owner_pk: ingrid_pk,
    })
    .fund(&mut manager, Amount::from_sat(BOND as u64))?;

    let claim_state = PendingExitState::for_claim(&params(), &claim, &ingrid_pk);
    let children = manager.spend_batch(&[
        unwind.start_exit(&claim, &ingrid_pk),
        bond.stake_claim(&claim_state).sign(HotSigner::new(ingrid_xpriv())),
    ])?;
    report_spend(&mut report, "AggregateExits", "start_exit + bond", unwind.handle());
    let pending: PendingExitHandle = try_handle(children[0].clone());

    // The claim matures unchallenged; Ingrid finalizes.
    manager.mine_blocks(params().challenge_period as u64)?;
    let children = pending
        .finalize()
        .output_amount(0, Amount::from_sat((claim.x + BOND) as u64))
        .exec(&mut manager)?;
    report_spend(&mut report, "AggregateExits", "finalize", pending.handle());
    let continued: UnwindHandle = try_handle(children[1].clone());
    assert_eq!(continued.state().unwrap().root, claim.r_prime);

    report.finalize("reports/report_aggregate_exits_happy.md");
    Ok(())
}

#[test]
#[ignore = "requires a running MATT-enabled regtest bitcoind"]
fn fraud_proof_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use support::testkit::report_spend;
    let (mut manager, mut report) = regtest_setup("testwallet")?;
    let pool = pool();
    let ingrid_pk = xonly(&ingrid_xpriv());

    let unwind = Unwind::new(params()).fund(
        &mut manager,
        Amount::from_sat(POOL_TOTAL),
        UnwindState { root: pool.root() },
    )?;

    // Ingrid claims 2000 sats too much at step 4.
    let lie = compute_claim_with_lie(&pool, &exit_bits(), Some((4, 2_000)));
    let honest = compute_claim(&pool, &exit_bits());
    let claim_state = PendingExitState::for_claim(&params(), &lie, &ingrid_pk);
    let ibond = ExitBond::new(ExitBondParams {
        pool: params(),
        owner_pk: ingrid_pk,
    })
    .fund(&mut manager, Amount::from_sat(BOND as u64))?;
    let children = manager.spend_batch(&[
        unwind.start_exit(&lie, &ingrid_pk),
        ibond.stake_claim(&claim_state).sign(HotSigner::new(ingrid_xpriv())),
    ])?;
    let pending: PendingExitHandle = try_handle(children[0].clone());

    // User 0 opens the bisection game.
    let challenger = user_xpriv(0);
    let cbond = ExitBond::new(ExitBondParams {
        pool: params(),
        owner_pk: xonly(&challenger),
    })
    .fund(&mut manager, Amount::from_sat(BOND as u64))?;
    let children = manager.spend_batch(&[
        pending.challenge_state(&honest, &xonly(&challenger)),
        cbond
            .stake_state_challenge(&claim_state, &honest, &xonly(&challenger))
            .sign(HotSigner::new(challenger.clone())),
    ])?;
    report_spend(&mut report, "AggregateExits", "challenge_state + bond", pending.handle());

    // Alternate reveals down to the disputed step.
    let mut current = children[0].clone();
    let leaf: ExitLeafHandle = loop {
        let b1: ExitBisect1Handle = try_handle(current.clone());
        let children = b1.ingrid_reveal(&lie.hs).exec(&mut manager)?;
        let b2: ExitBisect2Handle = try_handle(children[0].clone());
        let children = b2.challenger_reveal(&honest.hs).exec(&mut manager)?;
        match ExitLeafHandle::try_from(children[0].clone()) {
            Ok(leaf) => break leaf,
            Err(_) => current = children[0].clone(),
        }
    };
    assert_eq!(leaf.params().unwrap().k, 4);

    // The challenger re-runs step 4 on-chain and wins.
    let children = leaf
        .reveal(DisputeWinner::Challenger, &honest, &pool)
        .output_amount(0, Amount::from_sat((BOND + BOND / 2) as u64))
        .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))
        .exec(&mut manager)?;
    report_spend(&mut report, "AggregateExits", "leaf reveal (challenger wins)", leaf.handle());
    let reverted: UnwindHandle = try_handle(children[2].clone());
    assert_eq!(reverted.state().unwrap().root, pool.root());

    report.finalize("reports/report_aggregate_exits_fraud.md");
    Ok(())
}

#[test]
#[ignore = "requires a running MATT-enabled regtest bitcoind (with OP_CHECKSIGFROMSTACK for full validation)"]
fn delegation_challenge_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use support::testkit::report_spend;
    let (mut manager, mut report) = regtest_setup("testwallet")?;
    let pool = pool();
    let ingrid_pk = xonly(&ingrid_xpriv());

    let unwind = Unwind::new(params()).fund(
        &mut manager,
        Amount::from_sat(POOL_TOTAL),
        UnwindState { root: pool.root() },
    )?;
    let honest = compute_claim(&pool, &exit_bits());
    let claim_state = PendingExitState::for_claim(&params(), &honest, &ingrid_pk);
    let ibond = ExitBond::new(ExitBondParams {
        pool: params(),
        owner_pk: ingrid_pk,
    })
    .fund(&mut manager, Amount::from_sat(BOND as u64))?;
    let children = manager.spend_batch(&[
        unwind.start_exit(&honest, &ingrid_pk),
        ibond.stake_claim(&claim_state).sign(HotSigner::new(ingrid_xpriv())),
    ])?;
    let pending: PendingExitHandle = try_handle(children[0].clone());

    // User 2 disputes their own delegation; Ingrid defends with the signature.
    let challenger = user_xpriv(2);
    let cbond = ExitBond::new(ExitBondParams {
        pool: params(),
        owner_pk: xonly(&challenger),
    })
    .fund(&mut manager, Amount::from_sat(BOND as u64))?;
    let children = manager.spend_batch(&[
        pending.challenge_delegation(&pool, &honest.bits, 2, &xonly(&challenger)),
        cbond
            .stake_delegation_challenge(&claim_state, &xonly(&challenger), &xonly(&challenger))
            .sign(HotSigner::new(challenger.clone())),
    ])?;
    let dc: DelegationChallengeHandle = try_handle(children[0].clone());

    let sig = sign_delegation(&keypair(&user_xpriv(2)), &params().pool_id, &ingrid_pk);
    let children = dc
        .defend(&sig)
        .output_amount(0, Amount::from_sat((BOND / 2) as u64))
        .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))
        .exec(&mut manager)?;
    report_spend(&mut report, "AggregateExits", "defend (CSFS reveal)", dc.handle());
    let resumed: PendingExitHandle = try_handle(children[2].clone());
    assert_eq!(resumed.state().unwrap(), claim_state);

    // The resumed claim finalizes after a fresh challenge period.
    manager.mine_blocks(params().challenge_period as u64)?;
    resumed
        .finalize()
        .output_amount(0, Amount::from_sat((honest.x + BOND) as u64))
        .exec(&mut manager)?;
    report_spend(&mut report, "AggregateExits", "finalize (resumed)", resumed.handle());

    report.finalize("reports/report_aggregate_exits_delegation.md");
    Ok(())
}
