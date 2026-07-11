//! Aggregate exits demo: optimistic aggregated withdrawals from a shared UTXO.
//!
//! Runs the protocol of `aggregate_exits.md` (concrete spec in `SPEC.md`) on a
//! MATT-enabled regtest node, one scenario per execution path:
//!
//! ```text
//! cargo run --example aggregate_exits                          # all scenarios
//! cargo run --example aggregate_exits -- --scenario fraud
//! cargo run --example aggregate_exits -- --wallet mywallet
//! ```
//!
//! Scenarios: `direct` (Merkle-proof withdrawal), `happy` (unchallenged
//! aggregated exit), `fraud` (a lying claim loses the bisection game),
//! `false-challenge` (a bogus challenge loses and the claim resumes),
//! `delegation-defend` (Ingrid reveals the CHECKSIGFROMSTACK delegation),
//! `delegation-timeout` (she cannot, and the withdrawal reverts).
//!
//! Needs a regtest `bitcoind` with OP_CHECKCONTRACTVERIFY (and ideally
//! OP_CHECKSIGFROMSTACK) and a funded `testwallet`; see the repo README. Auth
//! follows `regtest_rpc_client` (`BITCOIN_RPC_URL`/`_USER`/`_PASSWORD` or the
//! regtest cookie).

// The tests compile this same module (see `tests/support/mod.rs`) and use
// parts of its API the demo does not; the allows mirror the support mounts.
#[allow(dead_code, unused_imports)]
mod contracts;

use bitcoin::bip32::Xpriv;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Amount, Network, XOnlyPublicKey};
use mattrs::manager::{regtest_rpc_client, ContractManager, InstanceHandle};
use mattrs::signer::HotSigner;

use contracts::*;

const BOND: i64 = 10_000;
const BALANCES: [i64; 6] = [1_000, 2_000, 3_000, 4_000, 5_000, 6_000];
const POOL_TOTAL: u64 = 21_000;

fn params() -> PoolParams {
    PoolParams {
        pool_id: [7u8; 32],
        n_users: 6, // padded to 8 slots
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

fn short(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn set_string(bits: &[bool]) -> String {
    let indices: Vec<String> = bits
        .iter()
        .enumerate()
        .filter(|(_, b)| **b)
        .map(|(i, _)| i.to_string())
        .collect();
    format!("{{{}}}", indices.join(", "))
}

/// Everything one scenario needs: a freshly funded pool and its cast.
struct Stage {
    manager: ContractManager,
    params: PoolParams,
    pool: PoolTree,
    unwind: UnwindHandle,
    ingrid_pk: XOnlyPublicKey,
}

impl Stage {
    fn new(wallet: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let params = params();
        let accounts: Vec<(XOnlyPublicKey, i64)> = (0..6)
            .map(|i| (xonly(&user_xpriv(i)), BALANCES[i]))
            .collect();
        let pool = PoolTree::new(&params, &accounts);

        let mut manager =
            ContractManager::new(regtest_rpc_client(wallet), Network::Regtest);
        let unwind = Unwind::new(params.clone()).fund(
            &mut manager,
            Amount::from_sat(POOL_TOTAL),
            UnwindState { root: pool.root() },
        )?;

        println!("  The pool holds {POOL_TOTAL} sats for 6 users (root {}):", short(&pool.root()));
        for (i, balance) in BALANCES.iter().enumerate() {
            println!("    user {i}: {balance:>5} sats  (pk {})", short(&xonly(&user_xpriv(i)).serialize()));
        }
        println!("  Unwind funded at {}", unwind.handle().outpoint().unwrap());

        Ok(Stage {
            manager,
            params,
            pool,
            unwind,
            ingrid_pk: xonly(&ingrid_xpriv()),
        })
    }

    fn bond_for(&mut self, owner: &Xpriv) -> Result<ExitBondHandle, Box<dyn std::error::Error>> {
        Ok(ExitBond::new(ExitBondParams {
            pool: self.params.clone(),
            owner_pk: xonly(owner),
        })
        .fund(&mut self.manager, Amount::from_sat(BOND as u64))?)
    }

    /// Post `claim` (with Ingrid's bond) and return the pending exit.
    fn claim(
        &mut self,
        claim: &ExitClaim,
    ) -> Result<(PendingExitHandle, PendingExitState), Box<dyn std::error::Error>> {
        let bond = self.bond_for(&ingrid_xpriv())?;
        let claim_state = PendingExitState::for_claim(&self.params, claim, &self.ingrid_pk);
        let children = self.manager.spend_batch(&[
            self.unwind.start_exit(claim, &self.ingrid_pk),
            bond.stake_claim(&claim_state)
                .sign(HotSigner::new(ingrid_xpriv())),
        ])?;
        println!(
            "  Ingrid claims X = {} sats for users {} (+{} sats bond, {}-block challenge period)",
            claim.x,
            set_string(&claim.bits),
            BOND,
            self.params.challenge_period,
        );
        Ok((children[0].clone().try_into().unwrap(), claim_state))
    }

    /// Open the bisection game on a claim.
    fn challenge(
        &mut self,
        pending: &PendingExitHandle,
        claim_state: &PendingExitState,
        challenger: &Xpriv,
        challenger_claim: &ExitClaim,
    ) -> Result<InstanceHandle, Box<dyn std::error::Error>> {
        let cbond = self.bond_for(challenger)?;
        let children = self.manager.spend_batch(&[
            pending.challenge_state(challenger_claim, &xonly(challenger)),
            cbond
                .stake_state_challenge(claim_state, challenger_claim, &xonly(challenger))
                .sign(HotSigner::new(*challenger)),
        ])?;
        println!(
            "  A challenger disputes the claim (h_end {} vs Ingrid's {}), posting {} sats bond",
            short(&challenger_claim.hs[challenger_claim.hs.len() - 1]),
            short(&step_h(&claim_state.r_prime, claim_state.x)),
            BOND,
        );
        Ok(children[0].clone())
    }

    /// Alternate reveals down to the single disputed step.
    fn bisect_to_leaf(
        &mut self,
        entry: InstanceHandle,
        ingrid_hs: &[[u8; 32]],
        challenger_hs: &[[u8; 32]],
    ) -> Result<ExitLeafHandle, Box<dyn std::error::Error>> {
        let mut current = entry;
        loop {
            let b1: ExitBisect1Handle = current.clone().try_into().unwrap();
            let p = b1.params().unwrap();
            let children = b1.ingrid_reveal(ingrid_hs).exec(&mut self.manager)?;
            println!("    bisecting [{}, {}]: Ingrid reveals her midpoint", p.i, p.j);
            let b2: ExitBisect2Handle = children[0].clone().try_into().unwrap();
            let children = b2
                .challenger_reveal(challenger_hs)
                .exec(&mut self.manager)?;
            match ExitLeafHandle::try_from(children[0].clone()) {
                Ok(leaf) => {
                    println!(
                        "    the challenger recurses: dispute pinned to step {}",
                        leaf.params().unwrap().k
                    );
                    return Ok(leaf);
                }
                Err(_) => {
                    let next: ExitBisect1Handle = children[0].clone().try_into().unwrap();
                    let np = next.params().unwrap();
                    println!("    the challenger recurses into [{}, {}]", np.i, np.j);
                    current = children[0].clone();
                }
            }
        }
    }

    fn mine(&mut self, blocks: u32, why: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("  ... {blocks} blocks pass ({why})");
        self.manager.mine_blocks(blocks as u64)?;
        Ok(())
    }
}

// ============================================================================
// Scenarios
// ============================================================================

fn scenario_direct(wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== direct: user 2 exits with a Merkle proof ===");
    let mut stage = Stage::new(wallet)?;

    let children = stage
        .unwind
        .withdraw_direct(&stage.pool, 2)
        .output_amount(0, Amount::from_sat(BALANCES[2] as u64))
        .exec(&mut stage.manager)?;
    let mut after = stage.pool.clone();
    after.zero(2);
    let next: UnwindHandle = children[1].clone().try_into().unwrap();
    assert_eq!(next.state().unwrap().root, after.root());
    println!(
        "  user 2 takes {} sats; the pool continues with {} sats at root {}",
        BALANCES[2],
        POOL_TOTAL - BALANCES[2] as u64,
        short(&after.root()),
    );

    // And it chains: user 5 exits from the continued pool.
    let children = next
        .withdraw_direct(&after, 5)
        .output_amount(0, Amount::from_sat(BALANCES[5] as u64))
        .exec(&mut stage.manager)?;
    after.zero(5);
    let next: UnwindHandle = children[1].clone().try_into().unwrap();
    assert_eq!(next.state().unwrap().root, after.root());
    println!(
        "  user 5 takes {} sats; the pool continues with {} sats",
        BALANCES[5],
        POOL_TOTAL - BALANCES[2] as u64 - BALANCES[5] as u64,
    );
    Ok(())
}

fn exit_bits() -> Vec<bool> {
    let mut bits = vec![false; 8];
    bits[1] = true;
    bits[2] = true;
    bits[4] = true;
    bits
}

fn scenario_happy(wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== happy: users 1, 2 and 4 exit through Ingrid, unchallenged ===");
    let mut stage = Stage::new(wallet)?;
    let claim = compute_claim(&stage.pool, &exit_bits());
    let (pending, _) = stage.claim(&claim)?;

    stage.mine(stage.params.challenge_period, "no one challenges")?;
    let children = pending
        .finalize()
        .output_amount(0, Amount::from_sat((claim.x + BOND) as u64))
        .exec(&mut stage.manager)?;
    let continued: UnwindHandle = children[1].clone().try_into().unwrap();
    assert_eq!(continued.state().unwrap().root, claim.r_prime);
    println!(
        "  Ingrid takes {} sats (aggregate {} + bond {}); the pool continues with {} sats at R' {}",
        claim.x + BOND,
        claim.x,
        BOND,
        POOL_TOTAL - claim.x as u64,
        short(&claim.r_prime),
    );
    println!("  (off-chain, Ingrid settles with users 1, 2 and 4 — e.g. over Lightning)");
    Ok(())
}

fn scenario_fraud(wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== fraud: Ingrid inflates the aggregate; user 0 proves it ===");
    let mut stage = Stage::new(wallet)?;
    let lie = compute_claim_with_lie(&stage.pool, &exit_bits(), Some((4, 2_000)));
    let honest = compute_claim(&stage.pool, &exit_bits());
    println!(
        "  (the honest aggregate is {} sats; Ingrid claims {} — a lie at step 4)",
        honest.x, lie.x
    );
    let (pending, claim_state) = stage.claim(&lie)?;

    let challenger = user_xpriv(0);
    let entry = stage.challenge(&pending, &claim_state, &challenger, &honest)?;
    let leaf = stage.bisect_to_leaf(entry, &lie.hs, &honest.hs)?;

    let children = leaf
        .reveal(DisputeWinner::Challenger, &honest, &stage.pool)
        .output_amount(0, Amount::from_sat((BOND + BOND / 2) as u64))
        .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))
        .exec(&mut stage.manager)?;
    let reverted: UnwindHandle = children[2].clone().try_into().unwrap();
    assert_eq!(reverted.state().unwrap().root, stage.pool.root());
    println!(
        "  step 4 re-run on-chain: Ingrid lied. The challenger takes {} sats (their bond back + half of Ingrid's), {} sats are burned,",
        BOND + BOND / 2,
        BOND - BOND / 2,
    );
    println!(
        "  and the withdrawal is reverted: the pool holds its full {} sats again at root {}",
        POOL_TOTAL,
        short(&stage.pool.root()),
    );
    Ok(())
}

fn scenario_false_challenge(wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== false-challenge: a bogus challenge against an honest claim ===");
    let mut stage = Stage::new(wallet)?;
    let honest = compute_claim(&stage.pool, &exit_bits());
    let fabricated = compute_claim_with_lie(&stage.pool, &exit_bits(), Some((2, -1_000)));
    let (pending, claim_state) = stage.claim(&honest)?;

    let challenger = user_xpriv(5);
    let entry = stage.challenge(&pending, &claim_state, &challenger, &fabricated)?;
    let leaf = stage.bisect_to_leaf(entry, &honest.hs, &fabricated.hs)?;

    let children = leaf
        .reveal(DisputeWinner::Ingrid, &honest, &stage.pool)
        .output_amount(0, Amount::from_sat((BOND / 2) as u64))
        .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))
        .exec(&mut stage.manager)?;
    let resumed: PendingExitHandle = children[2].clone().try_into().unwrap();
    assert_eq!(resumed.state().unwrap(), claim_state);
    println!(
        "  step 2 re-run on-chain: the claim was honest. Ingrid pockets {} sats of the challenger's bond, {} are burned,",
        BOND / 2,
        BOND - BOND / 2,
    );
    println!("  and the claim resumes with a fresh challenge period.");

    stage.mine(stage.params.challenge_period, "no further challenge")?;
    resumed
        .finalize()
        .output_amount(0, Amount::from_sat((honest.x + BOND) as u64))
        .exec(&mut stage.manager)?;
    println!("  Ingrid finalizes: {} sats out.", honest.x + BOND);
    Ok(())
}

fn scenario_delegation_defend(wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== delegation-defend: \"user 2 never delegated!\" — but they did ===");
    let mut stage = Stage::new(wallet)?;
    let honest = compute_claim(&stage.pool, &exit_bits());
    // Users 1, 2 and 4 sign delegations off-chain before the claim.
    let delegations: Vec<[u8; 64]> = (0..6)
        .map(|i| sign_delegation(&keypair(&user_xpriv(i)), &stage.params.pool_id, &stage.ingrid_pk))
        .collect();
    let (pending, claim_state) = stage.claim(&honest)?;

    let challenger = user_xpriv(2);
    let cbond = stage.bond_for(&challenger)?;
    let children = stage.manager.spend_batch(&[
        pending.challenge_delegation(&stage.pool, &honest.bits, 2, &xonly(&challenger)),
        cbond
            .stake_delegation_challenge(&claim_state, &xonly(&challenger), &xonly(&challenger))
            .sign(HotSigner::new(challenger)),
    ])?;
    println!("  user 2 disputes their own delegation (bond: {} sats)", BOND);

    let dc: DelegationChallengeHandle = children[0].clone().try_into().unwrap();
    let children = dc
        .defend(&delegations[2])
        .output_amount(0, Amount::from_sat((BOND / 2) as u64))
        .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))
        .exec(&mut stage.manager)?;
    let resumed: PendingExitHandle = children[2].clone().try_into().unwrap();
    assert_eq!(resumed.state().unwrap(), claim_state);
    println!(
        "  Ingrid reveals user 2's delegation signature (verified with OP_CHECKSIGFROMSTACK):"
    );
    println!(
        "  she pockets {} sats, {} are burned, and the claim resumes.",
        BOND / 2,
        BOND - BOND / 2,
    );

    stage.mine(stage.params.challenge_period, "no further challenge")?;
    resumed
        .finalize()
        .output_amount(0, Amount::from_sat((honest.x + BOND) as u64))
        .exec(&mut stage.manager)?;
    println!("  Ingrid finalizes: {} sats out.", honest.x + BOND);
    Ok(())
}

fn scenario_delegation_timeout(wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== delegation-timeout: Ingrid claims for user 3, who never delegated ===");
    let mut stage = Stage::new(wallet)?;
    let mut bits = exit_bits();
    bits[3] = true;
    let claim = compute_claim(&stage.pool, &bits);
    let (pending, claim_state) = stage.claim(&claim)?;

    let challenger = user_xpriv(3);
    let cbond = stage.bond_for(&challenger)?;
    let children = stage.manager.spend_batch(&[
        pending.challenge_delegation(&stage.pool, &claim.bits, 3, &xonly(&challenger)),
        cbond
            .stake_delegation_challenge(&claim_state, &xonly(&challenger), &xonly(&challenger))
            .sign(HotSigner::new(challenger.clone())),
    ])?;
    println!("  user 3 disputes their delegation (bond: {} sats)", BOND);

    stage.mine(stage.params.response_timeout, "Ingrid has no signature to reveal")?;
    let dc: DelegationChallengeHandle = children[0].clone().try_into().unwrap();
    let children = dc
        .challenger_wins()
        .output_amount(0, Amount::from_sat((BOND + BOND / 2) as u64))
        .output_amount(1, Amount::from_sat((BOND - BOND / 2) as u64))
        .exec(&mut stage.manager)?;
    let reverted: UnwindHandle = children[2].clone().try_into().unwrap();
    assert_eq!(reverted.state().unwrap().root, stage.pool.root());
    println!(
        "  user 3 collects {} sats (their bond back + half of Ingrid's), {} sats are burned,",
        BOND + BOND / 2,
        BOND - BOND / 2,
    );
    println!("  and the withdrawal is reverted: the pool holds its full {POOL_TOTAL} sats again.");
    Ok(())
}

// ============================================================================
// Entry point
// ============================================================================

const SCENARIOS: [(&str, fn(&str) -> Result<(), Box<dyn std::error::Error>>); 6] = [
    ("direct", scenario_direct),
    ("happy", scenario_happy),
    ("fraud", scenario_fraud),
    ("false-challenge", scenario_false_challenge),
    ("delegation-defend", scenario_delegation_defend),
    ("delegation-timeout", scenario_delegation_timeout),
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut wallet = "testwallet".to_string();
    let mut selected: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" if i + 1 < args.len() => {
                wallet = args[i + 1].clone();
                i += 2;
            }
            "--scenario" if i + 1 < args.len() => {
                selected = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!(
                    "usage: aggregate_exits [--wallet <name>] [--scenario all|{}]",
                    SCENARIOS.map(|(n, _)| n).join("|")
                );
                std::process::exit(2);
            }
        }
    }

    let selected = selected.unwrap_or_else(|| "all".to_string());
    let to_run: Vec<_> = SCENARIOS
        .iter()
        .filter(|(name, _)| selected == "all" || selected == *name)
        .collect();
    if to_run.is_empty() {
        eprintln!(
            "unknown scenario `{selected}`; expected all|{}",
            SCENARIOS.map(|(n, _)| n).join("|")
        );
        std::process::exit(2);
    }

    for (name, run) in to_run {
        if let Err(e) = run(&wallet) {
            eprintln!("scenario `{name}` failed: {e}");
            std::process::exit(1);
        }
    }
    println!("\nAll scenarios completed.");
}
