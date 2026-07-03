//! game256 fraud-proof challenge, end to end on a regtest node.
//!
//! Ports pymatt's `tests/test_fraud.py::test_fraud_proof_full`: Alice claims a
//! wrong result for the 8-step doubling computation, Bob challenges her, and
//! the bisection protocol narrows the dispute — every transition validated by
//! the node's script interpreter — down to the single step where Alice cheated,
//! which Bob wins by re-running it on-chain.

mod support;

use bitcoin::{Amount, TxOut};
use bitcoincore_rpc::RpcApi;
use mattrs::fraud::trace;
use mattrs::manager::ContractManager;
use mattrs::script_utils::{bn2vch, commit_int};
use mattrs::signer::HotSigner;
use support::game256::{
    Bisect1Handle, Bisect2Handle, G256Params, G256S0, G256S1Handle, G256S2Handle, LeafHandle,
};
use support::testkit::{alice_pk, alice_xpriv, bob_pk, bob_xpriv, regtest_client};

const AMOUNT: u64 = 20_000;

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_game256_fraud_challenge_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    // The claimed step values (x_0 .. x_8). Bob doubles honestly; Alice goes
    // wrong at step 6 (64 -> 127) and doubles consistently from there.
    let alice_vals: [i64; 9] = [2, 4, 8, 16, 32, 64, 127, 254, 508];
    let bob_vals: [i64; 9] = [2, 4, 8, 16, 32, 64, 128, 256, 512];
    let h_a: Vec<[u8; 32]> = alice_vals.iter().map(|&v| commit_int(v)).collect();
    let h_b: Vec<[u8; 32]> = bob_vals.iter().map(|&v| commit_int(v)).collect();
    let n = 8usize;

    let client = regtest_client("testwallet");
    let mut manager = ContractManager::new(client);
    let params = G256Params {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
    };

    // The game stages: Bob picks x, Alice claims y (fraudulently), Bob starts
    // the challenge with his own result z and trace commitment.
    let s0 = G256S0::new(params).fund(&mut manager, Amount::from_sat(AMOUNT))?;
    let s1: G256S1Handle = s0
        .choose(alice_vals[0])
        .sign(HotSigner::new(bob_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;

    let t_a = trace(&h_a, 0, n - 1);
    let t_b = trace(&h_b, 0, n - 1);
    let s2: G256S2Handle = s1
        .reveal(t_a, alice_vals[n], alice_vals[0])
        .sign(HotSigner::new(alice_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;

    let mut b1: Bisect1Handle = s2
        .start_challenge(t_a, alice_vals[n], alice_vals[0], bob_vals[n], t_b)
        .sign(HotSigner::new(bob_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;

    // The bisection rounds: at range [i, j], Alice reveals her midstate and
    // sub-traces (checked against her committed trace); Bob then recurses into
    // the half whose midstate they disagree on, until a single step remains.
    let (mut i, mut j) = (0usize, 7usize);
    let mut path = Vec::new();
    let leaf: LeafHandle = loop {
        // Half the (power-of-two) range size: the children cover [i, i+m-1]
        // and [i+m, j], and h[i+m] is the disputed midstate commitment.
        let size = j - i + 1;
        let m = size / 2;

        // The committed range endpoints and traces come from the instance
        // state; Alice only supplies her midstate and sub-traces.
        let b2: Bisect2Handle = b1
            .alice_reveal(
                h_a[i + m],
                trace(&h_a, i, i + m - 1),
                trace(&h_a, i + m, j),
            )?
            .sign(HotSigner::new(alice_xpriv()))
            .exec_one(&mut manager)?
            .try_into()?;

        let go_left = h_a[i + m] != h_b[i + m];
        path.push(if go_left { 'L' } else { 'R' });
        let builder = if go_left {
            b2.bob_reveal_left(h_b[i + m], trace(&h_b, i, i + m - 1), trace(&h_b, i + m, j))?
        } else {
            b2.bob_reveal_right(h_b[i + m], trace(&h_b, i, i + m - 1), trace(&h_b, i + m, j))?
        };
        let child = builder
            .sign(HotSigner::new(bob_xpriv()))
            .exec_one(&mut manager)?;

        if go_left {
            j = i + m - 1;
        } else {
            i += m;
        }
        if i == j {
            break child.try_into()?;
        }
        b1 = child.try_into()?;
    };

    // The dispute honed in on exactly the step where Alice cheated.
    assert_eq!(path, ['R', 'L', 'R']);
    assert_eq!((i, j), (5, 5));
    assert_eq!(alice_vals[i], bob_vals[i]);
    assert_ne!(alice_vals[i + 1], bob_vals[i + 1]);

    // Only honest Bob can re-run step 5 (64 -> 128) and take the pot.
    let dest = manager.rpc().get_new_address(None, None)?.assume_checked();
    leaf.bob_reveal(vec![bn2vch(bob_vals[i])])?
        .sign(HotSigner::new(bob_xpriv()))
        .outputs(vec![TxOut {
            script_pubkey: dest.script_pubkey(),
            value: Amount::from_sat(AMOUNT),
        }])
        .exec_none(&mut manager)?;

    Ok(())
}
