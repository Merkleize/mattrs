#[path = "../examples/wallet_funding.rs"]
mod wallet_funding;

#[test]
#[ignore = "requires a running CCV-enabled regtest node and funded testwallet"]
fn external_wallet_funds_signs_and_observes_batch() -> Result<(), Box<dyn std::error::Error>> {
    wallet_funding::run().map(|_| ())
}
