use bitcoincore_rpc::Client;

use crate::contracts::ContractInstance;

/// Manages contract instances. Works entirely with concrete types.
pub struct ContractManager<'a> {
    pub rpc: &'a Client,
    pub instances: Vec<ContractInstance>,
    pub poll_interval: f64,
    pub automine: bool,
}

impl<'a> ContractManager<'a> {
    pub fn new(rpc: &'a Client, poll_interval: f64, automine: bool) -> Self {
        Self {
            rpc,
            instances: vec![],
            poll_interval,
            automine,
        }
    }

    // TODO: fund_instance, spend_instance, wait_for_spend
    // These will be fleshed out when testing against regtest.
}
