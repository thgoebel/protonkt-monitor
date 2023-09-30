use crate::ct_api::CrtShApi;
use lazy_static::lazy_static;
use log::{error, info};
use std::{collections::HashMap, process::ExitCode};

mod ct_api;
mod ct_domains;
mod monitor;
mod proton_api;
mod utils;

// Type aliases
pub type HexString = String;
pub type Sha256Bytes = [u8; 32];
pub type Sha256Hex = String;
pub type DerBytes = Vec<u8>;

const KT_VERSION: u8 = 1;
const KT_BASE_DOMAIN: &str = "keytransparency.ch";

lazy_static! {
    /// Known chain hahes.
    /// These are pinned as the start of the root hash chaining.
    static ref KNOWN_CHAIN_HASHES: HashMap<u64, Sha256Bytes> = HashMap::from([
        (
            99,
            hex_literal::hex!("816d2ad66bff2fd7d6e7f8b574e91d860dae7663244c82fbd6ef503bf512a54e"),
        ),
        (
            450,
            hex_literal::hex!("302f5bbe61547c1ef02ecae78e2fca4340111f52b1f462fbc4e06b9f23410b21"),
        ),
        (
            570,
            hex_literal::hex!("955058da866301be54930411cfac416fc387b399d02a7578c9474a494ae61ced"),
        ),
    ]);
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Running ProtonKT monitor...");

    let from_epoch = 451;
    let prev_from_chain_hash = KNOWN_CHAIN_HASHES
        .get(&(from_epoch - 1))
        .expect(&format!("epoch {} not hardcoded", from_epoch - 1))
        .clone();

    let ct_api = CrtShApi::new();
    let monitor = monitor::equivocation::EquivocMonitor::new(ct_api);
    let res = monitor.run(from_epoch, prev_from_chain_hash).await;

    match res {
        Ok(_) => {
            info!("Monitoring complete!");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("Monitoring failed: {}", e);
            ExitCode::FAILURE
        }
    }
}
