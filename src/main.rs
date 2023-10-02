use crate::ct_api::CrtShApi;
use clap::Parser;
use itertools::Itertools;
use log::{error, info};
use std::{error::Error, path::PathBuf, process::ExitCode};
use utils::ToSha256Bytes;

mod ct_api;
mod ct_domains;
mod data;
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

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Directory to persist monitoring data in, and to read existing monitoring data from
    data_dir: PathBuf,

    /// Override the epoch id from which to start the monitoring
    #[arg(short = 'f', long)]
    from_epoch: Option<u64>,

    /// Override the hex-encoded PrevChainHash of the FROM_EPOCH (== the ChainHash of FROM_EPOCH-1)
    #[arg(short = 'p', long, value_parser = validate_hash)]
    prev_chain_hash: Option<Sha256Bytes>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn validate_hash(s: &str) -> Result<Sha256Bytes, String> {
    match s.to_sha256_bytes() {
        Ok(hash) => Ok(hash),
        Err(e) => Err(format!("Not a hex-encoded SHA-256 hash: {}", e)),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();

    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();
    info!("Running ProtonKT monitor...");

    // Load the cached data
    let res = data::load_data(args.data_dir.clone());
    let mut data = match res {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to load data: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let res = get_start_epoch(&args, &data);
    let (from_epoch, prev_from_chain_hash) = match res {
        Ok(data) => data,
        Err(_) => {
            return ExitCode::FAILURE;
        }
    };
    info!(
        "Starting monitor at epoch {} with PrevChainHash {}",
        from_epoch,
        hex::encode(prev_from_chain_hash)
    );

    let ct_api = CrtShApi::new();
    let monitor = monitor::equivocation::EquivocMonitor::new(ct_api);
    let res = monitor
        .run(&mut data, from_epoch, prev_from_chain_hash)
        .await;

    if let Err(e) = data.save() {
        error!("Failed to save data: {}", e);
        return ExitCode::FAILURE;
    }

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

/// Find the epoch id to start monitoring from, and the respective PrevChainHash
fn get_start_epoch(args: &Cli, data: &data::Data) -> Result<(u64, Sha256Bytes), Box<dyn Error>> {
    // User chose an epoch id to start from
    if let Some(override_epoch) = args.from_epoch {
        // User also chose a PrevChainHash to override whatever may be in epochs.json
        if let Some(override_prev_chain_hash) = args.prev_chain_hash {
            return Ok((override_epoch, override_prev_chain_hash));
        }

        // Try find a PrevChainHash from epochs.json for override_epoch
        if let Some(evidence_items) = data.epochs.epochs.get(&override_epoch) {
            let hashes: Vec<Sha256Bytes> = evidence_items
                .iter()
                .map(|i| i.prev_chain_hash)
                .unique()
                .collect();

            if hashes.len() == 1 {
                let stored_prev_chain_hash = hashes.first().unwrap().clone();
                return Ok((override_epoch, stored_prev_chain_hash));
            }
        }

        // Try find a ChainHash from epochs.json for override_epoch-1
        if let Some(evidence_items) = data.epochs.epochs.get(&(override_epoch - 1)) {
            let hashes: Vec<Sha256Bytes> = evidence_items
                .iter()
                .map(|i| i.chain_hash)
                .unique()
                .collect();

            if hashes.len() == 1 {
                let stored_prev_chain_hash = hashes.first().unwrap().clone();
                return Ok((override_epoch, stored_prev_chain_hash));
            }
        }

        error! {
                "Cannot start from chosen epoch {} because no suitable PrevChainHash for epoch {} was found in epochs.json. \
                Either there is none, or there are conflicting ones. \
                You can manually choose a chain hash to start from by passing --prev-chain-hash.",
                override_epoch, override_epoch-1
        };
        return Err("No PrevChainHash".into());
    }
    // User did not pass any CLI flags. Get the start epoch from the data/epochs.json.
    else {
        if let Some((id, evidence_items)) = data.epochs.latest_epoch() {
            let epoch_id = id.clone();

            // User chose a PrevChainHash to override whatever may be in epochs.json
            if let Some(override_prev_chain_hash) = args.prev_chain_hash {
                return Ok((epoch_id, override_prev_chain_hash));
            }

            // Use the PrevChainHash from epochs.json
            if evidence_items.len() == 1 {
                let prev_chain_hash = evidence_items.iter().next().unwrap().prev_chain_hash;
                return Ok((epoch_id, prev_chain_hash));
            }
            error! {
                    "Cannot start from latest epoch {} because no EpochEvidenceItems exist for epoch {} or they are conflicting. \
                    Thus it is undefined where to start the hash chain. \
                    You can manually choose a chain hash to start from by passing --prev-chain-hash.",
                    epoch_id, epoch_id-1
            };
            return Err("No PrevChainHash".into());
        }

        error!("No latest epoch to start from found in epochs.json. Try passing one with --from-epoch and --prev-chain-hash.");
        Err("No latest epoch".into())
    }
}

#[cfg(test)]
mod test_get_start_epoch {
    use super::*;
    use hex_literal::hex;

    const DUMMY_HASH: Sha256Bytes =
        hex!("e57671c0a3bb874026a205ad1c3e27bd2c3cd0b0c7d6aaaaaaaaaaaaaaaaaaaa");

    fn build_input(
        from_epoch: Option<u64>,
        prev_chain_hash: Option<Sha256Bytes>,
    ) -> (Cli, data::Data) {
        let data_dir = PathBuf::from("/tmp/pktdata");

        let args = Cli {
            data_dir: data_dir.clone(),
            from_epoch,
            prev_chain_hash,
            verbose: false,
        };
        let config = data::Config::default();
        let epochs = data::EpochEvidence::default();
        let data = data::Data {
            data_dir,
            config,
            epochs,
        };
        return (args, data);
    }

    #[test]
    fn no_override_flags() {
        let hash = data::DEFAULT_START_EPOCH_EVIDENCE_ITEM.prev_chain_hash;
        let (args, data) = build_input(None, None);

        let res = get_start_epoch(&args, &data);
        assert!(res.is_ok());
        let (out_epoch, out_prev_chain_hash) = res.unwrap();
        assert_eq!(out_epoch, data::DEFAULT_START_EPOCH);
        assert_eq!(out_prev_chain_hash, hash);
    }

    #[test]
    fn override_from_epoch_pch() {
        let epoch = data::DEFAULT_START_EPOCH;
        let hash = data::DEFAULT_START_EPOCH_EVIDENCE_ITEM.prev_chain_hash;
        let (args, data) = build_input(Some(epoch), None);

        let res = get_start_epoch(&args, &data);
        assert!(res.is_ok());
        let (out_epoch, out_prev_chain_hash) = res.unwrap();
        assert_eq!(out_epoch, epoch);
        assert_eq!(out_prev_chain_hash, hash);
    }

    #[test]
    fn override_from_epoch_ch() {
        let epoch = data::DEFAULT_START_EPOCH + 1;
        let hash = data::DEFAULT_START_EPOCH_EVIDENCE_ITEM.chain_hash;
        let (args, data) = build_input(Some(epoch), None);

        let res = get_start_epoch(&args, &data);
        assert!(res.is_ok());
        let (out_epoch, out_prev_chain_hash) = res.unwrap();
        assert_eq!(out_epoch, epoch);
        assert_eq!(out_prev_chain_hash, hash);
    }

    #[test]
    fn override_prev_chain_hash() {
        let hash = DUMMY_HASH;
        let (args, data) = build_input(None, Some(hash));

        let res = get_start_epoch(&args, &data);
        assert!(res.is_ok());
        let (out_epoch, out_prev_chain_hash) = res.unwrap();
        assert_eq!(out_epoch, 501);
        assert_eq!(out_prev_chain_hash, hash);
    }

    #[test]
    fn override_both() {
        let epoch = 42;
        let hash = DUMMY_HASH;
        let (args, data) = build_input(Some(epoch), Some(hash));

        let res = get_start_epoch(&args, &data);
        assert!(res.is_ok());
        let (out_epoch, out_prev_chain_hash) = res.unwrap();
        assert_eq!(out_epoch, epoch);
        assert_eq!(out_prev_chain_hash, hash);
    }

    #[test]
    fn override_from_epoch_with_unknown_epoch() {
        let epoch = 42;
        let (args, data) = build_input(Some(epoch), None);

        let res = get_start_epoch(&args, &data);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "No PrevChainHash");
    }

    #[test]
    fn empty_data_no_override() {
        let (args, mut data) = build_input(None, None);
        data.epochs.epochs.clear();

        let res = get_start_epoch(&args, &data);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "No latest epoch");
    }

    #[test]
    fn empty_data_override() {
        let epoch = data::DEFAULT_START_EPOCH;
        let hash = data::DEFAULT_START_EPOCH_EVIDENCE_ITEM.prev_chain_hash;
        let (args, mut data) = build_input(Some(epoch), Some(hash));
        data.epochs.epochs.clear();

        let res = get_start_epoch(&args, &data);
        assert!(res.is_ok());
        let (out_epoch, out_prev_chain_hash) = res.unwrap();
        assert_eq!(out_epoch, epoch);
        assert_eq!(out_prev_chain_hash, hash);
    }

    #[test]
    fn conflicting_hash_no_override() {
        let (args, mut data) = build_input(None, None);

        let mut conflict = data::DEFAULT_START_EPOCH_EVIDENCE_ITEM.clone();
        conflict.prev_chain_hash = DUMMY_HASH;
        data.epochs
            .epochs
            .get_mut(&data::DEFAULT_START_EPOCH)
            .unwrap()
            .push(conflict);

        let res = get_start_epoch(&args, &data);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "No PrevChainHash");
    }

    #[test]
    fn conflicting_hash_override() {
        let epoch = data::DEFAULT_START_EPOCH;
        let hash = data::DEFAULT_START_EPOCH_EVIDENCE_ITEM.prev_chain_hash;
        let (args, mut data) = build_input(Some(epoch), Some(hash));

        let mut conflict = data::DEFAULT_START_EPOCH_EVIDENCE_ITEM.clone();
        conflict.prev_chain_hash = DUMMY_HASH;
        data.epochs
            .epochs
            .get_mut(&data::DEFAULT_START_EPOCH)
            .unwrap()
            .push(conflict);

        let res = get_start_epoch(&args, &data);
        assert!(res.is_ok());
        let (out_epoch, out_prev_chain_hash) = res.unwrap();
        assert_eq!(out_epoch, epoch);
        assert_eq!(out_prev_chain_hash, hash);
    }
}
