//! Data dir layout:
//!
//! ```
//! config.json
//! epochs.json
//! certs/
//!   |- 420/serialnumber1.pem
//!   |- 420/serialnumber2.pem
//!   |- 421/serialnumber.pem
//!   \- 422/serialnumber.pem
//! ```

use crate::{ct_domains::FullDomain, Sha256Bytes, KT_BASE_DOMAIN, KT_VERSION};
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_with::serde_as;
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

const CONFIG_FILE: &str = "config.json";
const EPOCHS_FILE: &str = "epochs.json";

/// Collection of all (important) data in the data dir
#[derive(Default, Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Data {
    pub data_dir: PathBuf,
    pub config: Config,
    pub epochs: EpochEvidence,
}

/// Config for this data dir, the `config.json`.
///
/// This is used to allow data dirs for different environments
/// (different KT versions, different base urls).
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Config {
    pub base_url: String,
    pub kt_version: u8,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            base_url: KT_BASE_DOMAIN.to_owned(),
            kt_version: KT_VERSION,
        }
    }
}

/// The `epochs.json`.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct EpochEvidence {
    /// A map from epoch ids to a list of evidence items
    pub epochs: HashMap<u64, Vec<EpochEvidenceItem>>,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Copy)]
pub struct EpochEvidenceItem {
    pub issuance_time: u64,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub root_hash: Sha256Bytes,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub prev_chain_hash: Sha256Bytes,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub chain_hash: Sha256Bytes,
}

// 4fc86e6a14a64896cb021465eea370ac.1f670a3f3cc3478551e3bfc5ef0a25ec.1694508915.500.1.keytransparency.ch
// e57671c0a3bb874026a205ad1c3e27bd.2c3cd0b0c7d68e51e3405056aa18f9cb.1694524028.501.1.keytransparency.ch
pub const DEFAULT_START_EPOCH: u64 = 501;
pub const DEFAULT_START_EPOCH_EVIDENCE_ITEM: EpochEvidenceItem = EpochEvidenceItem {
    issuance_time: 1694524028,
    root_hash: hex!("5192335fae10d6b5f97b0bb63f5c784edb82f7e924ec76daa1b54c1ac2bae361"),
    prev_chain_hash: hex!("4fc86e6a14a64896cb021465eea370ac1f670a3f3cc3478551e3bfc5ef0a25ec"),
    chain_hash: hex!("e57671c0a3bb874026a205ad1c3e27bd2c3cd0b0c7d68e51e3405056aa18f9cb"),
};

impl Default for EpochEvidence {
    fn default() -> Self {
        EpochEvidence {
            epochs: HashMap::from([(DEFAULT_START_EPOCH, vec![DEFAULT_START_EPOCH_EVIDENCE_ITEM])]),
        }
    }
}

/// Load the files from the data dir
pub fn load_data(data_dir: PathBuf) -> Result<Data, Box<dyn Error>> {
    std::fs::create_dir_all(&data_dir)?;

    let config_path = data_dir.join(CONFIG_FILE);
    let epochs_path = data_dir.join(EPOCHS_FILE);

    let config: Config = if config_path.exists() {
        let file = File::open(config_path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader)?
    } else {
        Config::default()
    };

    let epochs: EpochEvidence = if epochs_path.exists() {
        let file = File::open(epochs_path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader)?
    } else {
        EpochEvidence::default()
    };

    Ok(Data {
        data_dir,
        config,
        epochs,
    })
}

impl Data {
    fn config_path(&self) -> PathBuf {
        self.data_dir.join(CONFIG_FILE)
    }
    fn epochs_path(&self) -> PathBuf {
        self.data_dir.join(EPOCHS_FILE)
    }

    /// Write the data out to disk
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let file = File::create(self.config_path())?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.config)?;

        let file = File::create(self.epochs_path())?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.epochs)?;

        Ok(())
    }
}

impl EpochEvidence {
    /// The latest epoch stored in the epochs.json
    pub fn latest_epoch(&self) -> Option<(&u64, &Vec<EpochEvidenceItem>)> {
        if let Some(max) = self.epochs.keys().max() {
            return self.epochs.get_key_value(max);
        }
        None
    }

    /// Create an EpochEvidenceItem from the provided parameters
    /// and insert it into the epochs.json (if it does not yet exist).
    pub fn insert(
        &mut self,
        full_domain: &FullDomain,
        root_hash: Sha256Bytes,
        prev_chain_hash: Sha256Bytes,
    ) {
        if !self.epochs.contains_key(&full_domain.epoch_id) {
            self.epochs.insert(full_domain.epoch_id, vec![]);
        }
        let items: &mut Vec<EpochEvidenceItem> = self
            .epochs
            .get_mut(&full_domain.epoch_id)
            .expect("key should exist by now");

        let ev = EpochEvidenceItem {
            issuance_time: full_domain.issuance_time,
            root_hash: root_hash,
            prev_chain_hash: prev_chain_hash,
            chain_hash: full_domain.chain_hash,
        };
        if !items.contains(&ev) {
            items.push(ev);
        }
    }
}
