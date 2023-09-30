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

use crate::{Sha256Bytes, KT_BASE_DOMAIN, KT_VERSION};
use serde::{Deserialize, Serialize};
use serde_json;
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
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct Data {
    base_dir: PathBuf,
    config: Config,
    epochs: EpochEvidence,
}

/// Config for this data dir, the `config.json`.
///
/// This is used to allow data dirs for different environments
/// (different KT versions, different base urls).
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    base_url: String,
    kt_version: u8,
}

/// The `epochs.json`.
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct EpochEvidence {
    /// A map from epoch ids to a list of evidence items
    epochs: HashMap<u64, Vec<EpochEvidenceItem>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EpochEvidenceItem {
    issuance_time: u64,
    root_hash: Sha256Bytes,
    prev_chain_hash: Sha256Bytes,
    chain_hash: Sha256Bytes,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            base_url: KT_BASE_DOMAIN.to_owned(),
            kt_version: KT_VERSION,
        }
    }
}

/// Load the files from the data dir
pub fn load_data(base_dir: PathBuf) -> Result<Data, Box<dyn Error>> {
    std::fs::create_dir_all(&base_dir)?;

    let config_path = base_dir.join(CONFIG_FILE);
    let epochs_path = base_dir.join(EPOCHS_FILE);

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
        base_dir,
        config,
        epochs,
    })
}

impl Data {
    fn config_path(&self) -> PathBuf {
        self.base_dir.join(CONFIG_FILE)
    }
    fn epochs_path(&self) -> PathBuf {
        self.base_dir.join(EPOCHS_FILE)
    }

    /// Write the data out to disk
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let file = File::create(self.config_path())?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &self.config)?;

        let file = File::create(self.epochs_path())?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &self.epochs)?;

        Ok(())
    }
}

