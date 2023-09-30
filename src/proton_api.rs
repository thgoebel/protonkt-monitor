use log::debug;
use serde::Deserialize;
use thiserror::Error;

const BASE_URL: &str = "https://mail-api.proton.me/";

/// A ProtonApi client.
pub struct ProtonApi {
    client: reqwest::Client,
}

/// Response to calling "kt/v1/epochs/{epochId}".
// Implementation note: the hashes are String and not Sha256Hex because they are not validated (for correct hex and correct length).
#[allow(unused)]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KtEpochResponse {
    code: u64,
    #[serde(rename = "EpochID")]
    epoch_id: u64,
    pub tree_hash: String,
    chain_hash: String,
    claimed_time: u64,
    certificate: String, // x509
    certificate_issuer: u8,
    certificate_time: u64,
    domain: String,
    #[serde(rename = "StartEpochID")]
    start_epoch_id: u64,
    prev_chain_hash: String,
}

/// Errors that can occur during network calls to the ProtonApi.
#[derive(Debug, Error)]
pub enum ProtonApiError {
    #[error("network request failed to create a response: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("got a response but status code was {0}")]
    RequestNotSuccessful(reqwest::StatusCode),
    #[error("failed to deserialise the response: {0}")]
    Deserialize(#[from] serde_json::Error),
}

impl ProtonApi {
    pub fn new() -> ProtonApi {
        ProtonApi {
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_epoch(&self, epoch_id: u64) -> Result<KtEpochResponse, ProtonApiError> {
        let url = format!("{}kt/v1/epochs/{}", BASE_URL, epoch_id);
        debug!("Querying {}", url);
        let response = self.client.get(url).send().await?;

        if response.status() != 200 {
            return Err(ProtonApiError::RequestNotSuccessful(response.status()));
        }

        let body = response.bytes().await?;
        let kt_epoch: KtEpochResponse = serde_json::from_slice(&body)?;
        Ok(kt_epoch)
    }
}
