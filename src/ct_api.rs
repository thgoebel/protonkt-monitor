//! APIs to query different Certificate Transparency (CT) databases
//! and look up logged certificates by domain name.

use crate::{DerBytes, KT_BASE_DOMAIN, KT_VERSION};
use async_trait::async_trait;
use base64::{engine::general_purpose as b64, Engine as _};
use log::error;
use serde::Deserialize;
use serde_json;
use thiserror::Error;

/* ------- TRAITS ------- */

#[derive(Debug)]
pub struct CtCert {
    /// An id for this cert, assigned the CT scanning service (crt.sh/CertSpotter).
    /// Useful for debugging.
    pub id: String,

    /// The actual certificate
    pub der: DerBytes,
}

/// Interface to access Certificate Transparency (CT) logs.
/// Different providers can implement this trait.
#[async_trait]
pub trait CtApi {
    /// Lookup and return the DER-encoded certificates that are logged in CT for this epoch.
    ///
    /// If no certs are logged, an empty Vector is returned.
    async fn get_certs_for_epoch(&self, epoch_id: u64) -> Result<Vec<CtCert>, GetCertsError>;
}

/// The different errors that can occur during [`CtApi::get_certs_for_epoch`].
#[derive(Error, Debug)]
pub enum GetCertsError {
    #[error("network request failed to create a response")]
    NetworkError(#[from] reqwest::Error),
    #[error("got a response but status code was")]
    RequestNotSuccessful(String, reqwest::StatusCode),
    #[error("failed to deserialise the response")]
    Deserialize(#[from] serde_json::Error),
    #[error("API specific error")]
    ApiError(String),
    #[error("PEM decode failed: {0}")]
    PemDecodeError(#[from] pem_rfc7468::Error),
}

/* ------- crt.sh ------- */

/// CT Log lookups using crt.sh
pub struct CrtShApi {
    client: reqwest::Client,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct CrtShItem {
    id: u64,
    common_name: String,
    serial_number: String,
    // other fields omitted
}

impl CrtShApi {
    #[allow(unused)]
    pub fn new() -> CrtShApi {
        CrtShApi {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl CtApi for CrtShApi {
    async fn get_certs_for_epoch(&self, epoch_id: u64) -> Result<Vec<CtCert>, GetCertsError> {
        let search_domain = format!("epoch.{epoch_id}.{KT_VERSION}.{KT_BASE_DOMAIN}");
        let url = format!("https://crt.sh/?Identity={search_domain}&output=json");

        let response = self.client.get(&url).send().await?;
        if response.status() != 200 {
            return Err(GetCertsError::RequestNotSuccessful(url, response.status()));
        }
        let body = response.bytes().await?;

        let items: Vec<CrtShItem> = serde_json::from_slice(&body)?;

        // Note: if both the precertificate and the leaf certificate are logged,
        // there will be two entries with the same serial number,
        // i.e. probably/hopefully the same certificate.
        // To protect against CT failures, where different certificates have the same serial number,
        // we do NOT de-duplicate these!
        // Even though it would be easy with `iter().unique_by(|i| i.serial_number)`.)

        let mut certs = vec![];
        for item in &items {
            let url = format!("https://crt.sh/?d={}", item.id);

            let response = self.client.get(&url).send().await?;
            if response.status() != 200 {
                return Err(GetCertsError::RequestNotSuccessful(url, response.status()));
            }
            let pem = response.bytes().await?;

            let (label, der) = pem_rfc7468::decode_vec(&pem)?;
            assert_eq!(label, "CERTIFICATE");

            certs.push(CtCert {
                id: item.id.to_string(),
                der,
            })
        }
        return Ok(certs);
    }
}

#[cfg(test)]
mod tests_crt_sh {
    use super::{CrtShApi, CtApi};

    #[tokio::test]
    async fn basic() {
        let api = CrtShApi::new();
        let certs = api.get_certs_for_epoch(321).await.unwrap();
        let mut cert_ids: Vec<String> = certs.into_iter().map(|c| c.id).collect();
        cert_ids.sort();
        assert_eq!(cert_ids, vec!["10232277493", "10232277526"]); // precert and cert
    }
}

/* ------- CertSpotter/SSLMate ------- */

/// CT Log lookups using [SSLMate's Cert Spotter](https://sslmate.com/ct_search_api/).
///
/// Note that there is a rate limit of 100 single-hostname queries per hour.
/// TODO: Implement using your own API key to overcome this limit.
pub struct CertSpotterApi {
    client: reqwest::Client,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
struct CertSpotterItem {
    id: String,
    tbs_sha256: String,
    cert_sha256: String,
    dns_names: Vec<String>,
    pubkey_sha256: String,
    //issuer: ,
    not_before: String,
    not_after: String,
    revoked: bool,
    #[serde(rename = "cert_der")]
    cert_der_b64: String,
}

/// CertSpotter API errors
///
/// Example:
///
/// > {"code":"rate_limited","message":"You have exceeded the domain search rate limit for the SSLMate CT Search API.
/// > Please try again later, or authenticate with an API key, which you can obtain by signing up at <https://sslmate.com/signup?for=ct_search_api>."}
#[allow(unused)]
#[derive(Deserialize, Debug)]
struct CertSpotterError {
    code: String,
    message: String,
}

impl CertSpotterApi {
    #[allow(unused)]
    pub fn new() -> CertSpotterApi {
        CertSpotterApi {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl CtApi for CertSpotterApi {
    async fn get_certs_for_epoch(&self, epoch_id: u64) -> Result<Vec<CtCert>, GetCertsError> {
        let search_domain = format!("epoch.{epoch_id}.{KT_VERSION}.{KT_BASE_DOMAIN}");
        let url = format!("https://api.certspotter.com/v1/issuances?domain={search_domain}&expand=dns_names&expand=cert_der");

        let response = self.client.get(&url).send().await?;
        if response.status() != 200 {
            return Err(GetCertsError::RequestNotSuccessful(url, response.status()));
        }
        let body = response.bytes().await?;

        let items: Result<Vec<CertSpotterItem>, serde_json::Error> = serde_json::from_slice(&body);

        let items: Vec<CertSpotterItem> = match items {
            Ok(its) => its,
            Err(e) => {
                error!("Failed decoding into Vec<CertSpotterItem>: {:?}", e);
                // try decoding into the error struct
                let api_err: CertSpotterError = serde_json::from_slice(&body)?;
                return Err(GetCertsError::ApiError(
                    format! {"CertSpotter API: {:?}", api_err},
                ));
            }
        };

        let certs: Vec<CtCert> = items
            .into_iter()
            .map(|i| (i.id, b64::STANDARD.decode(i.cert_der_b64)))
            .filter_map(|(id, res)| match res {
                Ok(der) => Some(CtCert { id, der }),
                Err(e) => {
                    error!("Failed decoding as base64: {:?}", e);
                    None
                }
            })
            .collect();
        Ok(certs)
    }
}

#[cfg(test)]
mod tests_certspotter {
    use super::{CertSpotterApi, CtApi};

    #[tokio::test]
    async fn basic() {
        let api = CertSpotterApi::new();
        let certs = api.get_certs_for_epoch(321).await.unwrap();
        let mut cert_ids: Vec<String> = certs.into_iter().map(|c| c.id).collect();
        cert_ids.sort();
        assert_eq!(cert_ids, vec!["5675842909"]); // only the cert
    }
}
