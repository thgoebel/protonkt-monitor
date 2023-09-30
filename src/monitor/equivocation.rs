use crate::ct_api::{CtApi, CtCert};
use crate::ct_domains::{find_full_domain, FullDomain, ShortDomain};
use crate::data::Data;
use crate::proton_api::ProtonApi;
use crate::utils::ToSha256Bytes;
use crate::Sha256Bytes;
use crate::KT_VERSION;
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use thiserror::Error;
extern crate time;
use time::OffsetDateTime;

const TIME_24_HOURS_IN_SEC: u64 = 24 * 60 * 60;
const EMPTY_THRESHOLD: usize = 5;

/// Monitor for equivocation of the tree.
///
/// This is done by scanning Certificate Transparency (CT) for the committed
/// tree root hashes of each epoch.
///
/// It also checks that the tree root hashes are correctly chained across epochs.
/// I.e. that `chain_hash = h(prev_chain_hash || root_hash)`.
pub struct EquivocMonitor<T>
where
    T: CtApi,
{
    ct_api: T,
    proton_api: ProtonApi,
}

#[derive(Debug, Error)]
pub enum EquivocationError {
    #[error("Conflicting FullDomains found in CT")]
    ConflictingFullDomainsFound,
    #[error("ChainHashes don't match")]
    ChainHashesDontMatch { computed: String, logged: String },
}

impl<T> EquivocMonitor<T>
where
    T: CtApi,
{
    pub fn new(ct_api: T) -> Self {
        EquivocMonitor {
            ct_api,
            proton_api: ProtonApi::new(),
        }
    }

    /// Runs the equivocation monitor, starting at the given `from_epoch_id` and until the latest epoch.
    pub async fn run(
        &self,
        data: &mut Data,
        from_epoch_id: u64,
        prev_from_chain_hash: Sha256Bytes,
    ) -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::now_utc();
        let mut current_epoch = from_epoch_id;
        let mut current_not_before: OffsetDateTime = now.clone();
        let mut prev_chain_hash = prev_from_chain_hash;

        let mut empty_count: usize = 0;

        loop {
            let short_domain = ShortDomain::new(current_epoch, KT_VERSION);
            info!(
                "Checking {} \t (previous epoch was at {}) ...",
                &short_domain.string_repr, current_not_before
            );

            let certs = self.ct_api.get_certs_for_epoch(current_epoch).await?;

            if certs.is_empty() {
                // This is legal. Epochs need to be increasing, but the server may skip epochs.
                // THIS CAN ALSO HAPPEN FOR RECENT EPOCHS WITH crt.sh DUE TO ITS SLOW INTAKE.
                // TODO: how do we handle this? allow re-running the entire monitor for past epochs?
                warn!("No cert logged in CT for epoch {}!", current_epoch);
                if empty_count > EMPTY_THRESHOLD {
                    info!("Too many empty epochs. Stopping.");
                    break;
                }

                // XXX: how to advance the chain hash in this case?
                empty_count += 1;
                current_epoch += 1;
                continue;
            }
            empty_count = 0;

            // There may be multiple certificates logged containing the same data.
            // This can happen e.g. if both the pre-certificate and the leaf certificate are logged.
            // De-duplicate them ONLY based on their FullDomain, because this is the critical info (chain hash) that we care about.
            // Don't duplicate them based on other values (such as CommonName or serial number)!
            let mut full_domains: HashSet<FullDomain> = HashSet::new();

            // Check all logged certs
            for cert in certs.iter() {
                let x509 = cert.x509();
                let san = x509.subject_alternative_name()?;
                let san = match san {
                    Some(san) => san,
                    None => {
                        info!(
                            "No SubjectAlternativeExtension found in X.509 cert with id {}",
                            cert.id
                        );
                        continue;
                    }
                };
                let san = san.value;

                let full_domain = find_full_domain(&short_domain, &san)?;
                full_domains.insert(full_domain);
            }

            let fd = match full_domains.len() {
                0 => {
                    warn!(
                        "Epoch {} has certificates in CT, but non contains a ChainHash",
                        current_epoch
                    );
                    empty_count += 1;
                    current_epoch += 1;
                    continue;
                }
                1 => {
                    let fd = full_domains
                        .iter()
                        .next()
                        .expect("should have exactly 1 element");
                    info!("One FullDomain found: {}", fd.string_repr);
                    fd
                }
                _ => {
                    error!(
                        "Conflicting certificates with conflicting FullDomains found: {:?}",
                        full_domains
                    );
                    return Err(Box::new(EquivocationError::ConflictingFullDomainsFound));
                }
            };

            // Check correct chaining
            let (_root_hash, chain_hash) = self
                .check_hash_chaining(current_epoch, &prev_chain_hash, &fd.chain_hash)
                .await?;

            // Check certificate issuance times against alleged epoch issuance time (as persisted in FullDomain)
            for cert in certs {
                current_not_before = check_cert_issued_with_epoch(&cert, fd.issuance_time);
            }

            // TODO: persist epoch data

            // Continue to next epoch
            prev_chain_hash = chain_hash;
            current_epoch += 1;

            if current_epoch % 5 == 0 {
                data.save()?;
            }
        }

        info!(
            "Checked all epochs up to and including epoch {}",
            current_epoch - 1
        );

        // Warn if the last epoch was not recent
        let is_epoch_not_recent = (now - current_not_before).abs() > time::Duration::hours(24);
        if is_epoch_not_recent {
            warn!(
                "The last epoch {} has notBefore {} but the current time is {}",
                current_epoch, current_not_before, now
            )
        }
        data.save()?;
        Ok(())
    }

    /// Checks whether two epochs are correctly chained.
    ///
    /// The rootHash is fetched from the Proton API.
    /// The logged_chain_hash was fetched from CT.
    /// The hash chain is reconstructed starting at the hardcoded chain_hash.
    ///
    /// Returns owned versions of the root hash and new, now verified, chain_hash.
    async fn check_hash_chaining(
        &self,
        current_epoch: u64,
        prev_chain_hash: &Sha256Bytes,
        logged_chain_hash: &Sha256Bytes,
    ) -> Result<(Sha256Bytes, Sha256Bytes), Box<dyn Error>> {
        let epoch = self.proton_api.get_epoch(current_epoch).await?;
        let root_hash = &epoch.tree_hash.to_sha256_bytes()?;

        // Compute: new_chain_hash = hash( prev_chain_hash || root_hash )
        let mut hasher = Sha256::new();
        hasher.update(prev_chain_hash);
        hasher.update(root_hash);
        let computed_chain_hash = hasher.finalize(); // GenericArray<u8, Self::OutputSize>
        let computed_chain_hash: Sha256Bytes = computed_chain_hash
            .as_slice()
            .try_into()
            .expect("wrong SHA256 output size");

        if &computed_chain_hash != logged_chain_hash {
            let computed = hex::encode(computed_chain_hash);
            let logged = hex::encode(logged_chain_hash);
            error!(
                "Chain hashs differ! computed={} <--> inCT={}",
                computed, logged,
            );
            return Err(Box::new(EquivocationError::ChainHashesDontMatch {
                computed,
                logged,
            }));
        }
        Ok((root_hash.clone(), computed_chain_hash))
    }
}

/// Checks that the certificate was issued together with the epoch.
/// I.e. checks that notBefore and the issuanceTime are close together.
///
/// XXX: This is important for the client, but not really for the auditor.
/// Thus not raising an error, only logging it.
fn check_cert_issued_with_epoch(cert: &CtCert, issuance_time: u64) -> OffsetDateTime {
    let not_before = cert.x509().validity().not_before;

    // signed int because the difference could be negative
    let delta: i64 = not_before.timestamp() - (issuance_time as i64);
    let delta_abs: u64 = delta.abs() as u64;

    if delta_abs > TIME_24_HOURS_IN_SEC {
        warn!(
            "Certificate was issued more than 24 hours away from epoch (cert id={})",
            cert.id
        );
    }
    not_before.to_datetime()
}
