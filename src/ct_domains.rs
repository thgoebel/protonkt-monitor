use crate::Sha256Bytes;
use crate::KT_BASE_DOMAIN;
use hex::FromHexError;
use log::warn;
use std::{collections::HashSet, str::FromStr};
use thiserror::Error;
use x509_parser::prelude::*;

// Recall that the output size of SHA-256 is:
// 256 bit = 32 bytes = 64 hex chars

/// Short domains have this form:
/// `epoch.<epochid>.<ktversion>.keytransparency.ch`
pub struct ShortDomain {
    epoch_id: u64,
    kt_version: u8,
    base_domain: String,
    pub string_repr: String,
}

impl ShortDomain {
    pub fn new(epoch_id: u64, kt_version: u8) -> ShortDomain {
        let string_repr = format!("epoch.{}.{}.{KT_BASE_DOMAIN}", epoch_id, kt_version);
        ShortDomain {
            epoch_id,
            kt_version,
            string_repr,
            base_domain: KT_BASE_DOMAIN.to_owned(),
        }
    }
}

/// Full domains have this form:
/// `<chainhash[0:32]>.<chainhash[32:64]>.<issuancetime>.<epochid>.<ktversion>.keytransparency.ch`
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct FullDomain {
    pub chain_hash: Sha256Bytes,
    pub issuance_time: u64,
    pub epoch_id: u64,
    pub kt_version: u8,
    pub base_domain: String,
    pub string_repr: String,
}

impl FullDomain {
    fn matches_short_domain(&self, short_domain: &ShortDomain) -> bool {
        self.epoch_id == short_domain.epoch_id
            && self.kt_version == short_domain.kt_version
            && self.base_domain == short_domain.base_domain
    }
}

#[derive(Debug, Error)]
pub enum FullDomainParseError {
    #[error("NotEnoughParts")]
    NotEnoughParts,
    #[error("Probably a ShortDomain")]
    ProbablyShortDomain,
    #[error("BadChainHashLength: {0} (expected 64)")]
    BadChainHashLength(usize),
    #[error("Failed to decode chainhash as hex string")]
    HexDecodeFailed(#[from] FromHexError),
    #[error("Failed to parse an Int to String")]
    FromStringError(#[from] std::num::ParseIntError),
}

impl FromStr for FullDomain {
    type Err = FullDomainParseError;

    /// Parse a string into the FullDomain struct
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(".").collect();

        // These length checks assume that basedomain has >= 2 parts,
        // e.g. "example.com", which is reasonable because it needs to be a proper DNS name.
        if parts.len() == 5 && parts[0] == "epoch" {
            return Err(FullDomainParseError::ProbablyShortDomain);
        }
        if parts.len() < 7 {
            return Err(FullDomainParseError::NotEnoughParts);
        }

        let mut chain_hash = String::from(parts[0]);
        chain_hash.push_str(parts[1]);
        if chain_hash.len() != 64 {
            return Err(FullDomainParseError::BadChainHashLength(chain_hash.len()));
        }
        let chain_hash: Vec<u8> = hex::decode(chain_hash)?;
        let chain_hash: [u8; 32] = chain_hash
            .try_into()
            .expect("the pre hex-decode length check above should catch this");

        Ok(FullDomain {
            chain_hash,
            issuance_time: parts[2].parse()?,
            epoch_id: parts[3].parse()?,
            kt_version: parts[4].parse()?,
            // there may be more than 6 parts, e.g. if the domain is "dev.kt.ch" instead of "kt.ch"
            base_domain: parts[5..].join("."),
            string_repr: s.to_owned(),
        })
    }
}

#[derive(Debug, Error)]
pub enum FindFullDomainError {
    #[error("No full domain found in SAN")]
    NotFound,
    #[error("Conflicting full domains. See the logs.")]
    ConflictingFullDomain,
}

/// Search through the names in the SAN for a match with `target`.
///
/// This function only returns an error if something in the SAN conflicts with the target ShortDomain
/// (e.g. contradicting chain hashes, or no chain hash at all).
///
/// All other errors (a SAN item that fails to parse, a full domain for a different ShortDomain)
/// are logged as warnings but not propagated to the caller.
/// This is because these errors shouldn't allow for an equivocation on the target ShortDomain
/// (assuming no parsing errors/inconsistencies).
pub fn find_full_domain(
    target: &ShortDomain,
    subject_alternative_name: &SubjectAlternativeName,
) -> Result<FullDomain, FindFullDomainError> {
    let mut found_full_domains: HashSet<FullDomain> = HashSet::new();

    // Search through all names in the SAN
    for name in subject_alternative_name.general_names.iter() {
        match name {
            GeneralName::DNSName(hostname) => {
                // Case 1: the short domain (which is just a handle to search CT logs)
                if hostname == &target.string_repr {
                    continue;
                }

                let full_domain_res = FullDomain::from_str(hostname);
                match full_domain_res {
                    Ok(full_domain) => {
                        // Case 2: full domain for the target short domain (same epoch id + kt version + base domain)
                        if full_domain.matches_short_domain(target) {
                            found_full_domains.insert(full_domain);
                        }
                        // Case 3: some other full domain
                        else {
                            warn!(
                                "Found full domain {} that does not match the short domain {}",
                                full_domain.string_repr, target.string_repr
                            );
                            // Just log, don't return an error
                        }
                    }
                    // Case 4: something else that we don't recognise
                    // Just log, don't return an error
                    Err(e) => warn!("Failed to parse FullDomain: {}", e),
                };
            }
            _ => warn!("Found non-DNSName in SAN: {:?}", name),
        }
    }

    return match found_full_domains.len() {
        0 => Err(FindFullDomainError::NotFound),
        1 => {
            let domain = found_full_domains.into_iter().next().unwrap();
            Ok(domain)
        }
        _ => {
            warn!("Found conflicting full domains:");
            for d in found_full_domains.iter() {
                warn!("- {}", d.string_repr);
            }
            Err(FindFullDomainError::ConflictingFullDomain)
        }
    };
}

#[cfg(test)]
mod tests_parse_full_domain {
    use super::*;

    #[test]
    fn basic() {
        let s = "a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch";
        let chain_hash =
            hex::decode("a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f03")
                .unwrap();
        let chain_hash: Sha256Bytes = chain_hash.try_into().unwrap();
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_ok());
        assert_eq!(
            fd.unwrap(),
            FullDomain {
                chain_hash,
                issuance_time: 1691888383,
                epoch_id: 321,
                kt_version: 1,
                base_domain: "keytransparency.ch".to_owned(),
                string_repr: s.to_owned()
            }
        );
    }

    #[test]
    fn long_base_domain() {
        let s = "a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.key.trans.paren.cy.ch";
        let chain_hash =
            hex::decode("a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f03")
                .unwrap();
        let chain_hash: Sha256Bytes = chain_hash.try_into().unwrap();
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_ok());
        assert_eq!(
            fd.unwrap(),
            FullDomain {
                chain_hash,
                issuance_time: 1691888383,
                epoch_id: 321,
                kt_version: 1,
                base_domain: "key.trans.paren.cy.ch".to_owned(),
                string_repr: s.to_owned()
            }
        );
    }

    #[test]
    fn too_few_parts() {
        let s = "e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch";
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_err());
        assert!(matches!(
            fd.unwrap_err(),
            FullDomainParseError::NotEnoughParts
        ));
    }

    #[test]
    fn short_domain() {
        let s = "epoch.321.1.keytransparency.ch";
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_err());
        assert!(matches!(
            fd.unwrap_err(),
            FullDomainParseError::ProbablyShortDomain
        ));
    }

    #[test]
    fn bad_chainhash_length() {
        let s = "a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9cc.1691888383.321.1.keytransparency.ch";
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_err());
        assert!(matches!(
            fd.unwrap_err(),
            FullDomainParseError::BadChainHashLength(54)
        ));
    }

    #[test]
    fn invalid_hex() {
        let s = "a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389#!??!?.1691888383.321.1.keytransparency.ch";
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_err());
        assert!(matches!(
            fd.unwrap_err(),
            FullDomainParseError::HexDecodeFailed(_)
        ));
    }

    #[test]
    fn issuancetime_not_int() {
        let s = "a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.##.321.1.keytransparency.ch";
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_err());
        assert!(matches!(
            fd.unwrap_err(),
            FullDomainParseError::FromStringError(_)
        ));
    }

    #[test]
    fn epochid_not_int() {
        let s = "a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.##.1.keytransparency.ch";
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_err());
        assert!(matches!(
            fd.unwrap_err(),
            FullDomainParseError::FromStringError(_)
        ));
    }

    #[test]
    fn ktversion_not_int() {
        let s = "a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.#.keytransparency.ch";
        let fd = FullDomain::from_str(&s);
        assert!(fd.is_err());
        assert!(matches!(
            fd.unwrap_err(),
            FullDomainParseError::FromStringError(_)
        ));
    }
}

#[cfg(test)]
mod tests_find_full_domain {
    use super::*;

    #[test]
    fn basic() {
        let sd = ShortDomain::new(321, 1);
        let general_names = vec![
            GeneralName::DNSName("epoch.321.1.keytransparency.ch"),
            GeneralName::DNSName("a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch"),
        ];
        let san = SubjectAlternativeName { general_names };
        let res = find_full_domain(&sd, &san);

        let chain_hash =
            hex::decode("a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f03")
                .unwrap();
        let chain_hash: Sha256Bytes = chain_hash.try_into().unwrap();

        assert!(res.is_ok());
        let fd = res.unwrap();
        assert_eq!(fd.kt_version, 1);
        assert_eq!(fd.base_domain, "keytransparency.ch".to_owned());
        assert_eq!(fd.epoch_id, 321);
        assert_eq!(fd.issuance_time, 1691888383);
        assert_eq!(fd.chain_hash, chain_hash);
    }

    #[test]
    fn duplicate_non_conflicting() {
        let sd = ShortDomain::new(321, 1);
        let general_names = vec![
            GeneralName::DNSName("epoch.321.1.keytransparency.ch"),
            GeneralName::DNSName("a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch"),
            GeneralName::DNSName("a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch"),
        ];
        let san = SubjectAlternativeName { general_names };
        let res = find_full_domain(&sd, &san);

        assert!(res.is_ok());
    }

    #[test]
    fn empty() {
        let sd = ShortDomain::new(321, 1);
        let general_names = vec![];
        let san = SubjectAlternativeName { general_names };
        let res = find_full_domain(&sd, &san);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), FindFullDomainError::NotFound));
    }

    #[test]
    fn no_full_domain() {
        let sd = ShortDomain::new(321, 1);
        let general_names = vec![GeneralName::DNSName("epoch.321.1.keytransparency.ch")];
        let san = SubjectAlternativeName { general_names };
        let res = find_full_domain(&sd, &san);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), FindFullDomainError::NotFound));
    }

    #[test]
    fn conflicting_chainhash() {
        let sd = ShortDomain::new(321, 1);
        let general_names = vec![
            GeneralName::DNSName("epoch.321.1.keytransparency.ch"),
            GeneralName::DNSName("a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch"),
            GeneralName::DNSName("e152ba803dd34b231ad9ccd389003f03.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch"),
        ];
        let san = SubjectAlternativeName { general_names };
        let res = find_full_domain(&sd, &san);
        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            FindFullDomainError::ConflictingFullDomain
        ));
    }

    #[test]
    fn multiple_distinct_domains() {
        // Both ShortDomains should independently pass.

        let sd = ShortDomain::new(321, 1);
        let general_names = vec![
            GeneralName::DNSName("epoch.321.1.keytransparency.ch"),
            GeneralName::DNSName("epoch.322.1.keytransparency.ch"),
            GeneralName::DNSName("a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch"),
            GeneralName::DNSName("349f893bcaaa2dfe14f3e4b167b64c8c.05588a69d6d3c323f0a87efdefed04b5.1691903463.322.1.keytransparency.ch"),
        ];
        let san = SubjectAlternativeName { general_names };
        let res = find_full_domain(&sd, &san);

        let chain_hash =
            hex::decode("a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f03")
                .unwrap();
        let chain_hash: Sha256Bytes = chain_hash.try_into().unwrap();

        assert!(res.is_ok());
        let fd = res.unwrap();
        assert_eq!(fd.kt_version, 1);
        assert_eq!(fd.epoch_id, 321);
        assert_eq!(fd.issuance_time, 1691888383);
        assert_eq!(fd.chain_hash, chain_hash);

        let sd = ShortDomain::new(322, 1);
        let res = find_full_domain(&sd, &san);

        let chain_hash =
            hex::decode("349f893bcaaa2dfe14f3e4b167b64c8c05588a69d6d3c323f0a87efdefed04b5")
                .unwrap();
        let chain_hash: Sha256Bytes = chain_hash.try_into().unwrap();

        assert!(res.is_ok());
        let fd = res.unwrap();
        assert_eq!(fd.kt_version, 1);
        assert_eq!(fd.epoch_id, 322);
        assert_eq!(fd.issuance_time, 1691903463);
        assert_eq!(fd.chain_hash, chain_hash);
    }

    #[test]
    fn additional_full_domain_other_epoch() {
        let sd = ShortDomain::new(321, 1);
        let general_names = vec![
            GeneralName::DNSName("epoch.321.1.keytransparency.ch"),
            GeneralName::DNSName("a78f116c473f70399a9ec6bae84f2f84.e152ba803dd34b231ad9ccd389003f03.1691888383.321.1.keytransparency.ch"),
            GeneralName::DNSName("349f893bcaaa2dfe14f3e4b167b64c8c.05588a69d6d3c323f0a87efdefed04b5.1691903463.322.1.keytransparency.ch"),
        ];
        let san = SubjectAlternativeName { general_names };
        let res = find_full_domain(&sd, &san);

        let chain_hash =
            hex::decode("a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f03")
                .unwrap();
        let chain_hash: Sha256Bytes = chain_hash.try_into().unwrap();

        assert!(res.is_ok());
        let fd = res.unwrap();
        assert_eq!(fd.kt_version, 1);
        assert_eq!(fd.epoch_id, 321);
        assert_eq!(fd.issuance_time, 1691888383);
        assert_eq!(fd.chain_hash, chain_hash);
    }
}
