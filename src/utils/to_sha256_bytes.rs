use crate::Sha256Bytes;
use thiserror::Error;

// as_ vs to_ vs into_: https://stackoverflow.com/a/73861738/11076036

pub trait ToSha256Bytes {
    /// Parse what should be a 64 character hexadecimal string into a 32-byte byte array
    /// and pretend it is a SHA-256 hash.
    ///
    /// This fails if the input string is not hexadecimal or not exactly 64 characters.
    fn to_sha256_bytes(self) -> Result<Sha256Bytes, ToSha256BytesError>;
}

/// Errors that can occur during [`to_sha256_bytes`].
#[derive(Debug, Error)]
pub enum ToSha256BytesError {
    #[error("failed to decode hex to bytes: {0}")]
    HashHex(#[from] hex::FromHexError),

    #[error("hash has an unexpected length ({0} bytes instead of 32)")]
    BadHashLength(usize),
}

impl<T: AsRef<[u8]>> ToSha256Bytes for T {
    fn to_sha256_bytes(self) -> Result<Sha256Bytes, ToSha256BytesError> {
        let root_hash: Vec<u8> = hex::decode(self)?;
        if root_hash.len() != 32 {
            return Err(ToSha256BytesError::BadHashLength(root_hash.len()));
        }
        let root_hash: Sha256Bytes = root_hash
            .try_into()
            .expect("length should be checked above");
        Ok(root_hash)
    }
}

#[cfg(test)]
mod tests_to_sha256_bytes {
    use super::*;

    #[test]
    fn basic() {
        let bytes =
            "a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f03".to_sha256_bytes();
        assert!(bytes.is_ok());
        let bytes =
            "349f893bcaaa2dfe14f3e4b167b64c8c05588a69d6d3c323f0a87efdefed04b5".to_sha256_bytes();
        assert!(bytes.is_ok());
    }

    #[test]
    fn too_short() {
        let bytes =
            "a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f".to_sha256_bytes();
        assert!(bytes.is_err());
        assert!(matches!(
            bytes.unwrap_err(),
            ToSha256BytesError::BadHashLength(31)
        ))
    }

    #[test]
    fn too_long() {
        let bytes =
            "a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f0300".to_sha256_bytes();
        assert!(bytes.is_err());
        assert!(matches!(
            bytes.unwrap_err(),
            ToSha256BytesError::BadHashLength(33)
        ))
    }

    #[test]
    fn too_long_odd_length() {
        let bytes =
            "a78f116c473f70399a9ec6bae84f2f84e152ba803dd34b231ad9ccd389003f030".to_sha256_bytes();
        assert!(bytes.is_err());
        assert!(matches!(
            bytes.unwrap_err(),
            ToSha256BytesError::HashHex(hex::FromHexError::OddLength)
        ))
    }

    #[test]
    fn empty() {
        let bytes = "".to_sha256_bytes();
        assert!(bytes.is_err());
        assert!(matches!(
            bytes.unwrap_err(),
            ToSha256BytesError::BadHashLength(0)
        ))
    }

    #[test]
    fn not_hex() {
        let bytes = "05588a69d6d3c323f0a87efdefed04b5!?".to_sha256_bytes();
        assert!(bytes.is_err());
        assert!(matches!(
            bytes.unwrap_err(),
            ToSha256BytesError::HashHex(hex::FromHexError::InvalidHexCharacter { c: _, index: _ })
        ))
    }
}
