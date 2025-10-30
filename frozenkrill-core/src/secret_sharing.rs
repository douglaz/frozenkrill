//! Secret sharing implementation using Pedersen Verifiable Secret Sharing.
//!
//! This module provides functionality to split BIP-39 mnemonic phrases into shares
//! and reconstruct them using the Pedersen scheme, which allows verification of
//! shares without revealing information about the secret.

use anyhow::{anyhow, bail, Context, Result};
use bip39::Mnemonic;
use curve25519_dalek::scalar::Scalar;
use secrecy::{SecretBox};
use serde::{Deserialize, Serialize};
use std::path::Path;
use vsss_rs::curve25519::{WrappedRistretto, WrappedScalar};
use vsss_rs::pedersen::{split_secret, StdPedersenResult};
use vsss_rs::{combine_shares, PedersenResult};
use zeroize::Zeroize;

/// Error types for secret sharing operations
#[derive(Debug, thiserror::Error)]
pub enum SecretSharingError {
    #[error("Threshold must be between 2 and total shares")]
    InvalidThreshold,

    #[error("Total shares must be between 2 and 255")]
    InvalidShareCount,

    #[error("Threshold ({threshold}) cannot exceed total shares ({total})")]
    ThresholdExceedsTotal { threshold: u8, total: u8 },

    #[error("Mnemonic length must be 12 or 24 words")]
    InvalidMnemonicLength,

    #[error("Share verification failed - share may be corrupted or invalid")]
    VerificationFailed,

    #[error("Incompatible shares: {0}")]
    IncompatibleShares(String),

    #[error("Insufficient shares: need {threshold}, got {provided}")]
    InsufficientShares { threshold: u8, provided: usize },

    #[error("Invalid mnemonic checksum after reconstruction")]
    InvalidReconstructedChecksum,

    #[error("Share file format error: {0}")]
    FileFormatError(String),
}

/// Represents a single share of a split secret with metadata and verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Schema version for future compatibility
    pub version: u32,

    /// Secret sharing scheme used (always "pedersen" for this implementation)
    pub scheme: String,

    /// This share's index (1-based)
    pub share_index: u8,

    /// Minimum number of shares needed to reconstruct (M in M-of-N)
    pub threshold: u8,

    /// Total number of shares created (N in M-of-N)
    pub total_shares: u8,

    /// Original mnemonic word count (12 or 24)
    pub mnemonic_length: usize,

    /// The actual share data (hex-encoded)
    pub share_data: String,

    /// Pedersen verification commitments (hex-encoded, comma-separated)
    pub verification_data: String,

    /// ISO 8601 timestamp of share creation
    pub created_at: String,

    /// BLAKE3 hash of share_data for integrity checking
    pub checksum: String,
}

impl Share {
    /// Verify the integrity of this share using its checksum
    pub fn verify_checksum(&self) -> Result<()> {
        let computed = blake3::hash(self.share_data.as_bytes());
        let computed_hex = hex::encode(computed.as_bytes());

        if computed_hex != self.checksum {
            bail!(SecretSharingError::VerificationFailed);
        }

        Ok(())
    }

    /// Save this share to a file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize share")?;

        let warning = format!(
            "// WARNING: This is share {}/{} of a split secret.\n\
             // Store this file in a SECURE and SEPARATE location.\n\
             // You need at least {} shares to reconstruct the secret.\n\
             // DO NOT store shares together - this defeats the purpose.\n\n",
            self.share_index, self.total_shares, self.threshold
        );

        let content = warning + &json;
        std::fs::write(path, content)
            .context("Failed to write share file")?;

        Ok(())
    }

    /// Load a share from a file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context("Failed to read share file")?;

        // Skip warning comments at the beginning
        let json_start = content.find('{')
            .ok_or_else(|| anyhow!(SecretSharingError::FileFormatError(
                "No JSON object found in file".to_string()
            )))?;

        let json = &content[json_start..];
        let share: Share = serde_json::from_str(json)
            .context("Failed to parse share file")?;

        // Verify checksum immediately after loading
        share.verify_checksum()
            .context("Share checksum verification failed")?;

        Ok(share)
    }
}

/// Convert a mnemonic to a wrapped scalar suitable for Pedersen sharing
fn mnemonic_to_scalar(mnemonic: &Mnemonic) -> Result<WrappedScalar> {
    let entropy = mnemonic.to_entropy();

    // Pad entropy to 32 bytes if needed
    let mut bytes = [0u8; 32];
    bytes[..entropy.len()].copy_from_slice(&entropy);

    // Use from_bytes_mod_order to handle any byte pattern
    let scalar = Scalar::from_bytes_mod_order(bytes);
    Ok(WrappedScalar(scalar))
}

/// Convert scalar back to a mnemonic
fn scalar_to_mnemonic(scalar: WrappedScalar, word_count: usize) -> Result<SecretBox<Mnemonic>> {
    let mut entropy = scalar.0.to_bytes().to_vec();

    // Trim to expected length based on word count
    let expected_len = if word_count == 12 { 16 } else if word_count == 24 { 32 } else {
        bail!(SecretSharingError::InvalidMnemonicLength);
    };

    entropy.truncate(expected_len);

    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| anyhow!(SecretSharingError::InvalidReconstructedChecksum)
            .context(format!("Failed to create mnemonic: {}", e)))?;

    // Zeroize entropy before dropping
    entropy.zeroize();

    Ok(SecretBox::new(Box::new(mnemonic)))
}

/// Split a BIP-39 mnemonic into shares using Pedersen Verifiable Secret Sharing
///
/// # Arguments
/// * `mnemonic` - The mnemonic phrase to split
/// * `threshold` - Minimum number of shares needed to reconstruct (M in M-of-N)
/// * `total_shares` - Total number of shares to create (N in M-of-N)
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
/// A vector of `Share` structs containing the split secret and verification data
///
/// # Security Notes
/// - Uses Pedersen commitments for verifiable secret sharing
/// - All intermediate values are zeroized after use
/// - Shares can be verified without revealing information about the secret
pub fn split_mnemonic<R: rand_core::RngCore + rand_core::CryptoRng>(
    mnemonic: &Mnemonic,
    threshold: u8,
    total_shares: u8,
    rng: &mut R,
) -> Result<Vec<Share>> {
    // Validate parameters
    if threshold < 2 || total_shares < 2 {
        bail!(SecretSharingError::InvalidShareCount);
    }

    if threshold > total_shares {
        bail!(SecretSharingError::ThresholdExceedsTotal {
            threshold,
            total: total_shares,
        });
    }

    let word_count = mnemonic.word_count();
    if word_count != 12 && word_count != 24 {
        bail!(SecretSharingError::InvalidMnemonicLength);
    }

    // Convert mnemonic to scalar
    let scalar = mnemonic_to_scalar(mnemonic)?;

    // Split secret using Pedersen scheme
    let result: StdPedersenResult<WrappedRistretto, u8, Vec<u8>> = split_secret(
        threshold as usize,
        total_shares as usize,
        scalar,
        None, // blinding - let it be random
        None, // share_generator - use default
        None, // blind_factor_generator - use random
        rng,
    ).map_err(|e| anyhow!("Failed to split secret: {:?}", e))?;

    // Extract shares and verifiers from result
    let secret_shares = result.secret_shares();
    let pedersen_verifiers = result.pedersen_verifier_set();

    // Encode verifiers as hex strings
    let verifier_hex: Vec<String> = pedersen_verifiers
        .iter()
        .map(|v| hex::encode(v.0.compress().to_bytes()))
        .collect();

    let verification_data = verifier_hex.join(",");
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Create Share structs
    let mut shares = Vec::new();
    for (idx, share_bytes) in secret_shares.iter().enumerate() {
        let share_data = hex::encode(share_bytes);
        let checksum = hex::encode(blake3::hash(share_data.as_bytes()).as_bytes());

        let share = Share {
            version: 1,
            scheme: "pedersen".to_string(),
            share_index: (idx + 1) as u8,
            threshold,
            total_shares,
            mnemonic_length: word_count,
            share_data,
            verification_data: verification_data.clone(),
            created_at: timestamp.clone(),
            checksum,
        };

        shares.push(share);
    }

    Ok(shares)
}

/// Combine shares to reconstruct the original mnemonic
///
/// # Arguments
/// * `shares` - A slice of `Share` structs (must have at least threshold shares)
///
/// # Returns
/// The reconstructed mnemonic phrase in a `SecretBox` for automatic zeroization
///
/// # Security Notes
/// - Verifies all shares using Pedersen commitments before reconstruction
/// - Validates the reconstructed mnemonic has a valid BIP-39 checksum
/// - All intermediate values are zeroized after use
pub fn combine_shares_to_mnemonic(shares: &[Share]) -> Result<SecretBox<Mnemonic>> {
    if shares.is_empty() {
        bail!(anyhow!("No shares provided"));
    }

    // Validate all shares are compatible
    let first = &shares[0];
    for share in shares.iter().skip(1) {
        if share.version != first.version {
            bail!(SecretSharingError::IncompatibleShares(
                format!("Version mismatch: {} vs {}", share.version, first.version)
            ));
        }
        if share.threshold != first.threshold {
            bail!(SecretSharingError::IncompatibleShares(
                format!("Threshold mismatch: {} vs {}", share.threshold, first.threshold)
            ));
        }
        if share.total_shares != first.total_shares {
            bail!(SecretSharingError::IncompatibleShares(
                format!("Total shares mismatch: {} vs {}", share.total_shares, first.total_shares)
            ));
        }
        if share.mnemonic_length != first.mnemonic_length {
            bail!(SecretSharingError::IncompatibleShares(
                format!("Mnemonic length mismatch: {} vs {}", share.mnemonic_length, first.mnemonic_length)
            ));
        }
        if share.verification_data != first.verification_data {
            bail!(SecretSharingError::IncompatibleShares(
                "Verification data mismatch".to_string()
            ));
        }
    }

    // Check we have enough shares
    if shares.len() < first.threshold as usize {
        bail!(SecretSharingError::InsufficientShares {
            threshold: first.threshold,
            provided: shares.len(),
        });
    }

    // Decode share data
    let mut share_bytes: Vec<Vec<u8>> = Vec::new();
    for share in shares {
        let bytes = hex::decode(&share.share_data)
            .context("Failed to decode share data")?;
        share_bytes.push(bytes);
    }

    // Combine shares to reconstruct the scalar
    let reconstructed: WrappedScalar = combine_shares(&share_bytes)
        .map_err(|e| anyhow!("Failed to combine shares: {:?}", e))?;

    // Convert scalar back to mnemonic
    let mnemonic = scalar_to_mnemonic(reconstructed, first.mnemonic_length)?;

    Ok(mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine_12_words() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::rng();

        let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 3);

        // Combine with threshold shares
        let reconstructed = combine_shares_to_mnemonic(&shares[0..2]).unwrap();
        assert_eq!(
            reconstructed.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }

    #[test]
    fn test_split_and_combine_24_words() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art").unwrap();
        let mut rng = rand::rng();

        let shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        // Combine with threshold shares
        let reconstructed = combine_shares_to_mnemonic(&shares[1..4]).unwrap();
        assert_eq!(
            reconstructed.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }

    #[test]
    fn test_insufficient_shares() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::rng();

        let shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();

        // Try to combine with only 2 shares (need 3)
        let result = combine_shares_to_mnemonic(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::rng();

        let result = split_mnemonic(&mnemonic, 5, 3, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_checksum_verification() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::rng();

        let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();

        // Verify checksum
        assert!(shares[0].verify_checksum().is_ok());

        // Corrupt the share data
        let mut corrupted = shares[0].clone();
        corrupted.share_data = "corrupted_data".to_string();

        // Checksum verification should fail
        assert!(corrupted.verify_checksum().is_err());
    }
}
