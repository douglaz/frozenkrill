//! Secret sharing implementation using Pedersen Verifiable Secret Sharing (VSS).
//!
//! This module implements **Pedersen VSS**, which is **Shamir's Secret Sharing with added
//! verifiability**. While Shamir's scheme splits secrets into shares with threshold reconstruction,
//! Pedersen VSS adds cryptographic commitments that allow anyone to verify shares are valid
//! without learning anything about the secret.
//!
//! ## What is Pedersen VSS?
//!
//! Pedersen VSS = **Shamir's Secret Sharing** + **Pedersen Commitments** for verification
//!
//! - **Base scheme**: Shamir's polynomial secret sharing (M-of-N threshold)
//! - **Enhancement**: Pedersen commitments provide verifiability
//! - **Benefit**: Shares can be verified as authentic before they're needed
//!
//! ## Why VSS instead of plain Shamir?
//!
//! Traditional Shamir's Secret Sharing has a problem: you can't verify shares are valid until
//! you try to reconstruct the secret. With Pedersen VSS, share holders can verify their shares
//! are genuine at any time, which is crucial for inheritance/backup scenarios where shares
//! may not be used for years.
//!
//! This module provides functionality to split BIP-39 mnemonic phrases into shares
//! and reconstruct them using the Pedersen VSS scheme.

use anyhow::{Context, Result, anyhow, bail};
use bip39::Mnemonic;
use curve25519_dalek::scalar::Scalar;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use curve25519_dalek::ristretto::CompressedRistretto;
use std::str::FromStr;
use vsss_rs::curve25519::{WrappedRistretto, WrappedScalar};
use vsss_rs::pedersen::{StdPedersenResult, split_secret};
use vsss_rs::{PedersenResult, PedersenVerifierSet, combine_shares};

/// Result of a successful `combine_vss_wallets`. Bundles the recovered
/// mnemonic with the chosen share group's public metadata so callers can
/// surface user-facing context (e.g. "this share set was created in duress
/// mode — you also need the BIP-39 passphrase to recover the real wallet").
pub struct VssRecovery {
    pub mnemonic: SecretBox<Mnemonic>,
    pub metadata: crate::wallet_description::SinglesigPublicMetadataV0,
}

impl VssRecovery {
    /// Rebuild a `SingleSigWalletDescriptionV0` from this recovery.
    ///
    /// This is the **safe** entry point for reconstructing a wallet
    /// from a successful `combine_vss_wallets`: the duress decision
    /// uses `self.metadata.is_duress`, which is *group-aggregated*
    /// (any verified share asserting duress flips the recovery to
    /// duress mode) — a single tampered share's `is_duress` byte
    /// cannot redirect a passphrase restore the way it could in the
    /// per-share `to_singlesig` path.
    ///
    /// Rules:
    ///   * normal recovery + caller passes `Some(non-empty)` ⇒ refuse.
    ///   * duress recovery + caller passes `Some(non-empty)` ⇒ build
    ///     the passphrase-derived (real) wallet and return it.
    ///   * either + caller passes `None` (or `Some("")`) ⇒ return the
    ///     no-passphrase wallet (the decoy in duress mode, the wallet
    ///     itself in normal mode).
    pub fn rebuild_singlesig(
        &self,
        seed_password: &Option<std::sync::Arc<secrecy::SecretString>>,
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<crate::wallet_description::SingleSigWalletDescriptionV0> {
        use std::sync::Arc;
        // Normalize empty string to None per BIP-39 semantics.
        let effective_pw: Option<Arc<secrecy::SecretString>> = match seed_password {
            Some(pw) if !pw.expose_secret().is_empty() => Some(Arc::clone(pw)),
            _ => None,
        };

        if !self.metadata.is_duress && effective_pw.is_some() {
            bail!(
                "This share set was not created in duress mode, but a BIP-39 passphrase \
                 was supplied. Restoring with a passphrase here would silently produce \
                 an unrelated wallet derived from the supplied (possibly mistyped) \
                 passphrase. Re-run without a passphrase, or use a duress-mode share set."
            );
        }

        // Clone the inner `Mnemonic` directly into a fresh
        // `SecretBox` instead of round-tripping through `to_string()
        // + Mnemonic::from_str`. The String round-trip would leave a
        // non-zeroizing copy of the seed phrase on the heap on every
        // successful recovery sanity-check.
        let mnemonic_arc: Arc<SecretBox<bip39::Mnemonic>> =
            Arc::new(SecretBox::new(Box::new(self.mnemonic.expose_secret().clone())));
        let network = bitcoin::Network::from_str(&self.metadata.network).with_context(|| {
            format!("invalid network in recovery metadata: {}", self.metadata.network)
        })?;
        let script_type = crate::wallet_description::ScriptType::from_str(
            &self.metadata.script_type,
        )
        .with_context(|| {
            format!(
                "invalid script type in recovery metadata: {}",
                self.metadata.script_type
            )
        })?;

        // Authenticate the metadata against the no-passphrase wallet
        // first (catches tampered network / script_type / xpub even
        // when a passphrase is supplied), then build and return the
        // wallet the caller actually asked for.
        let metadata_witness = crate::wallet_description::SingleSigWalletDescriptionV0::generate(
            Arc::clone(&mnemonic_arc),
            &None,
            network,
            script_type,
            secp,
        )?;
        anyhow::ensure!(
            metadata_witness.encoded_singlesig_xpub() == self.metadata.singlesig_xpub,
            "Reconstructed wallet xpub does not match recovery metadata: the share set \
             may have been tampered with"
        );
        if effective_pw.is_none() {
            return Ok(metadata_witness);
        }
        crate::wallet_description::SingleSigWalletDescriptionV0::generate(
            mnemonic_arc,
            &effective_pw,
            network,
            script_type,
            secp,
        )
    }
}
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Internal representation of a single share of a split secret.
///
/// Entropy is split into two independent 16-byte halves and each half is shared
/// via its own Pedersen VSS instance. 12-word mnemonics (16 bytes of entropy)
/// only use the `_lo` half; 24-word mnemonics (32 bytes) use both. Splitting in
/// half keeps every input < 2^128, well below the Curve25519 scalar order
/// (~2^252.4), so `Scalar::from_bytes_mod_order` never actually reduces and the
/// round-trip is exact.
///
/// `Zeroize`/`ZeroizeOnDrop` wipe the heap-resident hex strings (secret share,
/// blinder share, both halves) when the `Share` is dropped, so plaintext share
/// material doesn't linger in process memory after split / combine finishes.
///
/// This type is intentionally **crate-private**. The supported public API is
/// `split_singlesig_wallet` + `combine_vss_wallets`, which thread these
/// shares through the AEAD-authenticated `VssJsonWalletDescriptionV0` on
/// disk; the AEAD MAC is what protects the share metadata (verifier sets,
/// hi-half presence) from tampering. A bare `Share` outside that wrapper
/// has no integrity check, so accepting one from an untrusted source would
/// expose recovery to silent downgrade attacks (stripping `*_hi` fields,
/// editing `verification_data`, …) that this crate cannot detect on its own.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Share {
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

    /// Secret share of the low 16 entropy bytes (hex-encoded).
    pub share_data: String,

    /// Blinder share of the low 16 entropy bytes (hex-encoded). Required to
    /// verify `share_data` against the Pedersen commitments without
    /// learning anything about the secret.
    pub blinder_share_data: String,

    /// Pedersen commitments for the low half (hex-encoded, comma-separated).
    /// Layout: `[g, h, C_0, C_1, ..., C_{t-1}]` where `C_i = g^a_i * h^b_i`.
    pub verification_data: String,

    /// Secret share of the high 16 entropy bytes (hex-encoded). Present iff 24-word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_data_hi: Option<String>,

    /// Blinder share of the high 16 entropy bytes. Present iff 24-word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinder_share_data_hi: Option<String>,

    /// Pedersen commitments for the high half. Present iff 24-word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_data_hi: Option<String>,

    /// ISO 8601 timestamp of share creation
    pub created_at: String,

    /// BLAKE3 hash of share_data (and share_data_hi when present) for integrity checking
    pub checksum: String,
}

impl Share {
    /// Compute the canonical checksum over the share's secret/blinder data
    /// AND the Pedersen verifier sets that drive recovery. All of these
    /// streams are critical for correct reconstruction:
    ///
    ///   * share_data / share_data_hi: the secret-share polynomial points.
    ///   * blinder_share_data / blinder_share_data_hi: paired blinder
    ///     points used in Pedersen verify_share_and_blinder.
    ///   * verification_data / verification_data_hi: the Pedersen
    ///     commitments — the cryptographically authoritative description
    ///     of the polynomial. A tampered verifier set would still let a
    ///     plaintext share pass `verify_checksum()` if it were not
    ///     hashed in here, even though combine would later reject every
    ///     share for verifying against a fabricated polynomial.
    ///
    /// A single flipped bit in any of those streams must be caught at
    /// `load_from_file` time, so the load contract matches what combine
    /// will demand.
    fn compute_checksum(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.share_data.as_bytes());
        hasher.update(b"|");
        hasher.update(self.blinder_share_data.as_bytes());
        hasher.update(b"|");
        hasher.update(self.verification_data.as_bytes());
        if let Some(hi) = &self.share_data_hi {
            hasher.update(b"|");
            hasher.update(hi.as_bytes());
        }
        if let Some(hi) = &self.blinder_share_data_hi {
            hasher.update(b"|");
            hasher.update(hi.as_bytes());
        }
        if let Some(hi) = &self.verification_data_hi {
            hasher.update(b"|");
            hasher.update(hi.as_bytes());
        }
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Verify the integrity of this share using its checksum.
    /// Only used by tests now (the real on-disk format is the AEAD-
    /// authenticated `VssJsonWalletDescriptionV0`).
    #[cfg(test)]
    pub(crate) fn verify_checksum(&self) -> Result<()> {
        if self.compute_checksum() != self.checksum {
            bail!(SecretSharingError::VerificationFailed);
        }
        Ok(())
    }

}

// `Share::save_to_file` / `load_from_file` were intentionally removed:
// the only on-disk integrity check available there was an *unkeyed*
// BLAKE3 checksum that anyone editing the JSON could trivially
// recompute, so the format was tamperable rather than tamper-evident
// (e.g. stripping every `*_hi` field would silently downgrade a
// 24-word recovery to a different valid 12-word one). The supported
// share-file format in this crate is the password-encrypted
// `VssJsonWalletDescriptionV0` written by the `split-secret` CLI;
// authenticity for those files is provided by the AEAD wrapper.

/// Pack a 16-byte entropy half into a Curve25519 scalar.
///
/// 16 bytes (128 bits) is far below the scalar order (~2^252.4), so
/// `Scalar::from_bytes_mod_order` does not reduce and the round-trip is exact.
fn entropy_half_to_scalar(half: &[u8]) -> WrappedScalar {
    debug_assert_eq!(half.len(), 16);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(half);
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let wrapped = WrappedScalar(scalar);
    bytes.zeroize();
    wrapped
}

/// Unpack a scalar that holds at most 128 bits back into 16 entropy bytes.
fn scalar_to_entropy_half(scalar: &WrappedScalar) -> [u8; 16] {
    let bytes = scalar.0.to_bytes();
    let mut half = [0u8; 16];
    half.copy_from_slice(&bytes[..16]);
    half
}

/// Reassemble entropy halves into a mnemonic of the requested word count.
fn entropy_to_mnemonic(
    lo: &[u8; 16],
    hi: Option<&[u8; 16]>,
    word_count: usize,
) -> Result<SecretBox<Mnemonic>> {
    let mut entropy: Vec<u8> = match (word_count, hi) {
        (12, None) => lo.to_vec(),
        (24, Some(h)) => {
            let mut v = Vec::with_capacity(32);
            v.extend_from_slice(lo);
            v.extend_from_slice(h);
            v
        }
        _ => bail!(SecretSharingError::InvalidMnemonicLength),
    };

    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| {
        anyhow!(SecretSharingError::InvalidReconstructedChecksum)
            .context(format!("Failed to create mnemonic: {}", e))
    })?;

    entropy.zeroize();
    Ok(SecretBox::new(Box::new(mnemonic)))
}

/// Split a BIP-39 mnemonic into shares using Pedersen VSS (enhanced Shamir's Secret Sharing)
///
/// This uses **Shamir's polynomial secret sharing** as the base algorithm, enhanced with
/// **Pedersen commitments** for verifiability. The core splitting/reconstruction follows
/// Shamir's 1979 scheme, but adds the ability to verify shares without revealing the secret.
///
/// # Arguments
/// * `mnemonic` - The mnemonic phrase to split
/// * `threshold` - Minimum number of shares needed to reconstruct (M in M-of-N, from Shamir)
/// * `total_shares` - Total number of shares to create (N in M-of-N, from Shamir)
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
/// A vector of `Share` structs containing the split secret and verification data
///
/// # Security Notes
/// - Uses Shamir's polynomial interpolation for threshold reconstruction
/// - Adds Pedersen commitments for verifiable secret sharing
/// - All intermediate values are zeroized after use
/// - Shares can be verified without revealing information about the secret
/// - Information-theoretic security: M-1 shares reveal nothing (from Shamir's scheme)
pub(crate) fn split_mnemonic<R: rand::RngCore + rand::CryptoRng>(
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

    // BIP-39: 12 words → 16 bytes of entropy, 24 words → 32 bytes.
    // `mnemonic.to_entropy()` returns a plain `Vec<u8>` whose backing heap
    // buffer is not zeroized on drop, so wrap it in `SecretBox` to clear it
    // when this scope exits — otherwise the raw seed lingers in memory until
    // the allocator happens to reuse those bytes.
    let entropy = SecretBox::new(Box::new(mnemonic.to_entropy()));
    let entropy_bytes = entropy.expose_secret();
    let lo_scalar = entropy_half_to_scalar(&entropy_bytes[..16]);
    let hi_scalar = if word_count == 24 {
        Some(entropy_half_to_scalar(&entropy_bytes[16..32]))
    } else {
        None
    };
    drop(entropy);

    let lo_split = split_one_scalar(lo_scalar, threshold, total_shares, rng)?;
    let hi_split = match hi_scalar {
        Some(s) => Some(split_one_scalar(s, threshold, total_shares, rng)?),
        None => None,
    };

    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut shares = Vec::with_capacity(total_shares as usize);
    for idx in 0..(total_shares as usize) {
        let share_data = hex::encode(&lo_split.share_bytes[idx]);
        let blinder_share_data = hex::encode(&lo_split.blinder_bytes[idx]);
        let share_data_hi = hi_split
            .as_ref()
            .map(|h| hex::encode(&h.share_bytes[idx]));
        let blinder_share_data_hi = hi_split
            .as_ref()
            .map(|h| hex::encode(&h.blinder_bytes[idx]));
        let verification_data_hi = hi_split.as_ref().map(|h| h.verification_data.clone());

        let mut share = Share {
            version: 1,
            scheme: "pedersen".to_string(),
            share_index: (idx + 1) as u8,
            threshold,
            total_shares,
            mnemonic_length: word_count,
            share_data,
            blinder_share_data,
            verification_data: lo_split.verification_data.clone(),
            share_data_hi,
            blinder_share_data_hi,
            verification_data_hi,
            created_at: timestamp.clone(),
            checksum: String::new(),
        };
        share.checksum = share.compute_checksum();
        shares.push(share);
    }

    Ok(shares)
}

/// Result of splitting a single scalar via Pedersen VSS.
struct VssOneScalar {
    /// Per-share secret-share raw bytes (length == total_shares).
    share_bytes: Vec<Vec<u8>>,
    /// Per-share blinder-share raw bytes (length == total_shares; index `i`
    /// pairs with `share_bytes[i]`).
    blinder_bytes: Vec<Vec<u8>>,
    /// Hex-encoded, comma-separated Pedersen verifier set:
    /// `[g, h, C_0, C_1, ..., C_{t-1}]`. Combine uses this together with
    /// each (secret_share, blinder_share) pair to verify shares without
    /// learning anything about the secret — `C_i = g^a_i * h^b_i` blinds
    /// `a_i` (in particular `a_0 = secret`) with the random `b_i`, so even
    /// when the secret is restricted to a small range (here 128 bits) the
    /// commitment does not leak it (in contrast to a Feldman commitment
    /// `g^a_i`, which would be vulnerable to a ~2^64 discrete-log attack
    /// for a 128-bit exponent).
    verification_data: String,
}

/// Run one independent Pedersen VSS over a single 128-bit scalar.
fn split_one_scalar<R: rand::RngCore + rand::CryptoRng>(
    scalar: WrappedScalar,
    threshold: u8,
    total_shares: u8,
    rng: &mut R,
) -> Result<VssOneScalar> {
    let result: StdPedersenResult<WrappedRistretto, u8, Vec<u8>> = split_secret(
        threshold as usize,
        total_shares as usize,
        scalar,
        None,
        None,
        None,
        rng,
    )
    .map_err(|e| anyhow!("Failed to split secret: {:?}", e))?;

    let share_bytes: Vec<Vec<u8>> = result.secret_shares().to_vec();
    let blinder_bytes: Vec<Vec<u8>> = result.blinder_shares().to_vec();
    debug_assert_eq!(share_bytes.len(), blinder_bytes.len());
    let pedersen_hex: Vec<String> = result
        .pedersen_verifier_set()
        .iter()
        .map(|v| hex::encode(v.0.compress().to_bytes()))
        .collect();

    Ok(VssOneScalar {
        share_bytes,
        blinder_bytes,
        verification_data: pedersen_hex.join(","),
    })
}

/// Parse a comma-separated list of hex-encoded Ristretto points back into a
/// `Vec<WrappedRistretto>`. Used to deserialize the Pedersen verifier set.
fn parse_ristretto_points(s: &str) -> Result<Vec<WrappedRistretto>> {
    let mut out = Vec::new();
    for hex_str in s.split(',') {
        let bytes = hex::decode(hex_str).context("Failed to decode verifier hex")?;
        anyhow::ensure!(
            bytes.len() == 32,
            "verifier point must be 32 bytes (got {})",
            bytes.len()
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let compressed = CompressedRistretto(arr);
        let point = compressed
            .decompress()
            .ok_or_else(|| anyhow!("verifier point is not a valid Ristretto encoding"))?;
        out.push(WrappedRistretto(point));
    }
    Ok(out)
}

/// Filter (secret_share, blinder_share) pairs down to those that pass
/// Pedersen verification, deduped by share identifier (first byte).
///
/// Pedersen `verify_share_and_blinder` checks that the Pedersen commitment
/// `C(x_i) = g^a(x_i) * h^b(x_i)` equals the value implied by the share's
/// `(secret_share, blinder_share)` at the share's identifier. This proves
/// the share lies on both the secret and blinder polynomials without
/// revealing either value — in particular the secret remains hidden by the
/// random blinder even when it is restricted to a small range.
///
/// Combining requires distinct identifiers, and any two share-pairs with
/// the same identifier that both verify are guaranteed to be byte-identical
/// (a polynomial can take only one value at any given x), so first-wins
/// dedupe is safe.
fn verified_unique_share_pairs(
    secret_shares: &[Vec<u8>],
    blinder_shares: &[Vec<u8>],
    pedersen_hex: &str,
) -> Result<Vec<Vec<u8>>> {
    anyhow::ensure!(
        secret_shares.len() == blinder_shares.len(),
        "secret-share count ({}) does not match blinder-share count ({})",
        secret_shares.len(),
        blinder_shares.len()
    );
    let verifier_vec = parse_ristretto_points(pedersen_hex)?;
    anyhow::ensure!(
        verifier_vec.len() >= 3,
        "Pedersen verifier set must contain at least secret-generator + blinder-generator + 1 commitment (got {})",
        verifier_vec.len()
    );
    let mut seen_ids = std::collections::HashSet::new();
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut last_failure: Option<String> = None;
    for (secret_share, blinder_share) in secret_shares.iter().zip(blinder_shares.iter()) {
        let secret_id = secret_share.first().copied();
        let blinder_id = blinder_share.first().copied();
        if secret_id != blinder_id {
            last_failure = Some(format!(
                "secret-share/blinder-share identifier mismatch: {:?} vs {:?}",
                secret_id, blinder_id
            ));
            continue;
        }
        // verify_share_and_blinder rejects shares whose identifier is zero.
        if verifier_vec
            .verify_share_and_blinder(secret_share, blinder_share)
            .is_err()
        {
            last_failure = Some(format!(
                "share with identifier {:?} failed Pedersen verification",
                secret_id
            ));
            continue;
        }
        match secret_id {
            Some(id) if seen_ids.insert(id) => out.push(secret_share.clone()),
            _ => {} // duplicate identifier (already accepted) or empty share
        }
    }
    if out.is_empty() {
        bail!(
            anyhow!(SecretSharingError::VerificationFailed).context(
                last_failure.unwrap_or_else(|| "no shares supplied for verification".to_string())
            )
        );
    }
    Ok(out)
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
pub(crate) fn combine_shares_to_mnemonic(shares: &[Share]) -> Result<SecretBox<Mnemonic>> {
    if shares.is_empty() {
        bail!(anyhow!("No shares provided"));
    }

    // Group input shares by their cryptographic identity — the Pedersen
    // verifier sets uniquely identify a single split run. The largest
    // group is the candidate for reconstruction; smaller groups
    // (typically a single corrupted-verifier outlier) are dropped.
    //
    // This deliberately does NOT use `shares[0]` as the canonical
    // "first" share for compatibility checks — otherwise a corrupted
    // first-position share would abort recovery even when the remaining
    // shares form a valid threshold set. Recovery should depend only on
    // whether a viable subset exists, not on input order.
    type GroupKey<'a> = (&'a str, Option<&'a str>);
    let mut groups: std::collections::BTreeMap<GroupKey, Vec<&Share>> =
        std::collections::BTreeMap::new();
    for s in shares {
        let key: GroupKey = (s.verification_data.as_str(), s.verification_data_hi.as_deref());
        groups.entry(key).or_default().push(s);
    }
    // Pick the largest group (ties broken arbitrarily — within a single
    // call this just affects which set of shares is attempted; the next
    // step verifies and combines them).
    let chosen: Vec<&Share> = groups
        .into_values()
        .max_by_key(|g| g.len())
        .expect("non-empty input ⇒ at least one group");
    let first = chosen[0];

    // Other fields (`version`, `mnemonic_length`,
    // `share_data_hi.is_some()` consistency, `blinder_share_data_hi.is_some()`
    // consistency) are advisory metadata. A single share with a flipped
    // advisory field should NOT abort recovery for the whole group when
    // the remaining shares still satisfy the threshold — combine_one_half
    // skips individual broken shares per-half and the threshold check at
    // the end catches the case where too many were skipped.

    // Derive whether to reconstruct one half (12-word) or two (24-word)
    // from the *cryptographic* presence of the high-half verifier set,
    // not from the mutable `mnemonic_length` JSON field. Otherwise an
    // attacker who edits the metadata field down from 24 to 12 across
    // every share could trick combine into ignoring the high-half
    // share data and silently returning a different valid 12-word
    // mnemonic.
    let has_hi = first.verification_data_hi.is_some();
    let derived_word_count: usize = if has_hi { 24 } else { 12 };

    // The reconstruction threshold is derived from the Pedersen verifier set
    // (commitment data, not metadata). This is the cryptographically
    // authoritative threshold — the `Share.threshold` field is informational
    // only. Trusting only the verifier set here defeats a "downgrade"
    // attack (where an attacker rewrites `threshold` down across all
    // shares hoping that combine accepts fewer points than the polynomial
    // actually requires), because Lagrange interpolation will still demand
    // the real number of points and per-share Pedersen verification will
    // still reject any share that doesn't lie on the original polynomial.
    let lo_threshold = threshold_from_pedersen(&first.verification_data)?;

    // Check we have enough shares (using the cryptographic threshold) —
    // count shares in the chosen group, not the full input slice.
    if chosen.len() < lo_threshold as usize {
        bail!(SecretSharingError::InsufficientShares {
            threshold: lo_threshold,
            provided: chosen.len(),
        });
    }

    let lo_scalar = combine_one_half(
        &chosen,
        |s| Some(s.share_data.as_str()),
        |s| Some(s.blinder_share_data.as_str()),
        &first.verification_data,
        lo_threshold,
    )?
    .ok_or_else(|| anyhow!("missing low-half share data"))?;
    let lo_bytes = scalar_to_entropy_half(&lo_scalar);

    let hi_bytes = if has_hi {
        let hi_pedersen = first
            .verification_data_hi
            .as_deref()
            .expect("checked .is_some() above");
        let hi_threshold = threshold_from_pedersen(hi_pedersen)?;
        anyhow::ensure!(
            hi_threshold == lo_threshold,
            "Low-half and high-half Pedersen verifier sets imply different thresholds ({lo_threshold} vs {hi_threshold})"
        );
        let hi_scalar = combine_one_half(
            &chosen,
            |s| s.share_data_hi.as_deref(),
            |s| s.blinder_share_data_hi.as_deref(),
            hi_pedersen,
            hi_threshold,
        )?
        .ok_or_else(|| anyhow!("missing high-half share data"))?;
        Some(scalar_to_entropy_half(&hi_scalar))
    } else {
        None
    };

    let mnemonic = entropy_to_mnemonic(&lo_bytes, hi_bytes.as_ref(), derived_word_count)?;

    // Advisory: surface a tampered `mnemonic_length` field. The recovery
    // already used the cryptographically authoritative value derived from
    // the verifier set, so the secret returned is correct; this just
    // tells the caller that the share metadata disagreed with the
    // commitments and may have been edited.
    if first.mnemonic_length != derived_word_count {
        log::warn!(
            "Share metadata says mnemonic_length={} but Pedersen verifier set implies {}; \
             metadata may have been tampered with — recovered using the verifier-derived length",
            first.mnemonic_length,
            derived_word_count
        );
    }

    Ok(mnemonic)
}

/// Recover the reconstruction threshold from the Pedersen verifier set:
/// the set is `[g, h, C_0, C_1, ..., C_{t-1}]`, so its length is
/// `threshold + 2`.
fn threshold_from_pedersen(pedersen_hex: &str) -> Result<u8> {
    let count = pedersen_hex.split(',').count();
    anyhow::ensure!(
        count >= 4,
        "Pedersen verifier set must contain at least secret-generator + blinder-generator + 2 commitments (got {count} elements)"
    );
    let t = count - 2;
    u8::try_from(t).context("Pedersen verifier set encodes a threshold that does not fit in u8")
}

/// Combine the per-share secret/blinder hex pairs selected by `extract_*`
/// into a single scalar.
///
/// Per-share tolerance is the rule here: any individual share is dropped
/// (rather than aborting the whole combine) if it lacks the hex slot for
/// this half, has malformed hex, or fails Pedersen verification. The
/// `verified_unique_share_pairs` step then dedupes by share identifier
/// and the threshold check below catches the case where too many shares
/// were dropped.
fn combine_one_half(
    shares: &[&Share],
    extract_secret: impl Fn(&Share) -> Option<&str>,
    extract_blinder: impl Fn(&Share) -> Option<&str>,
    pedersen_hex: &str,
    threshold: u8,
) -> Result<Option<WrappedScalar>> {
    let mut secret_bytes: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
    let mut blinder_bytes: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
    for share in shares {
        // Skip shares that don't carry both halves' hex data, or whose
        // hex is malformed. Verified `verified_unique_share_pairs` will
        // confirm cryptographic validity; until then we only filter
        // structural defects so a single bad share doesn't block recovery
        // for an otherwise complete set.
        let (Some(s_hex), Some(b_hex)) = (extract_secret(share), extract_blinder(share)) else {
            continue;
        };
        let (Ok(sb), Ok(bb)) = (hex::decode(s_hex), hex::decode(b_hex)) else {
            continue;
        };
        secret_bytes.push(sb);
        blinder_bytes.push(bb);
    }
    if secret_bytes.is_empty() {
        return Ok(None);
    }
    let good = verified_unique_share_pairs(&secret_bytes, &blinder_bytes, pedersen_hex)?;
    anyhow::ensure!(
        good.len() >= threshold as usize,
        "Insufficient verified shares: needed at least {threshold}, got {}",
        good.len()
    );
    let combined: WrappedScalar =
        combine_shares(&good).map_err(|e| anyhow!("Failed to combine shares: {:?}", e))?;
    Ok(Some(combined))
}

/// Split a singlesig wallet into VSS shares
///
/// # Arguments
/// * `wallet` - The singlesig wallet to split
/// * `threshold` - Minimum number of shares needed to reconstruct (M in M-of-N)
/// * `total_shares` - Total number of shares to create (N in M-of-N)
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
/// A vector of `VssJsonWalletDescriptionV0` structs, each containing a share and the wallet metadata
pub fn split_singlesig_wallet<R: rand::RngCore + rand::CryptoRng>(
    wallet: &crate::wallet_description::SinglesigJsonWalletDescriptionV0,
    threshold: u8,
    total_shares: u8,
    is_duress: bool,
    rng: &mut R,
) -> Result<Vec<crate::wallet_description::VssJsonWalletDescriptionV0>> {
    use std::sync::Arc;

    // Parse the mnemonic from the wallet
    let mnemonic =
        Mnemonic::parse(&wallet.seed_phrase).context("Failed to parse mnemonic from wallet")?;

    // Refuse to embed metadata derived from a non-default BIP-39
    // passphrase. The recovery path
    // (`combine_vss_wallets` → `rebuild_singlesig(&None, ..)` /
    //  `to_singlesig`) authenticates the share metadata against the
    // *no-passphrase* derivation of the recovered seed, so a
    // passphrase-derived xpub baked into the shares would either:
    //   - render the share set unrecoverable (xpub mismatch on the
    //     authentication step), or
    //   - if `is_duress` is set, leak the hidden wallet's identity
    //     into every share file (defeating plausible deniability —
    //     an attacker who decrypted one share would see the real
    //     wallet's xpub and first address instead of the decoy's).
    // The CLI avoids both by always passing the no-passphrase /
    // decoy wallet, but the public core API must enforce the same
    // invariant for callers that bypass the CLI.
    {
        let secp_check = crate::random_generation_utils::get_secp(rng);
        let network = bitcoin::Network::from_str(&wallet.network).with_context(|| {
            format!("invalid network in wallet metadata: {}", wallet.network)
        })?;
        let script_type = crate::wallet_description::ScriptType::from_str(&wallet.script_type)
            .with_context(|| {
                format!("invalid script type in wallet metadata: {}", wallet.script_type)
            })?;
        let no_passphrase_witness =
            crate::wallet_description::SingleSigWalletDescriptionV0::generate(
                Arc::new(SecretBox::new(Box::new(mnemonic.clone()))),
                &None,
                network,
                script_type,
                &secp_check,
            )?;
        anyhow::ensure!(
            no_passphrase_witness.encoded_singlesig_xpub() == wallet.singlesig_xpub,
            "Refusing to split: wallet metadata's xpub does not match the no-passphrase \
             derivation of its seed phrase. VSS share metadata is authenticated against the \
             no-passphrase wallet at recovery time; passing a passphrase-derived wallet here \
             would either render the share set unrecoverable (xpub mismatch on combine) or, \
             when `is_duress` is set, leak the hidden wallet's xpub into every share file. \
             Pass the no-passphrase / decoy wallet instead — for duress-mode backups, that is \
             the wallet you opened *without* supplying the BIP-39 passphrase."
        );
    }

    // Split the mnemonic into shares
    let shares = split_mnemonic(&mnemonic, threshold, total_shares, rng)?;

    // Convert each share to a VssJsonWalletDescriptionV0 carrying only public
    // metadata about the wallet — the seed phrase and xprivs are NOT embedded.
    // `Share` derives `ZeroizeOnDrop` (so its hex-encoded secret/blinder
    // strings get wiped from the heap when this scope ends) which means
    // we can't move the fields out — clone them into the VSS wallet
    // wrapper instead. Cloning the hex strings is cheap; the original
    // `Share` is dropped (and zeroized) at the end of the iteration.
    let mut vss_wallets = Vec::with_capacity(shares.len());
    for share in &shares {
        let mnemonic_length = u8::try_from(share.mnemonic_length)
            .context("mnemonic length does not fit in u8")?;
        let vss_wallet = crate::wallet_description::VssJsonWalletDescriptionV0::from_singlesig(
            wallet,
            share.share_index,
            share.threshold,
            share.total_shares,
            mnemonic_length,
            share.share_data.clone(),
            share.blinder_share_data.clone(),
            share.verification_data.clone(),
            share.share_data_hi.clone(),
            share.blinder_share_data_hi.clone(),
            share.verification_data_hi.clone(),
            is_duress,
        );
        vss_wallets.push(vss_wallet);
    }
    drop(shares);

    Ok(vss_wallets)
}

/// Combine VSS wallet shares to reconstruct the original wallet
///
/// # Arguments
/// * `vss_wallets` - A slice of `VssJsonWalletDescriptionV0` (must have at least threshold shares)
///
/// # Returns
/// A `VssRecovery` containing the reconstructed mnemonic plus the chosen
/// group's metadata (so callers can surface, e.g., a duress-mode warning).
///
/// # Security Notes
/// - Verifies all shares using Pedersen commitments before reconstruction
/// - Validates the reconstructed mnemonic has a valid BIP-39 checksum
/// - All intermediate values are zeroized after use
pub fn combine_vss_wallets(
    vss_wallets: &[crate::wallet_description::VssJsonWalletDescriptionV0],
) -> Result<VssRecovery> {
    if vss_wallets.is_empty() {
        bail!(anyhow!("No VSS wallets provided"));
    }

    // We deliberately do NOT filter out shares whose `wallet_type`
    // metadata says "multisig". That tag is mutable JSON; an attacker
    // (or just a corrupted byte) editing it on an otherwise valid
    // share would, with a prefilter, turn a metadata-only problem
    // into a hard recovery failure on exact-threshold inputs (e.g.
    // 2-of-2). The cryptographic recovery only consumes
    // `share_data`/`blinder_share_data`/`verification_data`, all of
    // which exist on every share regardless of wallet_type, so let the
    // grouping + per-share Pedersen verification decide. Downstream
    // metadata derivation (`derive_metadata`) already handles a
    // Multisig variant by falling back to defaults — but we never
    // discard the share's secret bytes for it.
    let vss_wallets_owned: Vec<&crate::wallet_description::VssJsonWalletDescriptionV0> =
        vss_wallets.iter().collect();
    let vss_wallets: &[&crate::wallet_description::VssJsonWalletDescriptionV0] =
        &vss_wallets_owned;

    // Iterate verifier *candidates* — pairs of (lo_verifier_hex,
    // optional hi_verifier_hex) found in the input — instead of
    // grouping shares by their declared verifier strings. Verifying
    // every input share's secret/blinder against the candidate
    // verifier (rather than the share's own copy) means that a
    // share whose `verification_data` was corrupted but whose
    // `share_data` is still valid for the real polynomial gets picked
    // up by the candidate carrying the real verifier. Without this,
    // an exact-threshold recovery (e.g. 3-of-3) would be lost when
    // any single share's verifier copy was bit-flipped, even though
    // the cryptographic shares themselves were intact.
    //
    // For each candidate verifier pair, we then re-clone the input
    // shares, overwrite their `verification_data*` with the candidate
    // verifier, and pass them through `combine_shares_to_mnemonic`.
    // The internal Pedersen check inside that function will drop any
    // share whose secret/blinder bytes don't lie on the candidate
    // polynomial, so unrelated splits in the same input get filtered
    // per candidate.
    type CandidateVerifier<'a> = (&'a str, Option<&'a str>);
    // Enumerate the *cross product* of distinct lo verifiers and
    // distinct hi verifiers (plus `None` for hi, which models a
    // 12-word backup). For 24-word exact-threshold recoveries where
    // verifier-copy corruption independently hit the lo half on one
    // share and the hi half on another share, the correct lo and hi
    // verifiers both still exist in the input but never coexist on a
    // single share — so an "only try (lo, hi) pairs as carried by
    // some share" enumeration would miss the recoverable
    // (good_lo_from_share_B, good_hi_from_share_A) combination.
    // Cross-product enumeration covers that case while keeping the
    // candidate count bounded by O(N²) in the worst case (in
    // practice: 1-2 distinct lo's, 1-2 distinct hi's, well below 10
    // candidates).
    let mut distinct_los_set: std::collections::BTreeSet<&str> =
        std::collections::BTreeSet::new();
    let mut distinct_los: Vec<&str> = Vec::new();
    let mut distinct_his_set: std::collections::BTreeSet<&str> =
        std::collections::BTreeSet::new();
    let mut distinct_his: Vec<&str> = Vec::new();
    for w in vss_wallets {
        if distinct_los_set.insert(w.verification_data.as_str()) {
            distinct_los.push(w.verification_data.as_str());
        }
        if let Some(h) = w.verification_data_hi.as_deref()
            && distinct_his_set.insert(h)
        {
            distinct_his.push(h);
        }
    }
    let mut seen_candidates: std::collections::BTreeSet<CandidateVerifier> =
        std::collections::BTreeSet::new();
    let mut candidates: Vec<CandidateVerifier> = Vec::new();
    for lo in &distinct_los {
        // (lo, None) candidate — used by 12-word backups, and pruned
        // below by the `los_with_hi` retain rule when we see a 24-word
        // companion for the same lo (so a hybrid-attack can't
        // downgrade a 24-word recovery to a 12-word one).
        let key: CandidateVerifier = (lo, None);
        if seen_candidates.insert(key) {
            candidates.push(key);
        }
        for hi in &distinct_his {
            let key: CandidateVerifier = (lo, Some(hi));
            if seen_candidates.insert(key) {
                candidates.push(key);
            }
        }
    }
    // For each lo verifier, drop the bogus `(lo, None)` candidate when
    // ANY input share carries a hi half for that same lo. The
    // strictness is asymmetric on purpose: returning a wrong 12-word
    // mnemonic from a hi-stripped 24-word split (which would happen
    // at exact-threshold when only the lo-only candidate succeeds)
    // is a much worse failure mode than refusing to recover a real
    // 12-word backup that has a single forged-hi share added — in
    // the latter case the user gets a clear error and can re-run
    // after removing the corrupted share. We choose fail-closed
    // against the seed-corruption attack.
    let los_with_hi: std::collections::BTreeSet<&str> = vss_wallets
        .iter()
        .filter_map(|w| {
            w.verification_data_hi
                .as_deref()
                .map(|_| w.verification_data.as_str())
        })
        .collect();
    candidates.retain(|(lo, hi)| !(hi.is_none() && los_with_hi.contains(lo)));
    // Try larger / more-recent verifiers first — purely to keep error
    // messages and side effects deterministic; the ambiguity check
    // below is what actually decides safety.
    candidates.sort_by(|a, b| {
        let a_count = vss_wallets
            .iter()
            .filter(|w| {
                w.verification_data == *a.0
                    && w.verification_data_hi.as_deref() == a.1
            })
            .count();
        let b_count = vss_wallets
            .iter()
            .filter(|w| {
                w.verification_data == *b.0
                    && w.verification_data_hi.as_deref() == b.1
            })
            .count();
        b_count.cmp(&a_count)
    });

    // (mnemonic, verified_inputs, lo_verifier_hex, hi_verifier_hex)
    type SuccessEntry<'a> = (
        SecretBox<Mnemonic>,
        Vec<&'a crate::wallet_description::VssJsonWalletDescriptionV0>,
        String,
        Option<String>,
    );
    let mut successes: Vec<SuccessEntry> = Vec::new();
    let mut last_err: Option<anyhow::Error> = None;
    let mut tried = 0usize;
    for candidate in &candidates {
        let (lo_hex, hi_hex_opt) = candidate;
        let candidate_threshold = match threshold_from_pedersen(lo_hex) {
            Ok(t) => t,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        if vss_wallets.len() < candidate_threshold as usize {
            continue;
        }
        tried += 1;

        // Build Share structs that pretend each input share carries
        // the candidate verifier. The internal verification will then
        // drop those whose secret/blinder bytes don't lie on the
        // candidate polynomial.
        let mut shares = Vec::with_capacity(vss_wallets.len());
        for wallet in vss_wallets {
            let mut share = Share {
                version: wallet.version,
                scheme: "pedersen".to_string(),
                share_index: wallet.share_index,
                threshold: wallet.threshold,
                total_shares: wallet.total_shares,
                mnemonic_length: wallet.mnemonic_length as usize,
                share_data: wallet.share_data.clone(),
                blinder_share_data: wallet.blinder_share_data.clone(),
                verification_data: lo_hex.to_string(),
                share_data_hi: wallet.share_data_hi.clone(),
                blinder_share_data_hi: wallet.blinder_share_data_hi.clone(),
                verification_data_hi: hi_hex_opt.map(|s| s.to_string()),
                created_at: wallet.created_at.clone(),
                checksum: String::new(),
            };
            share.checksum = share.compute_checksum();
            shares.push(share);
        }
        match combine_shares_to_mnemonic(&shares) {
            Ok(secret) => {
                // Capture which input shares actually verified against
                // this candidate verifier, for downstream metadata
                // derivation. (combine_shares_to_mnemonic already did
                // the verification, but we need the raw input wallets,
                // not the cloned Shares, to derive the public
                // metadata / xpub etc.)
                let lo_set = parse_ristretto_points(lo_hex).ok();
                let hi_set = hi_hex_opt.and_then(|h| parse_ristretto_points(h).ok());
                let verifies_lo =
                    |w: &crate::wallet_description::VssJsonWalletDescriptionV0| -> bool {
                        let set = match &lo_set {
                            Some(s) => s,
                            None => return false,
                        };
                        let Ok(sb) = hex::decode(&w.share_data) else {
                            return false;
                        };
                        let Ok(bb) = hex::decode(&w.blinder_share_data) else {
                            return false;
                        };
                        set.verify_share_and_blinder(&sb, &bb).is_ok()
                    };
                let verifies_hi =
                    |w: &crate::wallet_description::VssJsonWalletDescriptionV0| -> bool {
                        let set = match &hi_set {
                            Some(s) => s,
                            None => return true, // 12-word: no hi half ⇒ vacuously OK
                        };
                        let (Some(s), Some(b)) =
                            (w.share_data_hi.as_deref(), w.blinder_share_data_hi.as_deref())
                        else {
                            return false;
                        };
                        let Ok(sb) = hex::decode(s) else {
                            return false;
                        };
                        let Ok(bb) = hex::decode(b) else {
                            return false;
                        };
                        set.verify_share_and_blinder(&sb, &bb).is_ok()
                    };
                let verified_inputs: Vec<&crate::wallet_description::VssJsonWalletDescriptionV0> =
                    vss_wallets
                        .iter()
                        .copied()
                        .filter(|w| verifies_lo(w) && verifies_hi(w))
                        .collect();
                if !verified_inputs.is_empty() {
                    successes.push((
                        secret,
                        verified_inputs,
                        lo_hex.to_string(),
                        hi_hex_opt.map(|s| s.to_string()),
                    ));
                }
            }
            Err(e) => last_err = Some(e),
        }
    }

    // Compute the public metadata that should be exposed for a given
    // candidate group. Pulled out so that the collapse path below can
    // peek at each group's metadata without consuming `successes`.
    let derive_metadata = |group: &[&crate::wallet_description::VssJsonWalletDescriptionV0],
                           lo_pedersen: &str,
                           hi_pedersen: Option<&str>|
     -> crate::wallet_description::SinglesigPublicMetadataV0 {
        // Use the *winning* verifier (the one that produced this
        // candidate's successful recovery) — NOT `group[0].verification_data`,
        // because the first share in the verified group might be the
        // one whose verifier copy was corrupted.
        let verifier_lo = parse_ristretto_points(lo_pedersen).ok();
        let verifier_hi = hi_pedersen.and_then(|hex| parse_ristretto_points(hex).ok());
        let share_passes = |w: &crate::wallet_description::VssJsonWalletDescriptionV0| -> bool {
            let lo_set = match &verifier_lo {
                Some(v) => v,
                None => return false,
            };
            let lo_bytes = match hex::decode(&w.share_data) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let lo_blinder = match hex::decode(&w.blinder_share_data) {
                Ok(b) => b,
                Err(_) => return false,
            };
            if lo_set
                .verify_share_and_blinder(&lo_bytes, &lo_blinder)
                .is_err()
            {
                return false;
            }
            if let Some(hi_set) = &verifier_hi {
                let (hi_bytes_hex, hi_blinder_hex) =
                    match (&w.share_data_hi, &w.blinder_share_data_hi) {
                        (Some(s), Some(b)) => (s, b),
                        _ => return false,
                    };
                let hi_bytes = match hex::decode(hi_bytes_hex) {
                    Ok(b) => b,
                    Err(_) => return false,
                };
                let hi_blinder = match hex::decode(hi_blinder_hex) {
                    Ok(b) => b,
                    Err(_) => return false,
                };
                if hi_set
                    .verify_share_and_blinder(&hi_bytes, &hi_blinder)
                    .is_err()
                {
                    return false;
                }
            }
            true
        };
        let verified: Vec<&crate::wallet_description::VssJsonWalletDescriptionV0> =
            group.iter().copied().filter(|w| share_passes(w)).collect();
        // Dedupe by the **cryptographic** share identifier (first byte
        // of decoded `share_data`) — NOT the mutable `share_index`
        // JSON field. Within each id's bucket the share-data bytes
        // are byte-identical (two shares with the same id that both
        // passed Pedersen verification are forced to coincide on the
        // polynomial), but the surrounding `original_wallet` metadata
        // can differ if the same share file was supplied multiple
        // times with different metadata copies. We therefore group
        // first, and only count the share's metadata vote if EVERY
        // copy of that id agrees on the metadata. Otherwise the
        // share's metadata is "indeterminate" and we abstain — first-
        // wins would let input order decide whose metadata propagates,
        // which on exact-threshold inputs can shift the strict-majority
        // outcome.
        let mut by_id: std::collections::BTreeMap<
            u8,
            Vec<&crate::wallet_description::VssJsonWalletDescriptionV0>,
        > = std::collections::BTreeMap::new();
        for w in &verified {
            let crypto_id = hex::decode(&w.share_data)
                .ok()
                .and_then(|b| b.first().copied())
                .unwrap_or(w.share_index);
            by_id.entry(crypto_id).or_default().push(*w);
        }
        let deduped: Vec<&crate::wallet_description::VssJsonWalletDescriptionV0> = by_id
            .into_values()
            .filter_map(|copies| {
                let first_meta = &copies[0].original_wallet;
                if copies.iter().all(|w| w.original_wallet == *first_meta) {
                    Some(copies[0])
                } else {
                    None
                }
            })
            .collect();
        // If every cryptographic share id had conflicting metadata
        // copies (so `deduped` is empty), abstain entirely — falling
        // back to `group` would re-count the duplicates and let extra
        // forged copies manufacture a strict majority of bogus
        // metadata. Returning the default empty metadata is the
        // fail-closed answer: the seed itself still recovers, but no
        // metadata is propagated.
        if deduped.is_empty() {
            return crate::wallet_description::SinglesigPublicMetadataV0::default();
        }
        let tally_source: &[&crate::wallet_description::VssJsonWalletDescriptionV0] = &deduped;
        // Exclude `is_duress` from the metadata vote — it's aggregated
        // separately (below) as "any-share-duress wins". Otherwise a
        // single-bit `is_duress` flip on one share would tie the vote
        // (1 vs 1 in exact-threshold recovery), the strict-majority
        // guard would fall back to default metadata, and
        // `VssRecovery::rebuild_singlesig` would then fail on the
        // empty `network` / `script_type` even though the rest of the
        // metadata is intact.
        let canonicalize_duress =
            |o: &crate::wallet_description::OriginalWalletJson|
             -> crate::wallet_description::OriginalWalletJson {
                match o {
                    crate::wallet_description::OriginalWalletJson::Singlesig(m) => {
                        let mut m_copy = m.clone();
                        m_copy.is_duress = false;
                        crate::wallet_description::OriginalWalletJson::Singlesig(m_copy)
                    }
                    crate::wallet_description::OriginalWalletJson::Multisig(m) => {
                        crate::wallet_description::OriginalWalletJson::Multisig(m.clone())
                    }
                }
            };
        let mut counts: Vec<(usize, crate::wallet_description::OriginalWalletJson)> = Vec::new();
        for w in tally_source {
            let key = canonicalize_duress(&w.original_wallet);
            if let Some(entry) = counts.iter_mut().find(|e| e.1 == key) {
                entry.0 += 1;
            } else {
                counts.push((1, key));
            }
        }
        // Require a *strict* majority: the top metadata variant must
        // have more than half of the deduped, verified votes. On a tie
        // (e.g. exact-threshold recovery with one tampered share)
        // there is no authoritative answer, so we return the empty
        // default metadata rather than picking the first variant in
        // input order — that way callers using `xpub` / `network` /
        // `script_type` to identify the wallet see blank fields and
        // know not to trust them, while mnemonic recovery itself
        // still proceeds.
        //
        // `is_duress` is aggregated separately (strict majority over
        // verified shares) so the warning is still surfaced reliably
        // when the rest of the metadata vote ties.
        let total_votes: usize = counts.iter().map(|(c, _)| *c).sum();
        let top_count = counts.iter().map(|(c, _)| *c).max().unwrap_or(0);
        let top_groups = counts.iter().filter(|(c, _)| *c == top_count).count();
        // Aggregate `is_duress` by *strict majority* over the deduped
        // verified set. Any-share-says-so used to be the rule, but a
        // single tampered share with `is_duress=true` would then
        // authorize a passphrase restore via
        // `VssRecovery::rebuild_singlesig(Some(_))` and silently
        // return whatever wallet that passphrase derives. Strict
        // majority is the safer direction — a single tampered share
        // can at worst suppress a real duress flag, which forces the
        // user to recover the decoy view first (annoying but
        // non-destructive) instead of fabricating a duress flag that
        // hands an attacker-controlled wallet to the user.
        let duress_yes = tally_source
            .iter()
            .filter(|w| match &w.original_wallet {
                crate::wallet_description::OriginalWalletJson::Singlesig(m) => m.is_duress,
                crate::wallet_description::OriginalWalletJson::Multisig(_) => false,
            })
            .count();
        let any_duress = duress_yes * 2 > tally_source.len();
        let strict_majority = top_groups == 1 && top_count * 2 > total_votes;
        let mut metadata = if strict_majority {
            let majority = &counts
                .iter()
                .max_by_key(|(c, _)| *c)
                .expect("non-empty group")
                .1;
            match majority {
                crate::wallet_description::OriginalWalletJson::Singlesig(m) => m.clone(),
                crate::wallet_description::OriginalWalletJson::Multisig(_) => {
                    crate::wallet_description::SinglesigPublicMetadataV0::default()
                }
            }
        } else {
            log::warn!(
                "Pedersen-verified share group has conflicting `original_wallet` metadata \
                 ({top_groups} variants tied at the top, top_count={top_count} of total_votes={total_votes}); \
                 no strict majority — returning empty metadata so callers don't trust an \
                 attacker-controlled xpub/network/script_type"
            );
            crate::wallet_description::SinglesigPublicMetadataV0::default()
        };
        metadata.is_duress = any_duress;
        metadata
    };

    let to_recovery = |successes: &mut Vec<SuccessEntry>| -> VssRecovery {
        let chosen = successes.pop().expect("non-empty successes");
        let metadata = derive_metadata(&chosen.1, &chosen.2, chosen.3.as_deref());
        VssRecovery {
            mnemonic: chosen.0,
            metadata,
        }
    };

    // Final authentication step: ensure the recovered mnemonic actually
    // belongs to the wallet described by the recovered metadata. This
    // turns combine_vss_wallets into a single-call safe API — every
    // caller (CLI or otherwise) gets the seed-vs-xpub check enforced
    // by the lib, instead of having to remember to call
    // `rebuild_singlesig` themselves.
    //
    // Returns Err when:
    //   * The recovered metadata is empty (per-group majority vote
    //     tied across all candidates) — in that state we have no xpub
    //     to authenticate against, and silently returning the
    //     unauthenticated mnemonic would let metadata-only tampering
    //     downgrade a 24-word to a wrong 12-word, or splice halves
    //     from different wallets into a hybrid mnemonic.
    //   * The reconstructed wallet's no-passphrase xpub doesn't match
    //     the metadata's `singlesig_xpub`.
    let authenticate = |recovery: VssRecovery| -> Result<VssRecovery> {
        if recovery.metadata.singlesig_xpub.is_empty()
            || recovery.metadata.network.is_empty()
        {
            bail!(
                "Recovered mnemonic could not be authenticated: the per-group share \
                 metadata vote tied across all candidates, leaving no authoritative \
                 xpub to cross-check the seed against. Re-run with the specific \
                 share files for the wallet you intend to recover, or remove \
                 conflicting / tampered share(s) and try again."
            );
        }
        let mut sanity_rng = rand::thread_rng();
        let sanity_secp = crate::random_generation_utils::get_secp(&mut sanity_rng);
        recovery
            .rebuild_singlesig(&None, &sanity_secp)
            .context(
                "Recovered mnemonic does not match the share metadata's xpub — the \
                 share set may have been tampered with",
            )?;
        Ok(recovery)
    };

    match successes.len() {
        0 => Err(match last_err {
            Some(e) => e.context(format!(
                "All {tried} candidate share group(s) failed to combine ({} input(s) total)",
                vss_wallets.len()
            )),
            None => anyhow!(
                "No threshold-compatible subset of shares found among the {} input(s)",
                vss_wallets.len()
            ),
        }),
        1 => authenticate(to_recovery(&mut successes)),
        _ => {
            // Collapse: if every successful group recovered the *same*
            // mnemonic (e.g. the user re-split the same wallet and kept
            // both backups in the same directory), there is no real
            // ambiguity and we can return that mnemonic. We only error
            // when at least two groups recovered *different* mnemonics —
            // that's the case where silently picking one would risk
            // recovering the wrong wallet.
            //
            // Compare `&Mnemonic` directly (it derives `PartialEq`) rather
            // than via `to_string()` — the latter would copy the seed
            // phrase out into a non-zeroizing heap String just to perform
            // an equality check.
            let first_mnemonic: &Mnemonic = successes[0].0.expose_secret();
            let all_identical = successes
                .iter()
                .skip(1)
                .all(|(s, _, _, _)| s.expose_secret() == first_mnemonic);
            if all_identical {
                // The mnemonic matches across groups — collapse safely
                // as long as the per-group metadata doesn't carry
                // contradictory authoritative values. Empty (default)
                // metadata isn't a contradiction; it just means that
                // candidate had a tied vote and abstained. So we
                // compare *non-empty* derived metadata only:
                //   - all candidates derived empty metadata ⇒ collapse,
                //     return empty metadata (caller will warn).
                //   - exactly one distinct non-empty metadata across
                //     candidates ⇒ collapse, return that one.
                //   - two or more distinct non-empty metadatas
                //     (e.g. Bitcoin vs Testnet for the same seed) ⇒
                //     ambiguity error.
                let derived: Vec<crate::wallet_description::SinglesigPublicMetadataV0> = successes
                    .iter()
                    .map(|(_, group, lo, hi)| derive_metadata(group, lo, hi.as_deref()))
                    .collect();
                let is_empty =
                    |m: &crate::wallet_description::SinglesigPublicMetadataV0| -> bool {
                        m.singlesig_xpub.is_empty() || m.network.is_empty()
                    };
                // Two compatibility checks that BOTH must pass for a
                // collapse to be safe:
                //   (1) The non-empty wallet-identity metadata
                //       (xpub/network/script_type/…) must agree across
                //       all candidates that have it. Empty metadata
                //       just means "abstain" and doesn't conflict.
                //   (2) The is_duress flag must agree across ALL
                //       candidates, including those whose
                //       wallet-identity metadata is empty. Otherwise a
                //       duress candidate whose xpub vote tied could
                //       silently collapse with a normal candidate, and
                //       the user would lose either the duress warning
                //       or the ability to do a passphrase restore.
                let mut non_empty: Vec<&crate::wallet_description::SinglesigPublicMetadataV0> =
                    derived.iter().filter(|m| !is_empty(m)).collect();
                let identity_agrees = match non_empty.len() {
                    0 => true,
                    _ => {
                        let first = non_empty.remove(0);
                        non_empty.iter().all(|m| **m == *first)
                    }
                };
                let duress_agrees = derived
                    .iter()
                    .skip(1)
                    .all(|m| m.is_duress == derived[0].is_duress);
                let safe_to_collapse = identity_agrees && duress_agrees;
                if safe_to_collapse {
                    // Prefer the candidate that produced non-empty
                    // metadata (so the caller gets the authenticated
                    // metadata to cross-check against). If none are
                    // non-empty, any candidate works.
                    let prefer_idx = derived.iter().position(|m| !is_empty(m));
                    if let Some(idx) = prefer_idx {
                        let last = successes.len() - 1;
                        successes.swap(idx, last);
                    }
                    return authenticate(to_recovery(&mut successes));
                }
                // Metadata conflict ⇒ fall through to the ambiguity
                // error path below, which will list the candidate xpubs
                // / configurations so the user can disambiguate.
            }
            let n = successes.len();
            // Use the *authenticated* per-group metadata (the same
            // strict-majority / abstain logic applied during recovery)
            // for the disambiguation hint. Reading xpub/duress straight
            // off the first share would let a single tampered share
            // make the user think they're picking a different wallet
            // than they actually are.
            let summary: Vec<String> = successes
                .iter()
                .map(|(_, group, lo, hi)| {
                    let derived = derive_metadata(group, lo, hi.as_deref());
                    describe_share_group(group, &derived)
                })
                .collect();
            // SecretBox<Mnemonic> values in `successes` are zeroized on drop
            // when this scope exits, so the rejected secrets do not linger.
            Err(anyhow!(
                "Ambiguous input: {n} independent share sets recovered different wallets. Re-run with the specific share files for the wallet you want. Candidates:\n{}",
                summary.join("\n")
            ))
        }
    }
}

/// Build a one-line description of a share group for inclusion in
/// disambiguation errors. Includes the wallet's xpub, threshold, share
/// indexes, the most recent `created_at`, AND the per-group
/// duress-vs-normal designation — important because two groups for the
/// SAME seed (one normal split, one duress split) would otherwise look
/// identical (same decoy xpub, same indexes), giving the user no way
/// to pick between them.
fn describe_share_group(
    group: &[&crate::wallet_description::VssJsonWalletDescriptionV0],
    derived: &crate::wallet_description::SinglesigPublicMetadataV0,
) -> String {
    // Use the *derived* (strict-majority / abstain) metadata for the
    // user-visible hint, NOT the first share's raw metadata. A single
    // tampered share would otherwise be able to forge the disambiguation
    // hint by claiming a different xpub or duress label.
    let xpub_hint: &str = if derived.singlesig_xpub.is_empty() {
        "<unauthenticated — share metadata vote tied>"
    } else {
        derived.singlesig_xpub.as_str()
    };
    let duress_label = if derived.is_duress { "yes" } else { "no" };
    let mut indexes: Vec<u8> = group.iter().map(|w| w.share_index).collect();
    indexes.sort_unstable();
    indexes.dedup();
    let newest = group
        .iter()
        .map(|w| w.created_at.as_str())
        .max()
        .unwrap_or("<unknown>");
    let threshold = group.first().map(|w| w.threshold).unwrap_or(0);
    let total = group.first().map(|w| w.total_shares).unwrap_or(0);
    format!(
        "  • xpub={xpub_hint} threshold={threshold}/{total} share_indexes={indexes:?} duress={duress_label} newest={newest}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine_12_words() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

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
        let mut rng = rand::thread_rng();

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
        let mut rng = rand::thread_rng();

        let shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();

        // Try to combine with only 2 shares (need 3)
        let result = combine_shares_to_mnemonic(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let result = split_mnemonic(&mnemonic, 5, 3, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_checksum_verification() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();

        // Verify checksum on a fresh share
        assert!(shares[0].verify_checksum().is_ok());

        // The checksum must cover EVERY field that is critical for
        // reconstruction: secret share data, blinder share data, and the
        // Pedersen verifier set. A single byte flipped in any of these
        // must be caught at load time.
        for tamper in [
            |s: &mut Share| s.share_data = "deadbeef".to_string(),
            |s: &mut Share| s.blinder_share_data = "deadbeef".to_string(),
            |s: &mut Share| s.verification_data = "deadbeef,deadbeef,deadbeef,deadbeef".to_string(),
        ] {
            let mut corrupted = shares[0].clone();
            tamper(&mut corrupted);
            assert!(
                corrupted.verify_checksum().is_err(),
                "checksum did not catch a tamper that should have been authenticated"
            );
        }
    }

    /// Property test: 100 random 24-word mnemonics must each round-trip
    /// through split + combine exactly.
    ///
    /// This is the regression test for the Curve25519 mod-order reduction
    /// bug. Before the two-half split, ~91% of random 24-word entropies
    /// landed above the scalar order and silently round-tripped to a
    /// *different* valid mnemonic. With the entropy split into two 16-byte
    /// halves, each half is < 2^128 ≪ scalar order, so reduction is
    /// impossible.
    #[test]
    fn test_random_24_word_round_trip() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let mut entropy = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            let shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();
            let recovered = combine_shares_to_mnemonic(&shares[1..4]).unwrap();
            assert_eq!(
                recovered.expose_secret().to_string(),
                mnemonic.to_string(),
                "24-word mnemonic failed to round-trip; entropy was {:x?}",
                entropy
            );
        }
    }

    /// Property test: same as above but for 12-word mnemonics, just to keep
    /// both lengths exercised on every CI run.
    #[test]
    fn test_random_12_word_round_trip() {
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let mut entropy = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rng, &mut entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
            let recovered = combine_shares_to_mnemonic(&shares[0..2]).unwrap();
            assert_eq!(
                recovered.expose_secret().to_string(),
                mnemonic.to_string(),
            );
        }
    }

    /// End-to-end test of `split_singlesig_wallet` → `combine_vss_wallets` →
    /// `to_singlesig`, including the xpub re-validation. Also confirms that
    /// each VSS share file no longer carries the seed phrase or any xpriv.
    #[test]
    fn test_vss_singlesig_round_trip_no_secret_leak() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(seed_phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json = SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp)
            .unwrap();

        let vss_wallets = split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap();
        assert_eq!(vss_wallets.len(), 3);

        // The serialized share must not contain the seed phrase or any xpriv —
        // those are exactly the secrets the threshold scheme exists to protect.
        let serialized = serde_json::to_string(&vss_wallets[0]).unwrap();
        assert!(
            !serialized.contains(seed_phrase),
            "VSS share leaked the seed phrase"
        );
        assert!(
            !serialized.contains("xprv"),
            "VSS share leaked an xpriv: {serialized}"
        );

        // Reconstruct via the public API.
        let recovered = combine_vss_wallets(&vss_wallets[0..2]).unwrap();
        let recovered_phrase = recovered.mnemonic.expose_secret().to_string();
        assert_eq!(recovered_phrase, seed_phrase);

        // to_singlesig should rebuild the wallet from the recovered mnemonic
        // + the share metadata, and pass the xpub re-validation.
        let rebuilt = vss_wallets[0]
            .to_singlesig(&recovered_phrase, &None, &secp)
            .unwrap();
        assert_eq!(rebuilt.encoded_singlesig_xpub(), wallet.encoded_singlesig_xpub());
    }

    /// The public `split_singlesig_wallet` API must refuse a wallet
    /// whose embedded xpub was derived from a non-default BIP-39
    /// passphrase. The recovery path authenticates against the
    /// no-passphrase derivation; a passphrase-derived xpub baked into
    /// shares would either render them unrecoverable (xpub mismatch)
    /// or, for `is_duress=true`, leak the hidden wallet's identity.
    /// The CLI happens to always pass the no-passphrase decoy, but a
    /// library caller could pass a passphrase-derived wallet and
    /// silently get unsafe shares — the core API enforces the
    /// invariant.
    #[test]
    fn test_split_singlesig_rejects_passphrase_derived_wallet() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        // Build a wallet whose xpub is derived from a non-empty
        // BIP-39 passphrase. Its `seed_phrase` field still carries
        // the same (passphrase-independent) mnemonic, but its
        // `singlesig_xpub` is the passphrase-derived one.
        let real_password = Arc::new(secrecy::SecretString::from(
            "real wallet passphrase".to_string(),
        ));
        let passphrase_wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &Some(real_password),
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json = SinglesigJsonWalletDescriptionV0::from_wallet_description(
            &passphrase_wallet,
            &secp,
        )
        .unwrap();

        let err = match split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng) {
            Ok(_) => panic!("expected split_singlesig_wallet to refuse a passphrase-derived wallet"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Refusing to split")
                && msg.contains("no-passphrase"),
            "expected refusal pointing at the no-passphrase invariant, got: {msg}"
        );

        // And the same refusal must fire when is_duress=true (this is
        // the case where silently accepting would leak the hidden
        // wallet's xpub via every share file).
        let err = match split_singlesig_wallet(json.expose_secret(), 2, 3, true, &mut rng) {
            Ok(_) => panic!("expected refusal in duress mode too"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Refusing to split"),
            "expected refusal in duress mode, got: {msg}"
        );
    }

    /// `generate_encrypted_encoded_vss_wallet` must succeed with the
    /// DEFAULT padding params for a 24-word share. The compressed VSS
    /// payload for a 24-word wallet routinely exceeds the 1200-byte
    /// minimum-ciphertext floor (extra share/blinder half plus a
    /// second Pedersen verifier set), so a padder that hard-errored on
    /// "pre-pad size > minimum" would block the common case.
    #[test]
    fn test_vss_encrypt_succeeds_with_default_padding_for_24_word() {
        use crate::random_generation_utils::{get_random_key, get_random_nonce, get_random_salt, get_secp};
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
            EncryptedWalletVersion,
        };
        use crate::{
            PaddingParams, generate_encrypted_encoded_vss_wallet, get_padder,
            key_derivation::{KeyDerivationDifficulty, default_derive_key},
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        // 24-word fixture (largest standard mnemonic).
        let phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        let vss = split_singlesig_wallet(json.expose_secret(), 3, 5, false, &mut rng).unwrap();

        let salt = get_random_salt(&mut rng).unwrap();
        let nonce = get_random_nonce(&mut rng).unwrap();
        let header_nonce = get_random_nonce(&mut rng).unwrap();
        let padding_params = PaddingParams::default();
        let padder = get_padder(&mut rng, &padding_params).unwrap();
        let password = Arc::new(secrecy::SecretString::from("test password".to_string()));
        let key = default_derive_key(&password, &[], &salt, &KeyDerivationDifficulty::Easy).unwrap();
        let header_key = SecretBox::from(Box::new(get_random_key(&mut rng).unwrap()));

        // The actual smoke test: encryption must succeed even when the
        // VSS payload is already above the 1200-byte size floor.
        let encrypted = generate_encrypted_encoded_vss_wallet(
            &key,
            header_key,
            &vss[0],
            salt,
            nonce,
            header_nonce,
            padder,
            EncryptedWalletVersion::V0Standard,
        )
        .unwrap();
        assert!(!encrypted.is_empty());
    }

    /// Exact-threshold recovery (2-of-2) with one tampered share has
    /// no metadata majority. The chosen recovery must NOT return the
    /// attacker-controlled metadata just because it appeared first.
    /// With internal authentication (`combine_vss_wallets` rejects
    /// recoveries it cannot authenticate against an xpub), a tied
    /// metadata vote leaves no authoritative xpub to verify the seed
    /// against — combine must therefore Err out instead of returning
    /// an unauthenticated mnemonic. This test verifies that
    /// fail-closed behavior end-to-end.
    #[test]
    fn test_recovery_metadata_fails_closed_on_tie() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            OriginalWalletJson, ScriptType, SingleSigWalletDescriptionV0,
            SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();

        // 2-of-2 split: every share counts in the metadata vote.
        let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 2, false, &mut rng).unwrap();
        // Tamper with one of the two shares' xpub. Now the vote is
        // 1 (real) vs 1 (forgery) — no strict majority.
        if let OriginalWalletJson::Singlesig(ref mut m) = vss[0].original_wallet {
            m.singlesig_xpub = "zpub6tampered00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();
        }

        let err = match combine_vss_wallets(&vss) {
            Ok(_) => panic!("expected combine_vss_wallets to fail closed on tied metadata"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not be authenticated"),
            "expected fail-closed authentication error, got: {msg}"
        );
    }

    /// A single tampered share whose `original_wallet` metadata was
    /// rewritten to point at a *different* xpub must NOT be able to
    /// drive `VssRecovery.metadata` — otherwise a caller using that
    /// metadata to rebuild a wallet could be redirected to the
    /// attacker's chosen wallet. The chosen group's metadata is the
    /// majority across its shares, so a 1-of-N forgery cannot win.
    #[test]
    fn test_recovery_metadata_uses_majority_against_tampered_share() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            OriginalWalletJson, ScriptType, SingleSigWalletDescriptionV0,
            SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 5, false, &mut rng).unwrap();
        let real_xpub = match &vss[0].original_wallet {
            OriginalWalletJson::Singlesig(m) => m.singlesig_xpub.clone(),
            _ => panic!("expected singlesig"),
        };

        // Tamper with one share's xpub. Real metadata is in 4 of 5 shares
        // (majority); this forgery is in 1 of 5 (minority).
        if let OriginalWalletJson::Singlesig(ref mut m) = vss[0].original_wallet {
            m.singlesig_xpub =
                "zpub6tampered00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();
        }

        let recovered = combine_vss_wallets(&vss).unwrap();
        assert_eq!(
            recovered.metadata.singlesig_xpub, real_xpub,
            "metadata followed the tampered minority share — majority must win"
        );
    }

    /// A single share whose `is_duress` field was edited (false→true
    /// `is_duress` aggregation uses **strict majority** over the
    /// deduped, verified shares. A single tampered share can therefore
    /// neither *fabricate* duress on a normal split (which would
    /// authorize a passphrase restore via `rebuild_singlesig` and
    /// silently return an unrelated wallet) nor *suppress* duress on a
    /// real duress split when the majority of shares still assert it.
    #[test]
    fn test_combine_strict_majority_is_duress_aggregation() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            OriginalWalletJson, ScriptType, SingleSigWalletDescriptionV0,
            SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();

        // Real duress split with one share's is_duress flipped to
        // false: 2 of 3 still assert duress (strict majority) ⇒ the
        // recovery is still flagged as duress.
        let mut duress_vss =
            split_singlesig_wallet(json.expose_secret(), 2, 3, true, &mut rng).unwrap();
        if let OriginalWalletJson::Singlesig(ref mut m) = duress_vss[0].original_wallet {
            m.is_duress = false;
        }
        let recovered = combine_vss_wallets(&duress_vss).unwrap();
        assert!(
            recovered.metadata.is_duress,
            "single suppress attempt against a 3-share duress split must lose to majority"
        );

        // Normal split with one share's is_duress fabricated to true:
        // only 1 of 3 asserts duress (no strict majority) ⇒ the
        // recovery is NOT flagged as duress, and rebuild_singlesig
        // therefore refuses a passphrase — the attacker cannot use
        // this single-share tamper to authorize a passphrase restore.
        let mut normal_vss =
            split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap();
        if let OriginalWalletJson::Singlesig(ref mut m) = normal_vss[0].original_wallet {
            m.is_duress = true;
        }
        let recovered = combine_vss_wallets(&normal_vss).unwrap();
        assert!(
            !recovered.metadata.is_duress,
            "single fabricate attempt against a 3-share normal split must lose to majority"
        );
    }

    /// When a directory contains both a normal split AND a duress
    /// split of the same wallet, the two recovered mnemonics are
    /// identical, but their authenticated metadata DIFFERS (`is_duress`
    /// flag is different — and that flag drives a critical user-
    /// facing warning). Treating that as silently equivalent and
    /// returning one group's metadata would either suppress or
    /// fabricate the duress warning depending on input order, so the
    /// safer choice is to surface ambiguity. The user can disambiguate
    /// by passing a specific share-file list.
    #[test]
    fn test_combine_treats_normal_vs_duress_same_seed_as_ambiguous() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            OriginalWalletJson, ScriptType, SingleSigWalletDescriptionV0,
            SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut split = |is_duress: bool| {
            let mnemonic =
                SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
            let wallet = SingleSigWalletDescriptionV0::generate(
                Arc::new(mnemonic),
                &None,
                bitcoin::Network::Bitcoin,
                ScriptType::SegwitNative,
                &secp,
            )
            .unwrap();
            let json = SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp)
                .unwrap();
            split_singlesig_wallet(json.expose_secret(), 2, 3, is_duress, &mut rng).unwrap()
        };

        let normal = split(false);
        let duress = split(true);
        let mixed: Vec<_> = normal.iter().cloned().chain(duress.iter().cloned()).collect();

        // Sanity-check: the two share sets do carry different is_duress flags.
        let normal_duress = match &normal[0].original_wallet {
            OriginalWalletJson::Singlesig(m) => m.is_duress,
            _ => panic!("expected singlesig"),
        };
        let duress_duress = match &duress[0].original_wallet {
            OriginalWalletJson::Singlesig(m) => m.is_duress,
            _ => panic!("expected singlesig"),
        };
        assert!(!normal_duress);
        assert!(duress_duress);

        // Ambiguity error: the duress signal differs even though the
        // seed is the same.
        let err = match combine_vss_wallets(&mixed) {
            Ok(_) => panic!("expected ambiguity error on mixed normal+duress same-seed input"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Ambiguous input"),
            "expected ambiguity error, got: {msg}"
        );
    }

    /// `to_singlesig` must refuse a passphrase on a NORMAL share —
    /// otherwise a typo'd or accidentally-supplied passphrase would
    /// silently reconstruct an unrelated wallet (there is no on-disk
    /// witness for a passphrase-derived wallet on a normal share).
    #[test]
    fn test_to_singlesig_refuses_passphrase_on_normal_share() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        // is_duress=false: this is a normal share.
        let vss = split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap();
        let recovered = combine_vss_wallets(&vss[0..2]).unwrap();
        let recovered_phrase = recovered.mnemonic.expose_secret().to_string();

        // Without a passphrase: succeeds.
        vss[0]
            .to_singlesig(&recovered_phrase, &None, &secp)
            .unwrap();

        // With a passphrase: must be refused.
        let typo = Arc::new(secrecy::SecretString::from("oops typo".to_string()));
        let err = match vss[0].to_singlesig(&recovered_phrase, &Some(typo), &secp) {
            Ok(_) => panic!("expected to_singlesig to refuse a passphrase on a normal share"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not split in duress mode") || msg.contains("passphrase"),
            "expected duress-mode refusal, got: {msg}"
        );
    }

    /// External callers should restore the real wallet from a duress
    /// share set via `VssRecovery::rebuild_singlesig`, which makes the
    /// duress decision from group-aggregated metadata. This test
    /// covers that path: the share files were created in duress mode,
    /// recovery yields the seed, and rebuild_singlesig with the
    /// non-duress passphrase returns the real wallet (different from
    /// the decoy). It also verifies that the per-share `to_singlesig`
    /// REFUSES the same passphrase, so a tampered single share's
    /// is_duress flag can never sneak a passphrase restore through.
    #[test]
    fn test_vss_recovery_supports_duress_restore_with_passphrase() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let decoy = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let decoy_json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&decoy, &secp).unwrap();
        // is_duress=true on the split.
        let vss = split_singlesig_wallet(decoy_json.expose_secret(), 2, 3, true, &mut rng).unwrap();
        let recovered = combine_vss_wallets(&vss[0..2]).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
        assert!(recovered.metadata.is_duress);

        // Real-wallet restore via the safe API.
        let passphrase = Arc::new(secrecy::SecretString::from("non-duress secret".to_string()));
        let real = recovered
            .rebuild_singlesig(&Some(Arc::clone(&passphrase)), &secp)
            .unwrap();
        assert_ne!(real.encoded_singlesig_xpub(), decoy.encoded_singlesig_xpub());

        // Per-share path refuses passphrases (defense in depth).
        let err = match vss[0].to_singlesig(
            &recovered.mnemonic.expose_secret().to_string(),
            &Some(passphrase),
            &secp,
        ) {
            Ok(_) => panic!("per-share to_singlesig must refuse passphrases"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("VssRecovery::rebuild_singlesig"),
            "expected per-share refusal pointing at the safe API, got: {msg}"
        );
    }

    /// A share whose embedded singlesig_xpub has been swapped for a different
    /// wallet's xpub must be rejected by `to_singlesig`, even when the
    /// combined mnemonic is valid. This is the metadata-tamper guard.
    #[test]
    fn test_vss_to_singlesig_rejects_tampered_xpub() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            OriginalWalletJson, ScriptType, SingleSigWalletDescriptionV0,
            SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(seed_phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json = SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp)
            .unwrap();

        let mut vss_wallets =
            split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap();

        // Construct an unrelated wallet to source a valid-looking but wrong xpub.
        let other_phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let other_mnemonic =
            SecretBox::new(Box::new(bip39::Mnemonic::from_str(other_phrase).unwrap()));
        let other_wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(other_mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let bad_xpub = other_wallet.encoded_singlesig_xpub();

        if let OriginalWalletJson::Singlesig(ref mut m) = vss_wallets[0].original_wallet {
            // Sanity: the legitimate xpub differs from the impostor.
            assert_ne!(m.singlesig_xpub, bad_xpub);
            m.singlesig_xpub = bad_xpub.clone();
        } else {
            panic!("expected singlesig variant");
        }

        // Drive `to_singlesig` directly with the known-good seed phrase.
        // We deliberately do NOT go through `combine_vss_wallets` here:
        // that path now internally authenticates the recovered seed
        // against the share metadata's xpub and would reject this
        // tampered set before we got a chance to exercise the
        // per-share `to_singlesig` xpub guard. This test isolates the
        // `to_singlesig` xpub validation path.
        let err = match vss_wallets[0].to_singlesig(seed_phrase, &None, &secp) {
            Ok(_) => panic!("expected to_singlesig to reject the tampered xpub"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("xpub does not match"),
            "expected xpub-mismatch error, got: {msg}"
        );
    }

    /// If a directory contains two independent complete share sets that
    /// happen to back up the *same* wallet (e.g. the user re-ran
    /// `split-secret` on the same wallet and kept the older set), every
    /// candidate group recovers the same mnemonic and the result is
    /// unambiguous — `combine_vss_wallets` must collapse them and return
    /// that one mnemonic, not bail with an "ambiguous input" error.
    #[test]
    fn test_combine_collapses_identical_wallet_recoveries() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mut split_same = || {
            let mnemonic =
                SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
            let wallet = SingleSigWalletDescriptionV0::generate(
                Arc::new(mnemonic),
                &None,
                bitcoin::Network::Bitcoin,
                ScriptType::SegwitNative,
                &secp,
            )
            .unwrap();
            let json = SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp)
                .unwrap();
            split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap()
        };

        let set_old = split_same();
        let set_new = split_same();

        // Two independent complete 2-of-3 sets, each polynomial different
        // (different randomness) but reconstructing the same mnemonic.
        let mixed: Vec<_> = set_old
            .iter()
            .cloned()
            .chain(set_new.iter().cloned())
            .collect();

        let recovered = combine_vss_wallets(&mixed).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
    }

    /// `combine_vss_wallets` must:
    ///   (a) recover the only viable group when one set is complete and
    ///       the other has too few shares to combine; and
    ///   (b) refuse — with a disambiguation message — when more than one
    ///       independent share set is independently combinable AND they
    ///       recover *different* wallets, so the user cannot silently
    ///       recover the wrong wallet from a directory.
    #[test]
    fn test_combine_vss_wallets_handles_mixed_directories() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let phrase_a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let phrase_b = "legal winner thank year wave sausage worth useful legal winner thank yellow";

        let mut make_wallets = |phrase: &str| {
            let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
            let wallet = SingleSigWalletDescriptionV0::generate(
                Arc::new(mnemonic),
                &None,
                bitcoin::Network::Bitcoin,
                ScriptType::SegwitNative,
                &secp,
            )
            .unwrap();
            let json = SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp)
                .unwrap();
            split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap()
        };

        let set_a = make_wallets(phrase_a);
        let set_b = make_wallets(phrase_b);

        // (a) Only one viable set: A has 1 share (below threshold=2), B has
        // 3 (above threshold). Recovery must yield B without ambiguity.
        let mixed_one_viable = vec![
            set_a[0].clone(),
            set_b[0].clone(),
            set_b[1].clone(),
            set_b[2].clone(),
        ];
        let recovered = combine_vss_wallets(&mixed_one_viable).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase_b);

        // (b) Two viable sets: both A and B have 2+ shares. Combine must
        // refuse rather than guess.
        let mixed_two_viable = vec![
            set_a[0].clone(),
            set_a[1].clone(),
            set_b[0].clone(),
            set_b[1].clone(),
        ];
        let err = match combine_vss_wallets(&mixed_two_viable) {
            Ok(_) => panic!("expected ambiguity error"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Ambiguous input"),
            "expected ambiguity error, got: {msg}"
        );
        // The disambiguation message should name xpubs so the user can pick.
        assert!(msg.contains("xpub="), "expected xpub hints, got: {msg}");

        // Insufficient shares of any compatible set must still fail.
        let neither_viable = vec![set_a[0].clone(), set_b[0].clone()];
        let err = match combine_vss_wallets(&neither_viable) {
            Ok(_) => panic!("expected insufficient-shares error"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("No threshold-compatible subset")
                || msg.contains("failed to combine")
                || msg.contains("Insufficient"),
            "got: {msg}"
        );
    }

    /// Exact-threshold (3-of-3) recovery where one share's verifier
    /// COPY is corrupted but its secret/blinder bytes are still valid
    /// for the real polynomial. The remaining shares carry the real
    /// verifier; we use it to verify ALL shares (including the one
    /// with the corrupted verifier copy). Recovery must succeed.
    #[test]
    fn test_combine_vss_wallets_tolerates_verifier_copy_corruption() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        // 3-of-3: each share is mandatory.
        let mut vss = split_singlesig_wallet(json.expose_secret(), 3, 3, false, &mut rng).unwrap();
        // Corrupt the LO verifier on share[2] only — its share_data /
        // blinder_share_data stay intact.
        vss[2].verification_data = "deadbeef,deadbeef,deadbeef,deadbeef,deadbeef".to_string();

        let recovered = combine_vss_wallets(&vss).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
    }

    /// Exact-threshold 24-word recovery where the LO verifier is
    /// corrupted on one share AND the HI verifier is corrupted on a
    /// *different* share. The correct lo verifier and the correct hi
    /// verifier both still exist in the input, but they never coexist
    /// on the same share. Recovery must succeed by trying the
    /// cross-product of distinct lo verifiers × distinct hi verifiers,
    /// not just the (lo, hi) pairs that come together on one share.
    #[test]
    fn test_combine_vss_wallets_tolerates_split_lo_hi_verifier_corruption() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        // 24-word phrase so each share carries both lo and hi
        // verifiers / share data.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        // 2-of-2 (exact threshold): both shares are mandatory and
        // each carries both halves' verifiers. Corrupt LO verifier on
        // share[0] AND HI verifier on share[1] — the correct lo
        // verifier still exists on share[1], the correct hi verifier
        // still exists on share[0], but they never coexist on a
        // single share. Without cross-product candidate enumeration,
        // the only candidates would be
        //   (bad_lo,    good_hi_0)   ← from share[0]
        //   (good_lo_1, bad_hi)      ← from share[1]
        // both of which fail the Pedersen check. The cross-product
        // adds (good_lo_1, good_hi_0), which combines successfully.
        let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 2, false, &mut rng).unwrap();
        vss[0].verification_data = "deadbeef,deadbeef,deadbeef,deadbeef".to_string();
        vss[1].verification_data_hi =
            Some("cafebabe,cafebabe,cafebabe,cafebabe".to_string());

        let recovered = combine_vss_wallets(&vss).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
    }

    /// Tamper the share_data hex of one share, then attempt to combine the
    /// threshold shares. Lagrange interpolation alone would happily produce
    /// *some* scalar (and thus *some* mnemonic) from any t consistent points,
    /// so without per-share verification a bad share would silently corrupt
    /// recovery. With Feldman verification on the combine path, the tampered
    /// share must be rejected before reconstruction.
    #[test]
    fn test_tampered_share_is_rejected() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();

        // Flip a few hex nibbles in share 0's share_data so it still parses
        // as hex but encodes a different field element. (We preserve the
        // first byte, which encodes the share identifier.)
        let mut bytes = hex::decode(&shares[0].share_data).unwrap();
        assert!(bytes.len() > 4);
        for b in &mut bytes[1..] {
            *b ^= 0xAA;
        }
        shares[0].share_data = hex::encode(&bytes);
        shares[0].checksum = shares[0].compute_checksum();

        let err = match combine_shares_to_mnemonic(&shares[0..2]) {
            Ok(_) => panic!("expected combine to reject the tampered share"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Feldman")
                || msg.contains("verification")
                || msg.contains("Insufficient verified shares"),
            "expected verification failure, got: {msg}"
        );
    }

    /// If the largest compatible group fails verification (too many
    /// corrupt shares), `combine_vss_wallets` must fall back to a smaller
    /// group whose verified shares still meet threshold. Without iterative
    /// candidate selection, a noisy "big" group would block recovery even
    /// when a clean smaller group is also present.
    #[test]
    fn test_combine_falls_back_to_smaller_clean_group() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let phrase_a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let phrase_b = "legal winner thank year wave sausage worth useful legal winner thank yellow";

        let mut split = |phrase: &str| {
            let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
            let wallet = SingleSigWalletDescriptionV0::generate(
                Arc::new(mnemonic),
                &None,
                bitcoin::Network::Bitcoin,
                ScriptType::SegwitNative,
                &secp,
            )
            .unwrap();
            let json =
                SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
            split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap()
        };

        let mut set_a = split(phrase_a); // larger group, but two shares get corrupted
        let set_b = split(phrase_b);     // smaller-presence-but-clean group

        // Corrupt 2 of the 3 shares in set A so its verified count drops to
        // 1 (below threshold=2).
        for share in set_a.iter_mut().take(2) {
            let mut bytes = hex::decode(&share.share_data).unwrap();
            for b in &mut bytes[1..] {
                *b ^= 0xAA;
            }
            share.share_data = hex::encode(&bytes);
        }

        // Mix: 3 of A (largest by raw count) + 2 of B (smaller, still clean).
        let mixed = vec![
            set_a[0].clone(),
            set_a[1].clone(),
            set_a[2].clone(),
            set_b[0].clone(),
            set_b[1].clone(),
        ];

        let recovered = combine_vss_wallets(&mixed).unwrap();
        // A is biggest by input size; tried first, fails (2 corrupt). B is
        // tried next, succeeds. Recovered phrase must be B's.
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase_b);
    }

    /// Recovery must depend only on cryptographically authoritative data
    /// (Feldman verifier set + share bytes). Tampering with the mutable
    /// `threshold` JSON field — either UP (e.g. claiming 5 instead of 2)
    /// or DOWN (claiming 2 instead of 3) — must not affect the outcome:
    ///   * "edit up": recovery still succeeds, because the real threshold
    ///     comes from the Feldman set.
    ///   * "edit down": cannot trick combine into using fewer points,
    ///     because Lagrange interpolation needs the real polynomial degree
    ///     and per-share Feldman verification rejects forged points; in
    ///     the all-genuine-shares case recovery again succeeds and the
    ///     downgraded metadata is harmless noise.
    #[test]
    fn test_combine_ignores_tampered_threshold_metadata() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();

        for tampered_threshold in [1u8, 5u8, 99u8] {
            let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 3, false, &mut rng).unwrap();
            for w in vss.iter_mut() {
                w.threshold = tampered_threshold;
                w.total_shares = 99; // also corrupt this — should be ignored
            }
            let recovered = combine_vss_wallets(&vss).unwrap_or_else(|e| {
                panic!(
                    "combine_vss_wallets should ignore tampered threshold={tampered_threshold}, but failed: {e:#}"
                )
            });
            assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
        }
    }

    /// Lower-level mirror of the above: at the `combine_shares_to_mnemonic`
    /// API, tampering the `Share.threshold` field on every share of a
    /// genuine 3-of-5 split (an attacker downgrading metadata to 2)
    /// must NOT trick combine into accepting 2 shares — Lagrange + Feldman
    /// still demand the real polynomial. With 3 genuine shares supplied,
    /// recovery succeeds despite the lying metadata.
    #[test]
    fn test_combine_shares_ignores_downgraded_threshold_metadata() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let mut shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();
        for share in shares.iter_mut() {
            share.threshold = 2; // downgrade across the board
            share.checksum = share.compute_checksum();
        }

        // 2 shares: must still fail because the Feldman threshold is 3.
        let err = combine_shares_to_mnemonic(&shares[0..2]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Insufficient"),
            "expected insufficient-shares error, got: {msg}"
        );

        // 3 shares: recovery succeeds, downgraded metadata is harmless.
        let recovered = combine_shares_to_mnemonic(&shares[0..3]).unwrap();
        assert_eq!(
            recovered.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }

    /// An attacker who edits `mnemonic_length` from 24 down to 12 across
    /// every share must NOT be able to silently truncate the recovered
    /// seed to a different valid 12-word mnemonic. The combine path
    /// must determine 12-vs-24 from the *cryptographic* presence of
    /// the high-half verifier set, not from the mutable JSON field.
    ///
    /// Use 100 random 24-word mnemonics so a coincidental collision
    /// (where the lo-half-only mnemonic happens to equal the original)
    /// can't pass.
    #[test]
    fn test_combine_resists_24_to_12_metadata_downgrade() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let mut entropy = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut entropy);
            let original = Mnemonic::from_entropy(&entropy).unwrap();

            let mut shares = split_mnemonic(&original, 3, 5, &mut rng).unwrap();
            // Tamper: rewrite the metadata across all shares.
            for s in &mut shares {
                s.mnemonic_length = 12;
                s.checksum = s.compute_checksum();
            }

            let recovered = combine_shares_to_mnemonic(&shares[0..3]).unwrap();
            assert_eq!(
                recovered.expose_secret().to_string(),
                original.to_string(),
                "downgrade attack succeeded — recovery returned a 12-word phrase instead of the original 24"
            );
        }
    }

    /// Recovery must not depend on input order. Even when the
    /// corrupted-verifier share happens to be at index 0 (which the old
    /// "anchor on shares[0]" check used as canonical), the remaining
    /// shares must still reconstruct as long as a viable verifier-
    /// matching subset exists.
    #[test]
    fn test_combine_recovers_when_shares_zero_has_corrupt_verifier() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();
        // 2-of-3 split. Corrupt shares[0]'s verifier so it ends up in a
        // singleton group. shares[1..3] still have the real verifier and
        // form a 2-share group that meets threshold.
        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        shares[0].verification_data = "deadbeef,deadbeef,deadbeef,deadbeef".to_string();
        shares[0].checksum = shares[0].compute_checksum();

        let recovered = combine_shares_to_mnemonic(&shares).unwrap();
        assert_eq!(
            recovered.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }

    /// A metadata-corrupted extra share must not strand a recoverable
    /// threshold set: a flipped `version` byte, a stripped high-half
    /// field, or other purely-metadata damage on one share is dropped
    /// per-share by combine_one_half, leaving the remaining good shares
    /// to reconstruct.
    #[test]
    fn test_combine_tolerates_metadata_corrupt_extra_share() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();
        // 2-of-3 split → corrupt the *third* share's metadata. We hand 2
        // good shares + 1 metadata-corrupt share to combine; recovery
        // must succeed because the threshold is still met by the good 2.
        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        // Flip the version on one share (metadata-only damage; doesn't
        // affect the cryptographic share data).
        shares[2].version = 9999;

        let recovered = combine_shares_to_mnemonic(&shares).unwrap();
        assert_eq!(
            recovered.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }

    /// Share files must not embed Feldman commitments (`g^a_i`). For our
    /// 16-byte halves the secret `a_0` is bounded to 128 bits, so a
    /// Feldman commitment `g^secret_half` would be vulnerable to a ~2^64
    /// discrete-log attack — an attacker who decrypts a single share could
    /// recover the half. The Pedersen blind commitments we DO store
    /// (`g^a * h^b` with random `b`) hide the secret information-
    /// theoretically.
    ///
    /// This is a structural test: we serialize a fresh share to JSON and
    /// assert no field contains a "feldman" key, plus that the verifier
    /// set length matches Pedersen layout (`threshold + 2`) and not
    /// Feldman layout (`threshold + 1`).
    #[test]
    fn test_share_does_not_leak_feldman_commitments() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();
        let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        let json = serde_json::to_string(&shares[0]).unwrap();
        assert!(
            !json.to_lowercase().contains("feldman"),
            "share serialization must not include any Feldman field: {json}"
        );

        // Threshold = 2 → Pedersen verifier set should hold 2+2 = 4 hex
        // points (g, h, C_0, C_1). Anything else means we accidentally
        // serialized the wrong commitment set.
        let parts: Vec<&str> = shares[0].verification_data.split(',').collect();
        assert_eq!(parts.len(), 4, "verification_data must be 4 points for 2-of-3 split: {parts:?}");
    }

    /// One corrupted share among extra redundant shares must not block
    /// recovery — the verifier filters out the bad one and reconstruction
    /// succeeds from the remaining good ones.
    #[test]
    fn test_extra_share_redundancy_tolerates_one_corruption() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        // 2-of-3 split → corrupt share 0, but provide all 3 shares. Combine
        // should drop the bad one, keep shares 1 and 2, and recover the seed.
        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        let mut bytes = hex::decode(&shares[0].share_data).unwrap();
        for b in &mut bytes[1..] {
            *b ^= 0xAA;
        }
        shares[0].share_data = hex::encode(&bytes);
        shares[0].checksum = shares[0].compute_checksum();

        let recovered = combine_shares_to_mnemonic(&shares).unwrap();
        assert_eq!(
            recovered.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }
}
