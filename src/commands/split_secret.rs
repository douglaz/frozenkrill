use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use dialoguer::{Confirm, console::Term, theme::Theme};
use frozenkrill_core::{
    PaddingParams,
    anyhow::{self, Context},
    bitcoin::secp256k1::{All, Secp256k1},
    generate_encrypted_encoded_vss_wallet, get_padder,
    key_derivation::{KeyDerivationDifficulty, default_derive_key},
    random_generation_utils::{self, get_random_key},
    secrecy::{ExposeSecret, SecretBox, SecretString},
    secret_sharing::split_singlesig_wallet as split_singlesig_wallet_core,
    wallet_description::{
        EncryptedWalletVersion, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
    },
};

use crate::progress_bar::get_spinner;

/// Split a wallet's seed phrase into shares using Pedersen secret sharing
pub(crate) fn split_singlesig_wallet(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    threshold: u8,
    total_shares: u8,
    output_dir: &Path,
    password: &Arc<SecretString>,
    keyfiles: &[PathBuf],
    difficulty: KeyDerivationDifficulty,
    padding_params: &PaddingParams,
    encrypted_version: EncryptedWalletVersion,
    rng: &mut (impl frozenkrill_core::rand::RngCore + frozenkrill_core::rand::CryptoRng),
) -> anyhow::Result<()> {
    // Validate output directory exists
    anyhow::ensure!(
        output_dir.exists(),
        "Output directory does not exist: {}",
        output_dir.display()
    );

    anyhow::ensure!(
        output_dir.is_dir(),
        "Output path is not a directory: {}",
        output_dir.display()
    );

    // Show warning and require confirmation
    println!("\n⚠️  WARNING: Secret Sharing Operation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "You are about to split your wallet seed into {} shares.",
        total_shares
    );
    println!(
        "You will need at least {} shares to reconstruct the seed.",
        threshold
    );
    println!("\nIMPORTANT SECURITY NOTES:");
    println!("  • Store each share in a SEPARATE, SECURE location");
    println!(
        "  • Losing {} or more shares = PERMANENT LOSS of funds",
        total_shares - threshold + 1
    );
    println!(
        "  • Anyone with {} or more shares can access your wallet",
        threshold
    );
    println!("  • Shares will be written to: {}", output_dir.display());
    println!("  • This operation is IRREVERSIBLE");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let confirmed = Confirm::with_theme(theme)
        .with_prompt("Do you understand the risks and want to proceed?")
        .default(false)
        .interact_on(term)?;

    if !confirmed {
        println!("Operation cancelled by user.");
        return Ok(());
    }

    // Convert wallet to JSON format for splitting
    let spinner = get_spinner("Preparing wallet for splitting...");
    let wallet_json = SinglesigJsonWalletDescriptionV0::from_wallet_description(wallet, secp)?;
    spinner.finish_with_message("✓ Wallet prepared");

    // Create a spinner for the splitting operation
    let spinner = get_spinner("Splitting seed into shares using Pedersen scheme...");

    // Perform the split using the core function
    let vss_wallets =
        split_singlesig_wallet_core(wallet_json.expose_secret(), threshold, total_shares, rng)
            .context("Failed to split wallet into shares")?;

    spinner.finish_with_message("✓ Seed successfully split into shares");

    // Encrypt and save shares to files
    let spinner = get_spinner("Encrypting and writing shares to files...");
    let mut saved_files = Vec::new();

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");

    for vss_wallet in &vss_wallets {
        let filename = format!(
            "share-{}-of-{}-{}.frozenkrill",
            vss_wallet.share_index, vss_wallet.total_shares, timestamp
        );
        let filepath = output_dir.join(&filename);

        // Ensure file doesn't already exist
        if filepath.exists() {
            anyhow::bail!(
                "Share file already exists: {}. Please remove it or choose a different output directory.",
                filepath.display()
            );
        }

        // Generate encryption parameters for this share
        let salt = random_generation_utils::get_random_salt(rng)?;
        let nonce = random_generation_utils::get_random_nonce(rng)?;
        let header_nonce = random_generation_utils::get_random_nonce(rng)?;
        let padder = get_padder(rng, padding_params)?;

        // Derive key from password and keyfiles, generate random header key
        let key = default_derive_key(password, keyfiles, &salt, &difficulty)?;
        let header_key = SecretBox::from(Box::new(get_random_key(rng)?));

        // Encrypt the share
        let encrypted_wallet = generate_encrypted_encoded_vss_wallet(
            &key,
            header_key,
            vss_wallet,
            salt,
            nonce,
            header_nonce,
            padder,
            encrypted_version,
        )
        .context("Failed to encrypt share")?;

        // Write encrypted share to file
        std::fs::write(&filepath, encrypted_wallet).with_context(|| {
            format!("Failed to write encrypted share to {}", filepath.display())
        })?;

        saved_files.push(filepath);
    }

    spinner.finish_with_message(format!(
        "✓ {} encrypted shares written successfully",
        vss_wallets.len()
    ));

    // Display results
    println!("\n✓ Secret sharing completed successfully!");
    println!("\nShare files created:");
    for (idx, path) in saved_files.iter().enumerate() {
        println!("  {}. {}", idx + 1, path.display());
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("NEXT STEPS - Share Distribution Checklist:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  ☐ Verify all {} share files were created", total_shares);
    println!(
        "  ☐ Test reconstruction with {} shares (see 'combine-secret' command)",
        threshold
    );
    println!("  ☐ Store each share in a DIFFERENT physical location");
    println!("  ☐ Consider geographic distribution (different cities/countries)");
    println!("  ☐ Document where each share is stored (without storing shares together)");
    println!("  ☐ Securely delete shares from this computer after distribution");
    println!("  ☐ Keep your original wallet safe until shares are distributed");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    Ok(())
}

/// Get share files from a directory or list of paths
pub(crate) fn collect_share_files(share_paths: &[String]) -> anyhow::Result<Vec<PathBuf>> {
    let mut share_files = Vec::new();

    for path_str in share_paths {
        let path = PathBuf::from(path_str);

        if path.is_file() {
            share_files.push(path);
        } else if path.is_dir() {
            // Collect all .frozenkrill files in directory
            for entry in std::fs::read_dir(&path)
                .with_context(|| format!("Failed to read directory: {}", path.display()))?
            {
                let entry = entry?;
                let file_path = entry.path();

                if file_path.is_file()
                    && file_path
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("frozenkrill"))
                        .unwrap_or(false)
                {
                    share_files.push(file_path);
                }
            }
        } else {
            anyhow::bail!("Path does not exist: {}", path.display());
        }
    }

    anyhow::ensure!(
        !share_files.is_empty(),
        "No share files found in the provided paths"
    );

    Ok(share_files)
}
