use std::path::{Path, PathBuf};

use dialoguer::{console::Term, theme::Theme, Confirm};
use frozenkrill_core::{
    anyhow::{self, Context},
    bitcoin::secp256k1::{All, Secp256k1},
    secret_sharing::{split_mnemonic, Share},
    wallet_description::SingleSigWalletDescriptionV0,
};

use crate::progress_bar::get_spinner;

/// Split a wallet's seed phrase into shares using Pedersen secret sharing
pub(crate) fn split_singlesig_wallet(
    theme: &dyn Theme,
    term: &Term,
    _secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    threshold: u8,
    total_shares: u8,
    output_dir: &Path,
    rng: &mut (impl frozenkrill_core::rand_core::RngCore + frozenkrill_core::rand_core::CryptoRng),
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

    // Get the mnemonic from the wallet
    let mnemonic = wallet.mnemonic();

    // Show warning and require confirmation
    println!("\n⚠️  WARNING: Secret Sharing Operation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("You are about to split your wallet seed into {} shares.", total_shares);
    println!("You will need at least {} shares to reconstruct the seed.", threshold);
    println!("\nIMPORTANT SECURITY NOTES:");
    println!("  • Store each share in a SEPARATE, SECURE location");
    println!("  • Losing {} or more shares = PERMANENT LOSS of funds", total_shares - threshold + 1);
    println!("  • Anyone with {} or more shares can access your wallet", threshold);
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

    // Create a spinner for the splitting operation
    let spinner = get_spinner("Splitting seed into shares using Pedersen scheme...");

    // Perform the split
    let shares = split_mnemonic(mnemonic, threshold, total_shares, rng)
        .context("Failed to split mnemonic")?;

    spinner.finish_with_message("✓ Seed successfully split into shares");

    // Save shares to files
    let spinner = get_spinner("Writing shares to files...");
    let mut saved_files = Vec::new();

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");

    for share in &shares {
        let filename = format!(
            "share-{}-of-{}-{}.json",
            share.share_index, share.total_shares, timestamp
        );
        let filepath = output_dir.join(&filename);

        // Ensure file doesn't already exist
        if filepath.exists() {
            anyhow::bail!(
                "Share file already exists: {}. Please remove it or choose a different output directory.",
                filepath.display()
            );
        }

        share.save_to_file(&filepath)
            .with_context(|| format!("Failed to save share to {}", filepath.display()))?;

        saved_files.push(filepath);
    }

    spinner.finish_with_message(format!("✓ {} shares written successfully", shares.len()));

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
    println!("  ☐ Test reconstruction with {} shares (see 'combine-secret' command)", threshold);
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
            // Collect all .json files in directory
            for entry in std::fs::read_dir(&path)
                .with_context(|| format!("Failed to read directory: {}", path.display()))?
            {
                let entry = entry?;
                let file_path = entry.path();

                if file_path.is_file()
                    && file_path
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("json"))
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

/// Load and verify share files
pub(crate) fn load_shares(share_files: &[PathBuf]) -> anyhow::Result<Vec<Share>> {
    let spinner = get_spinner(format!("Loading {} share files...", share_files.len()));

    let mut shares = Vec::new();

    for (idx, path) in share_files.iter().enumerate() {
        let share = Share::load_from_file(path)
            .with_context(|| format!("Failed to load share from {}", path.display()))?;

        spinner.set_message(format!(
            "Loaded share {}/{}: {} of {}",
            idx + 1,
            share_files.len(),
            share.share_index,
            share.total_shares
        ));

        shares.push(share);
    }

    spinner.finish_with_message(format!("✓ Loaded {} shares successfully", shares.len()));

    Ok(shares)
}
