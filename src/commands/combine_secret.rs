use std::path::PathBuf;

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bip39::Mnemonic,
    secrecy::ExposeSecret,
    secret_sharing::combine_shares_to_mnemonic,
};

use crate::progress_bar::get_spinner;

use super::split_secret::{collect_share_files, load_shares};

/// Combine shares to reconstruct the original mnemonic
pub(crate) fn combine_shares(
    _theme: &dyn Theme,
    _term: &Term,
    share_paths: &[String],
    display_mnemonic: bool,
) -> anyhow::Result<Mnemonic> {
    // Collect share files
    let share_files = collect_share_files(share_paths)?;

    println!("\nFound {} share files:", share_files.len());
    for (idx, path) in share_files.iter().enumerate() {
        println!("  {}. {}", idx + 1, path.display());
    }

    // Load shares
    let shares = load_shares(&share_files)?;

    // Display share information
    if let Some(first_share) = shares.first() {
        println!("\nShare Information:");
        println!("  Scheme: {}", first_share.scheme);
        println!("  Threshold: {} shares required", first_share.threshold);
        println!("  Total shares: {}", first_share.total_shares);
        println!("  Mnemonic length: {} words", first_share.mnemonic_length);
        println!("  Shares provided: {}", shares.len());

        if shares.len() < first_share.threshold as usize {
            anyhow::bail!(
                "Insufficient shares: need at least {} but only have {}",
                first_share.threshold,
                shares.len()
            );
        }

        println!(
            "\n✓ Have enough shares ({}/{}) to reconstruct secret",
            shares.len(),
            first_share.threshold
        );
    }

    // Verify and combine shares
    let spinner = get_spinner("Verifying shares using Pedersen commitments...");

    let reconstructed_mnemonic = combine_shares_to_mnemonic(&shares)
        .context("Failed to combine shares")?;

    spinner.finish_with_message("✓ Shares verified and combined successfully");

    // Display mnemonic if requested
    if display_mnemonic {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("⚠️  RECONSTRUCTED MNEMONIC (KEEP THIS SECRET!)");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("\n{}\n", reconstructed_mnemonic.expose_secret());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("SECURITY REMINDER:");
        println!("  • Anyone with this mnemonic can access your funds");
        println!("  • Write it down in a secure location");
        println!("  • Clear your terminal history after viewing");
        println!("  • Do not share or photograph this mnemonic");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    } else {
        println!("\n✓ Mnemonic reconstructed successfully (use --display-mnemonic to view it)");
    }

    // Return the mnemonic (moved out of SecretBox)
    Ok(reconstructed_mnemonic.expose_secret().clone())
}
