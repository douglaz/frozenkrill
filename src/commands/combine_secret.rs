use std::{path::PathBuf, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bip39::Mnemonic,
    key_derivation::{KeyDerivationDifficulty, default_derive_key},
    secret_sharing::combine_vss_wallets,
    wallet_description::read_decode_wallet,
};

use crate::{ask_password, progress_bar::get_spinner};

use super::split_secret::collect_share_files;

/// Combine shares to reconstruct the original wallet
pub(crate) fn combine_shares(
    theme: &dyn Theme,
    term: &Term,
    share_paths: &[String],
    display_mnemonic: bool,
) -> anyhow::Result<Mnemonic> {
    // Collect share files
    let share_files = collect_share_files(share_paths)?;

    println!("\nFound {} share files:", share_files.len());
    for (idx, path) in share_files.iter().enumerate() {
        println!("  {}. {}", idx + 1, path.display());
    }

    // Prompt for password and keyfiles to decrypt shares
    println!(
        "\nTo decrypt the shares, please provide the password and keyfiles used during splitting:"
    );
    let password = ask_password(theme, term).map(Arc::new)?;

    // For now, we'll assume no keyfiles for simplicity
    // TODO: Add support for keyfiles in combine command
    let keyfiles: Vec<PathBuf> = vec![];

    // Decrypt all shares
    let spinner = get_spinner("Decrypting share files...");
    let mut decrypted_shares = Vec::new();

    for share_file in &share_files {
        // Read and decode the encrypted wallet
        let encrypted_wallet = read_decode_wallet(share_file)
            .with_context(|| format!("Failed to read share file: {}", share_file.display()))?;

        // Derive key from password
        let key = default_derive_key(
            &password,
            &keyfiles,
            &encrypted_wallet.salt,
            &KeyDerivationDifficulty::Normal,
        )?;

        // Decrypt the share
        let decrypted = encrypted_wallet.decrypt_vss(&key).with_context(|| {
            format!(
                "Failed to decrypt share file: {}. Wrong password?",
                share_file.display()
            )
        })?;

        decrypted_shares.push(decrypted);
    }

    spinner.finish_with_message(format!(
        "✓ Decrypted {} shares successfully",
        decrypted_shares.len()
    ));

    // Display share information
    if let Some(first_share) = decrypted_shares.first() {
        println!("\nShare Information:");
        println!("  Threshold: {} shares required", first_share.threshold);
        println!("  Total shares: {}", first_share.total_shares);
        println!("  Shares provided: {}", decrypted_shares.len());

        if decrypted_shares.len() < first_share.threshold as usize {
            anyhow::bail!(
                "Insufficient shares: need at least {} but only have {}",
                first_share.threshold,
                decrypted_shares.len()
            );
        }

        println!(
            "\n✓ Have enough shares ({}/{}) to reconstruct secret",
            decrypted_shares.len(),
            first_share.threshold
        );
    }

    // Combine shares to reconstruct mnemonic
    let spinner =
        get_spinner("Verifying shares using Pedersen commitments and reconstructing wallet...");

    let reconstructed_mnemonic_str = combine_vss_wallets(&decrypted_shares)
        .context("Failed to combine shares. Shares may be from different wallets or corrupted.")?;

    let reconstructed_mnemonic = Mnemonic::parse(&reconstructed_mnemonic_str)
        .context("Failed to parse reconstructed mnemonic")?;

    spinner.finish_with_message("✓ Shares verified and combined successfully");

    // Display mnemonic if requested
    if display_mnemonic {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("⚠️  RECONSTRUCTED MNEMONIC (KEEP THIS SECRET!)");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("\n{}\n", reconstructed_mnemonic);
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

    Ok(reconstructed_mnemonic)
}
