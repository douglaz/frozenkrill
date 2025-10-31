# Secret Sharing with Pedersen VSS

## Overview

Frozenkrill supports splitting your BIP-39 seed phrase into multiple encrypted shares using **Pedersen VSS (Verifiable Secret Sharing)**. This allows you to distribute your seed across multiple secure locations, requiring a minimum threshold of shares to reconstruct the original seed.

## What is Pedersen VSS?

**Pedersen VSS is an enhanced version of Shamir's Secret Sharing with added verification.**

Think of it as: **Pedersen VSS = Shamir's Secret Sharing + Verification Commitments**

Shamir's Secret Sharing (invented in 1979) pioneered threshold cryptography - splitting a secret into N shares where any M shares can reconstruct it. Pedersen VSS (1991) enhanced this by adding cryptographic commitments that allow anyone to verify shares are valid without learning the secret.

### Key Features

- **Splits a secret** into N shares (from Shamir)
- Requires **M shares to reconstruct** (M-of-N threshold scheme, from Shamir)
- **Provides verifiability** - shares can be verified as authentic without revealing the secret (Pedersen's addition)
- Offers **information-theoretic security** - possessing M-1 shares reveals no information about the secret (from Shamir)
- Uses **hidden commitments** - unlike Feldman VSS, verification data doesn't leak information about the secret (Pedersen's improvement)

### Why VSS instead of plain Shamir?

Traditional Shamir's Secret Sharing has a critical limitation: you can't verify shares are valid until you actually try to reconstruct the secret. This is problematic for inheritance/backup scenarios where shares might not be used for years - you don't know if a share was corrupted or tampered with until it's too late.

Pedersen VSS solves this by allowing share holders to verify their shares are genuine at any time, without revealing anything about the secret.

### Comparison with Multisig

| Feature | Secret Sharing | Multisig |
|---------|---------------|----------|
| **Purpose** | Protects seed phrase | Protects transaction signing |
| **Recovery** | Reconstructs original seed | No single seed exists |
| **Use Case** | Backup/inheritance | Operational security |
| **On-chain** | No blockchain interaction | Requires special address type |
| **Flexibility** | Can recover any wallet type | Specific to multisig wallets |

**Use both together for maximum security**: Multisig for operational security, VSS for seed backup.

## Security Considerations

### Benefits

✅ **Geographic distribution** - Store shares in different physical locations
✅ **Disaster resistance** - Loss of some shares doesn't compromise the seed
✅ **Inheritance planning** - Distribute shares among trustees
✅ **Verifiable** - Recipients can verify shares are valid before you're unavailable
✅ **No single point of failure** - No one location contains the complete seed
✅ **Encrypted** - Each share is a fully encrypted .frozenkrill wallet file

### Important Warnings

⚠️ **Threshold security**: Anyone with M shares can reconstruct your seed and access ALL funds
⚠️ **Share loss**: Losing too many shares (>N-M) means PERMANENT loss of funds
⚠️ **Password protection**: Shares are encrypted - you MUST remember the password used during splitting
⚠️ **Under audit**: vsss-rs library includes a warning about audit status - use at your own risk
⚠️ **Distribution risk**: The distribution process itself creates temporary risk

### Best Practices

1. **Test first**: Use a test wallet with small amounts to verify the process
2. **Separate storage**: NEVER store M or more shares together
3. **Geographic distribution**: Store shares in different cities/countries if possible
4. **Multiple backup methods**: VSS complements, doesn't replace other backups
5. **Document locations**: Keep a secure record of where shares are stored (without the shares themselves)
6. **Regular verification**: Periodically verify shares are still accessible and valid
7. **Secure distribution**: Use encrypted channels when distributing shares electronically
8. **Remember password**: The password used to encrypt shares is required for reconstruction

## Usage

### Splitting a Seed

To split an existing wallet's seed phrase:

```bash
frozenkrill split-secret \
  wallet.frozenkrill \
  --threshold 3 \
  --total-shares 5 \
  --output-dir /path/to/shares \
  --password mypassword \
  --keyfile /path/to/keyfile \
  --difficulty normal
```

**Parameters:**
- `wallet_input_file`: Path to your encrypted wallet file
- `--threshold`: Minimum shares needed to reconstruct (M)
- `--total-shares`: Total shares to create (N)
- `--output-dir`: Directory where share files will be written (default: current directory)
- `--password`: Password for encrypting shares (will prompt if not provided)
- `--keyfile`: Optional keyfile(s) for share encryption
- `--difficulty`: Key derivation difficulty (easy/normal/hard/veryhard)
- `--enable-duress-wallet`: Use duress wallet instead of main wallet
- `--disable-all-padding`: Disable padding (not recommended)
- `--wallet-file-type`: standard or compact (default: standard)

**Output:**
Creates encrypted files named: `share-1-of-5-20251031-120000.frozenkrill`, `share-2-of-5-20251031-120000.frozenkrill`, etc.

### Combining Shares

To reconstruct the seed phrase from shares:

```bash
frozenkrill combine-secret \
  share-1-of-5.frozenkrill share-3-of-5.frozenkrill share-4-of-5.frozenkrill \
  --display-mnemonic
```

**Parameters:**
- Provide M or more share file paths as arguments
- `--display-mnemonic`: Display the reconstructed mnemonic on screen (⚠️ **SENSITIVE!**)

**Alternative**: Provide a directory and it will use all `.frozenkrill` files found:

```bash
frozenkrill combine-secret /path/to/shares/directory
```

## Share File Format

Shares are stored as encrypted .frozenkrill wallet files with the following structure (after decryption):

```json
{
  "version": 0,
  "share_index": 2,
  "threshold": 3,
  "total_shares": 5,
  "share_data": "base64-encoded-share",
  "verification_data": "base64-encoded-commitments",
  "created_at": "2025-10-31T12:00:00Z",
  "original_wallet": {
    "wallet_type": "singlesig",
    "version": 0,
    "network": "bitcoin",
    "script_type": "segwit_native",
    "seed_phrase": "[redacted - this is the SAME for all shares]",
    "descriptors": { ... },
    "public_keys": { ... }
  }
}
```

### File Format Design

- **Encrypted format**: Each share is a fully encrypted .frozenkrill wallet file
- **Complete metadata**: Shares include full wallet metadata (network, script type, descriptors, public keys)
- **Watch-only capable**: Shares can be used for watch-only wallet monitoring without reconstruction
- **Version field**: Forward compatibility for future improvements
- **Metadata**: Threshold and total shares info for validation
- **Verification data**: Pedersen commitments for share verification
- **Timestamp**: ISO 8601 creation timestamp

## Example Scenarios

### Scenario 1: Personal Backup (2-of-3)

**Setup:**
- Keep 1 share at home (fireproof safe)
- Keep 1 share at a trusted family member's location
- Keep 1 share in a bank safe deposit box

**Security:** Any 2 locations compromised = seed compromised
**Availability:** Can lose any 1 location and still recover

### Scenario 2: Inheritance Planning (3-of-5)

**Setup:**
- Give 1 share to spouse
- Give 1 share to each of 2 children
- Give 1 share to lawyer
- Keep 1 share yourself

**Security:** Requires cooperation of 3 parties
**Availability:** Can lose 2 parties and still recover
**Inheritance:** Your heirs can recover even if you're unavailable

### Scenario 3: Geographic Distribution (4-of-7)

**Setup:**
- 1 share in each of 7 different countries
- Each in a different secure storage facility

**Security:** Highly resistant to jurisdiction-specific attacks
**Availability:** Can lose 3 entire countries and still recover
**Complexity:** More complex to manage and access

## Technical Details

### Cryptographic Scheme

- **Base Algorithm**: Shamir's Secret Sharing (polynomial interpolation)
- **Enhancement**: Pedersen commitments for verifiability
- **Complete Scheme**: Pedersen VSS over Curve25519
- **Field**: Ristretto255 group (canonical form of Curve25519)
- **Secret Splitting**: Shamir's polynomial with random coefficients
- **Share Verification**: Pedersen commitments (hidden, non-interactive)
- **Randomness**: Cryptographically secure random number generation via libsodium
- **Encryption**: Argon2id key derivation + XChaCha20-Poly1305 AEAD
- **Compression**: GZIP compression before encryption

### Implementation

- **Library**: [vsss-rs](https://github.com/mikelodder7/vsss-rs) v4.x
- **Curve**: Curve25519 (via `curve25519-dalek`)
- **Encoding**: BIP-39 mnemonic → entropy bytes → Curve25519 scalar
- **Security**: All intermediate values are zeroized after use
- **File format**: Encrypted .frozenkrill wallet files (not JSON)

### Security Guarantees

1. **Information-theoretic security**: M-1 shares reveal absolutely no information about the secret
2. **Verifiable**: Shares can be verified using Pedersen commitments without revealing the secret
3. **Tamper-evident**: Any modification to shares is detected via verification
4. **No trust required**: The scheme is cryptographically secure, not dependent on trusted parties
5. **Encrypted at rest**: Shares are encrypted with Argon2id + XChaCha20-Poly1305

## Troubleshooting

### "Insufficient shares" error

You provided fewer than the threshold number of shares. Check the `threshold` field in the share files (you'll need to decrypt them first or check during splitting).

### "Incompatible shares" error

The shares are from different splitting operations. Ensure all shares have matching:
- `version`
- `threshold`
- `total_shares`
- `verification_data`

### "Share verification failed" error

A share file may be corrupted or tampered with. Check:
- File integrity
- File wasn't manually edited
- File wasn't corrupted during transfer

### "Failed to decrypt share file" error

Wrong password or keyfiles. The password used during `split-secret` must match the one used during `combine-secret`.

### "Invalid mnemonic checksum after reconstruction" error

The reconstructed mnemonic doesn't have a valid BIP-39 checksum. This could indicate:
- Incompatible or corrupted shares
- Wrong shares from different sets
- Implementation bug (please report!)

## FAQ

**Q: Can I change the threshold after creating shares?**
A: No, you must generate a new set of shares with the desired threshold.

**Q: Can I add more shares later?**
A: No, the total number of shares is fixed at creation time.

**Q: Can I use this with my existing wallet?**
A: Yes, the `split-secret` command works with any existing frozenkrill wallet.

**Q: Is this compatible with hardware wallets?**
A: The shares encode your seed phrase, which can be used with any BIP-39 compatible wallet.

**Q: What happens if I lose my original wallet after splitting?**
A: You can reconstruct the seed from the shares and create a new wallet.

**Q: What if I forget the password?**
A: There is NO way to recover shares without the password. This is why you must test the entire process and verify you can reconstruct the seed before relying on it.

**Q: Can someone with one share see my wallet balance?**
A: Yes! Each share contains the complete wallet metadata including public keys and descriptors. Shares can be used as watch-only wallets to monitor balances. This is by design for inheritance planning.

**Q: Is this the same as Shamir's Secret Sharing?**
A: Almost! Pedersen VSS **is** Shamir's Secret Sharing, but with an important enhancement. It uses the same mathematical foundation (Shamir's polynomial scheme) for splitting and reconstructing secrets, but adds Pedersen commitments that allow verifying shares are valid without revealing the secret. Think of it as "Shamir's Secret Sharing 2.0" - the same core algorithm made better with verification.

**Q: How is this different from Shamir's Secret Sharing (SLIP-39)?**
A: SLIP-39 is a different standard for mnemonic splitting. It uses the original Shamir algorithm without verification commitments. Pedersen VSS (frozenkrill):
- Uses standard BIP-39 mnemonics (SLIP-39 uses its own wordlist)
- Provides cryptographic verification via Pedersen commitments (SLIP-39 does not)
- Stores shares as encrypted wallet files (SLIP-39 shares are mnemonic phrases)
- Is not standardized for wallets (frozenkrill-specific)

**Q: Can someone with M-1 shares brute-force the last share?**
A: No, Pedersen VSS has information-theoretic security - M-1 shares provide zero information about the secret. This security property comes from Shamir's original scheme.

**Q: Are shares portable between devices?**
A: Yes, share files are standard .frozenkrill wallet files that can be transferred and used on any device with frozenkrill installed.

## References

- [Frozenkrill](https://github.com/douglaz/frozenkrill) - Cold storage wallet project
- [vsss-rs](https://github.com/mikelodder7/vsss-rs) - Secret sharing library
- [Pedersen VSS Paper](https://link.springer.com/chapter/10.1007/3-540-46766-1_9) - Original research
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic standard

## License

This feature is part of frozenkrill and is licensed under MIT or Apache-2.0, matching the project license.

---

**⚠️ REMEMBER**: Secret sharing is a powerful tool but requires careful planning. Test thoroughly with small amounts before trusting it with significant funds. Always remember your password!
