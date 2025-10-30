# Secret Sharing with Pedersen Verifiable Secret Sharing

## Overview

Frozenkrill now supports splitting your BIP-39 seed phrase into multiple shares using **Pedersen Verifiable Secret Sharing (VSS)**. This allows you to distribute your seed across multiple secure locations, requiring a minimum threshold of shares to reconstruct the original seed.

## What is Pedersen VSS?

Pedersen Verifiable Secret Sharing is a cryptographic scheme that:

- **Splits a secret** into N shares
- Requires **M shares to reconstruct** (M-of-N threshold scheme)
- Provides **verifiability** - shares can be verified as authentic without revealing the secret
- Offers **information-theoretic security** - possessing M-1 shares reveals no information about the secret
- Uses **hidden commitments** - unlike Feldman VSS, verification data doesn't leak information about the secret

### Comparison with Multisig

| Feature | Secret Sharing | Multisig |
|---------|---------------|----------|
| **Purpose** | Protects seed phrase | Protects transaction signing |
| **Recovery** | Reconstructs original seed | No single seed exists |
| **Use Case** | Backup/inheritance | Operational security |
| **On-chain** | No blockchain interaction | Requires special address type |
| **Flexibility** | Can recover any wallet type | Specific to multisig wallets |

**Use both together for maximum security**: Multisig for operational security, secret sharing for seed backup.

## Security Considerations

### Benefits

✅ **Geographic distribution** - Store shares in different physical locations
✅ **Disaster resistance** - Loss of some shares doesn't compromise the seed
✅ **Inheritance planning** - Distribute shares among trustees
✅ **Verifiable** - Recipients can verify shares are valid before you're unavailable
✅ **No single point of failure** - No one location contains the complete seed

### Important Warnings

⚠️ **Threshold security**: Anyone with M shares can reconstruct your seed and access ALL funds
⚠️ **Share loss**: Losing too many shares (>N-M) means PERMANENT loss of funds
⚠️ **No password protection**: Shares themselves are not password-protected (encrypt them separately if needed)
⚠️ **Under audit**: vsss-rs library includes a warning about audit status - use at your own risk
⚠️ **Distribution risk**: The distribution process itself creates temporary risk

### Best Practices

1. **Test first**: Use a test wallet with small amounts to verify the process
2. **Separate storage**: NEVER store M or more shares together
3. **Geographic distribution**: Store shares in different cities/countries if possible
4. **Multiple backup methods**: Secret sharing complements, doesn't replace other backups
5. **Document locations**: Keep a secure record of where shares are stored (without the shares themselves)
6. **Regular verification**: Periodically verify shares are still accessible and valid
7. **Secure distribution**: Use encrypted channels when distributing shares electronically

## Usage

### Splitting a Seed

To split an existing wallet's seed phrase:

```bash
frozenkrill split-secret \\
  --wallet /path/to/wallet.json \\
  --threshold 3 \\
  --total-shares 5 \\
  --output-dir /path/to/shares \\
  --password \\
  --keyfiles /path/to/keyfile
```

**Parameters:**
- `--wallet`: Path to your encrypted wallet file
- `--threshold`: Minimum shares needed to reconstruct (M)
- `--total-shares`: Total shares to create (N)
- `--output-dir`: Directory where share files will be written (default: current directory)
- `--password`: Wallet password (will prompt if not provided)
- `--keyfiles`: Optional keyfile(s) for wallet decryption
- `--enable-duress-wallet`: Use duress wallet instead of main wallet

**Output:**
Creates files named: `share-1-of-5-20251029-120000.json`, `share-2-of-5-20251029-120000.json`, etc.

### Combining Shares

To reconstruct the seed phrase from shares:

```bash
frozenkrill combine-secret \\
  share-1-of-5.json share-3-of-5.json share-4-of-5.json \\
  --display-mnemonic
```

**Parameters:**
- Provide M or more share file paths as arguments
- `--display-mnemonic`: Display the reconstructed mnemonic on screen (⚠️ **SENSITIVE!**)

**Alternative**: Provide a directory and it will use all `.json` files found:

```bash
frozenkrill combine-secret /path/to/shares/directory
```

## Share File Format

Shares are stored as JSON files with the following structure:

```json
{
  "version": 1,
  "scheme": "pedersen",
  "share_index": 2,
  "threshold": 3,
  "total_shares": 5,
  "mnemonic_length": 24,
  "share_data": "hex-encoded-share",
  "verification_data": "hex-encoded-commitments",
  "created_at": "2025-10-29T12:00:00Z",
  "checksum": "blake3-hash"
}
```

### File Format Design

- **Human-readable JSON**: Easy to inspect and verify
- **Version field**: Forward compatibility for future improvements
- **Metadata**: Threshold and total shares info for validation
- **Checksum**: BLAKE3 hash for integrity verification
- **Warning comments**: Files include warnings at the top

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

- **Algorithm**: Pedersen Verifiable Secret Sharing over Curve25519
- **Field**: Ristretto255 group (canonical form of Curve25519)
- **Polynomial**: Shamir's polynomial interpolation
- **Commitments**: Pedersen commitments for verification
- **Randomness**: Cryptographically secure random number generation via libsodium

### Implementation

- **Library**: [vsss-rs](https://github.com/mikelodder7/vsss-rs) v4.x
- **Curve**: Curve25519 (via `curve25519-dalek`)
- **Encoding**: BIP-39 mnemonic → entropy bytes → Curve25519 scalar
- **Security**: All intermediate values are zeroized after use
- **File format**: JSON with BLAKE3 checksums

### Security Guarantees

1. **Information-theoretic security**: M-1 shares reveal absolutely no information about the secret
2. **Verifiable**: Shares can be verified using Pedersen commitments without revealing the secret
3. **Tamper-evident**: Any modification to shares is detected via checksums and verification
4. **No trust required**: The scheme is cryptographically secure, not dependent on trusted parties

## Troubleshooting

### "Insufficient shares" error

You provided fewer than the threshold number of shares. Check the `threshold` field in the share files.

### "Incompatible shares" error

The shares are from different splitting operations. Ensure all shares have matching:
- `version`
- `threshold`
- `total_shares`
- `mnemonic_length`
- `verification_data`

### "Share verification failed" error

A share file may be corrupted or tampered with. Check:
- File integrity (checksum)
- File hasn't been manually edited
- File wasn't corrupted during transfer

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

**Q: Can I use password-protected shares?**
A: Shares are not encrypted by default. You can encrypt the share files separately using tools like `age` or `gpg`.

**Q: How is this different from Shamir's Secret Sharing (SLIP-39)?**
A: SLIP-39 is a different standard for mnemonic splitting. Pedersen VSS:
- Uses standard BIP-39 mnemonics
- Provides cryptographic verification
- Is not standardized for wallets (frozenkrill-specific)

**Q: Can someone with M-1 shares brute-force the last share?**
A: No, Pedersen VSS has information-theoretic security - M-1 shares provide zero information about the secret.

## References

- [Original Plan](https://github.com/douglaz/frozenkrill) - Frozenkrill project
- [vsss-rs](https://github.com/mikelodder7/vsss-rs) - Secret sharing library
- [Pedersen VSS Paper](https://link.springer.com/chapter/10.1007/3-540-46766-1_9) - Original research
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic standard

## License

This feature is part of frozenkrill and is licensed under MIT or Apache-2.0, matching the project license.

---

**⚠️ REMEMBER**: Secret sharing is a powerful tool but requires careful planning. Test thoroughly with small amounts before trusting it with significant funds.
