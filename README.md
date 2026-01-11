# TripleSec

Military-grade encryption for Roblox. Triple-cascade ciphers, PBKDF2 key derivation, and XTS mode.

---

## Features

- **Triple-Cascade Encryption**: AES-256 -> Twofish-256 -> Serpent-256 (VeraCrypt standard)
- **XTS Mode**: Proper disk encryption mode with sector-level security
- **PBKDF2**: Industry-standard key derivation with configurable iterations
- **Multiple Hash Functions**: SHA-256, SHA-512, Whirlpool
- **Volume Encryption**: Full VeraCrypt-compatible volume management
- **Pure Luau**: Native-optimized, no external dependencies

---

## Installation

1. Download/clone this repository
2. Place the folder structure in your game:
   ```
   ServerStorage/
   ├── Modules/
   │   ├── AES.lua
   │   ├── BitOps.lua
   │   ├── CipherCascade.lua
   │   ├── Entropy.lua
   │   ├── HMAC.lua
   │   ├── PBKDF2.lua
   │   ├── Serpent.lua
   │   ├── SHA256.lua
   │   ├── SHA512.lua
   │   ├── Twofish.lua
   │   ├── Whirlpool.lua
   │   └── XTS.lua
   └── INIT/
       └── TripleSec.lua
   ```
3. Require in your scripts:
   ```lua
   local TripleSec = require(game:GetService("ServerStorage").INIT.TripleSec)
   ```
---

## Performance Guide

---

### Iteration Recommendations

| Iterations | Time (SHA256) | Time (SHA512) | Security | 
|------------|---------------|---------------|----------|
| 1,000 | ~0.5s | ~1s | ⚠️ Minimum |
| 5,000 | ~2.5s | ~5s | ✅ Good |
| 10,000 | ~5s | ~10s | ✅ Strong |
| 50,000 | ~25s | ~50s | ⭐ Very Strong |
| 100,000 | ~50s | ~100s | ⭐ Maximum |

* Iterations above 1000 may cause script timeouts in Roblox. It depends on your device specifications and individual settings

### Hash Function Performance

- **SHA-256**: ~2x faster than SHA-512 (recommended for most use cases)
- **SHA-512**: Maximum security, slower performance
- **Whirlpool**: Alternative hash function, similar speed to SHA-512

### Cipher Performance

- **Single cipher** (AES/Serpent/Twofish): Fastest
- **Double cascade**: ~2x slower
- **Triple cascade**: ~3x slower (maximum security)

---

## Security Notes

This module provides:
- VeraCrypt-standard algorithms and implementation
- Triple-cascade provides defense-in-depth
- Proper XTS mode for sector-based encryption
- PBKDF2 prevents rainbow table attacks
- Cryptographically secure random number generation

However, **Roblox memory is not secure**. Keys exist in memory and could theoretically be accessed by a third party. 

---

## Documentation

- **[TripleSec](docs/triplesec.md)** - Main encryption interface
- **[AES](docs/aes.md)** - AES-256 cipher
- **[Serpent](docs/serpent.md)** - Serpent-256 cipher
- **[Twofish](docs/twofish.md)** - Twofish-256 cipher
- **[CipherCascade](docs/ciphercascade.md)** - Cascade encryption
- **[XTS](docs/xts.md)** - XTS encryption mode
- **[PBKDF2](docs/pbkdf2.md)** - Key derivation
- **[SHA256](docs/sha256.md)** - SHA-256 hash
- **[SHA512](docs/sha512.md)** - SHA-512 hash
- **[Whirlpool](docs/whirlpool.md)** - Whirlpool hash
- **[HMAC](docs/hmac.md)** - HMAC authentication
- **[BitOps](docs/bitops.md)** - Bit operations
- **[Entropy](docs/entropy.md)** - Random number generation

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature (i.e., yielding support) branch
3. Add tests for new functionality (please provide in the PR)
4. Submit the PR

---

## License

MIT License - see [LICENSE](LICENSE) for details

---

## Disclaimer

This library is provided as-is without warranty. While it provides industry-standard algorithms, this particular source code has not been professionally audited.

---

## Acknowledgments

- **VeraCrypt** - Algorithm specifications and security standards
- **NIST** - AES, SHA-2 standards

---

Made with ❤️ | Last updated 11/01/2026