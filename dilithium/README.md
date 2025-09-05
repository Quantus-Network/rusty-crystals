# Quantus Newtowrk CRYSTALS-Dilithium

Pure Rust implementation of the ML-DSA (CRYSTALS-Dilithium) post-quantum digital signature scheme.

## Features

- **ML-DSA-44, ML-DSA-65, ML-DSA-87** - All three security levels
- **Pure Rust** - No unsafe code, memory-safe implementation
- **NIST Compliant** - Verified against official test vectors
- **High Performance** - Optimized for speed and efficiency

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
qp-rusty-crystals-dilithium = "0.0.2"
```

### Basic Example

```rust
use qp_rusty_crystals_dilithium::{ml_dsa_44, Keypair};

// Generate a keypair
let keypair = ml_dsa_44::Keypair::generate(None);

// Sign a message
let message = b"Hello, post-quantum world!";
let signature = keypair.sign(message);

// Verify the signature
let is_valid = keypair.public_key.verify(message, &signature);
assert!(is_valid);
```

## Security Levels

| Variant | Security Level | Public Key Size | Signature Size |
|---------|----------------|-----------------|----------------|
| ML-DSA-44 | ~128 bits | 1,312 bytes | 2,420 bytes |
| ML-DSA-65 | ~192 bits | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | ~256 bits | 2,592 bytes | 4,627 bytes |

## Testing

```bash
cargo test
```

## Benchmarks

```bash
cargo bench
```

## License

GPL-3.0 - See [LICENSE](../LICENSE) for details.