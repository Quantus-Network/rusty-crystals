use bip39::{Language, Mnemonic};
use hmac::Mac;
use rand::RngCore;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore as ChaChaCore, SeedableRng};
use rusty_crystals_dilithium::ml_dsa_87::Keypair;
use sha2::Sha512;
use sha2::digest::FixedOutput;

mod tests;
mod test_vectors;

#[derive(Debug, thiserror::Error)]
pub enum HDLatticeError {
    #[error("BIP39 error: {0}")]
    Bip39Error(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Bad entropy bit count: {0}")]
    BadEntropyBitCount(usize),
    #[error("Mnemonic derivation failed: {0}")]
    MnemonicDerivationFailed(String),
    #[error("Invalid wormhole path: {0}")]
    InvalidWormholePath(String),
}

/// Manages entropy generation for HD wallets
pub struct HDLattice {
    pub seed: [u8; 64],
    pub master_key: [u8; 64],
}

const HARDENED_OFFSET: u32 = 0x80000000;
const SALT: &[u8] = b"Dilithium seed";

impl HDLattice {
    /// Create new HDEntropy from a master seed
    // #[tarpaulin::skip] // tarpaulin fails - this is covered.
    pub fn from_seed(seed: [u8; 64]) -> Result<Self, HDLatticeError> {
        Ok(Self {
            seed,
            master_key: Self::master_key_from_seed(&seed)?,
        })
    }

    /// Create new HDLattice from a BIP39 mnemonic phrase
    pub fn from_mnemonic(phrase: &str, passphrase: Option<&str>) -> Result<Self, HDLatticeError> {
        // Parse the mnemonic
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|e| HDLatticeError::Bip39Error(e.to_string()))?;

        // Generate seed from mnemonic
        let seed: [u8; 64] = mnemonic.to_seed_normalized(passphrase.unwrap_or(""));

        Ok(Self {
            seed,
            master_key: Self::master_key_from_seed(&seed)?,
        })
    }

    pub fn master_key_from_seed(seed: &[u8; 64]) -> Result<[u8; 64], HDLatticeError> {
        let mut hasher = hmac::Hmac::<Sha512>::new_from_slice(SALT).map_err(|_| {
            HDLatticeError::KeyDerivationFailed("Failed to create HMAC".to_string())
        })?;
        hasher.update(seed);
        Ok(hasher.finalize_fixed().into())
    }

    pub fn generate_keys(&self) -> Keypair {
        Keypair::generate(Some(&self.seed))
    }

    pub fn generate_derived_keys(&self, path: &str) -> Keypair {
        let derived_entropy = self.derive_entropy(path);
        Keypair::generate(Some(&derived_entropy.unwrap()))
    }

    // Derives entropy from a seed along a given path
    pub fn derive_entropy(&self, path: &str) -> Result<[u8; 64], HDLatticeError> {
        // If path is empty, return master seed
        if path.is_empty() {
            return Ok(self.master_key);
        }

        // Check if this is a wormhole path
        let (is_wormhole, remaining_path) = if path.starts_with("w/") {
            (true, &path[2..])
        } else {
            (false, path)
        };

        let entries = remaining_path.split('/');
        let mut entropy = self.master_key.clone();

        // For wormhole paths, we use a different salt to ensure separation
        if is_wormhole {
            let mut hasher = hmac::Hmac::<Sha512>::new_from_slice(b"Wormhole seed").map_err(|_| {
                HDLatticeError::KeyDerivationFailed("Failed to create HMAC".to_string())
            })?;
            hasher.update(&entropy);
            entropy = hasher.finalize_fixed().into();
        }

        // Continue with normal derivation
        for (_, c) in entries.into_iter().enumerate() {
            let mut child_index = c
                .parse::<u32>()
                .map_err(|_| HDLatticeError::KeyDerivationFailed("Non-integer path".to_string()))?;
            if child_index >= HARDENED_OFFSET {
                Err(HDLatticeError::KeyDerivationFailed(
                    "Path index >= 0x80000000".to_string(),
                ))?
            }
            child_index += HARDENED_OFFSET;

            entropy = self.derive_child_entropy(&entropy, child_index); // derive the child key and recurse
        }

        Ok(entropy)
    }

    /// Derives a child key using hardened derivation only, where the index indicates a hardened child if >= HARDENED_OFFSET.
    fn derive_child_entropy(&self, entropy: &[u8; 64], index: u32) -> [u8; 64] {
        let index_buffer = index.to_be_bytes();

        // Note - we follow Bip32 for the derived value since it is well known.
        // HMAC(R || 0x00 || L || index)
        #[allow(clippy::unwrap_used)]
        let mut hasher = hmac::Hmac::<Sha512>::new_from_slice(&entropy[32..]).unwrap();
        hasher.update(&[0x00]); // delimiter
        hasher.update(&entropy[..32]);
        hasher.update(&index_buffer);
        hasher.finalize_fixed().into()
    }
}

/// Generate a new random mnemonic of the specified word count
pub fn generate_mnemonic(word_count: usize) -> Result<String, HDLatticeError> {
    // Calculate entropy bytes needed (12 words = 16 bytes, 24 words = 32 bytes)
    let bits = match word_count {
        12 => 128,
        15 => 160,
        18 => 192,
        21 => 224,
        24 => 256,
        _ => return Err(HDLatticeError::BadEntropyBitCount(word_count)),
    };

    let entropy_bytes = bits / 8;
    let mut seed = [0u8; 32];

    // Use os rng to make seed
    OsRng::default().fill_bytes(&mut seed);

    // Use seed to initiate chacha stream and fill it
    // NOTE: chacha will "whiten" the entropy provided by the os
    // if an attacker does not 100% control the os entropy, chacha
    // will provide full entropy, due to avalanche effects
    let mut chacha_rng = ChaCha20Rng::from_seed(seed);

    let mut entropy = vec![0u8; entropy_bytes];
    chacha_rng.fill_bytes(&mut entropy);

    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| HDLatticeError::MnemonicDerivationFailed(e.to_string()))?;

    Ok(mnemonic.words().collect::<Vec<&str>>().join(" "))
}
