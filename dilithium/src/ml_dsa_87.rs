use sha2::{Digest, Sha256, Sha512};
#[cfg(not(feature = "no_std"))]
use std::vec;

use crate::errors::{KeyParsingError, KeyParsingError::BadSecretKey};

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec};
use core::fmt;

pub const SECRETKEYBYTES: usize = crate::params::ml_dsa_87::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::ml_dsa_87::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::ml_dsa_87::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type Signature = [u8; SIGNBYTES];

/// A pair of private and public keys.
#[derive(Clone)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Generate a Keypair instance.
    ///
    /// # Arguments
    ///
    /// * 'entropy' - optional bytes for determining the generation process
    ///
    /// Returns an instance of Keypair
    pub fn generate(entropy: Option<&[u8]>) -> Keypair {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        crate::sign::ml_dsa_87::keypair(&mut pk, &mut sk, entropy);
        Keypair {
            secret: SecretKey::from_bytes(&sk).expect("Should never fail"),
            public: PublicKey::from_bytes(&pk).expect("Should never fail"),
        }
    }

    /// Convert a Keypair to a bytes array.
    ///
    /// Returns an array containing private and public keys bytes
    pub fn to_bytes(&self) -> [u8; KEYPAIRBYTES] {
        let mut result = [0u8; KEYPAIRBYTES];
        result[..SECRETKEYBYTES].copy_from_slice(&self.secret.to_bytes());
        result[SECRETKEYBYTES..].copy_from_slice(&self.public.to_bytes());
        result
    }

    /// Create a Keypair from bytes.
    ///
    /// # Arguments
    ///
    /// * 'bytes' - private and public keys bytes
    ///
    /// Returns a Keypair
    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, KeyParsingError> {
        if bytes.len() != SECRETKEYBYTES + PUBLICKEYBYTES {
            return Err(KeyParsingError::BadKeypair);
        }
        let (secret_bytes, public_bytes) = bytes.split_at(SECRETKEYBYTES);
        let secret =
            SecretKey::from_bytes(secret_bytes).map_err(|_| KeyParsingError::BadKeypair)?;
        let public =
            PublicKey::from_bytes(public_bytes).map_err(|_| KeyParsingError::BadKeypair)?;
        Ok(Keypair { secret, public })
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    ///
    /// Returns Option<Signature>
    pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Signature {
        self.secret.sign(msg, ctx, hedged)
    }

    /// Verify a signature for a given message with a public key.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    ///
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
        self.public.verify(msg, sig, ctx)
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    ///
    /// Returns Option<Signature>
    #[cfg(not(feature = "no_std"))]

    pub fn prehash_sign(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        hedged: bool,
        ph: crate::PH,
    ) -> Option<Signature> {
        self.secret.prehash_sign(msg, ctx, hedged, ph)
    }

    /// Verify a signature for a given message with a public key.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    ///
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn prehash_verify(
        &self,
        msg: &[u8],
        sig: &[u8],
        ctx: Option<&[u8]>,
        ph: crate::PH,
    ) -> bool {
        self.public.prehash_verify(msg, sig, ctx, ph)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .finish()
    }
}

/// Private key.
#[derive(Clone)]
pub struct SecretKey {
    pub bytes: [u8; SECRETKEYBYTES],
}

impl SecretKey {
    /// Returns a copy of underlying bytes.
    pub fn to_bytes(&self) -> [u8; SECRETKEYBYTES] {
        self.bytes.clone()
    }

    /// Create a SecretKey from bytes.
    ///
    /// # Arguments
    ///
    /// * 'bytes' - private key bytes
    ///
    /// Returns a SecretKey
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, KeyParsingError> {
        let result = bytes.try_into();
        match result {
            Ok(bytes) => Ok(SecretKey { bytes }),
            Err(_) => Err(BadSecretKey),
        }
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    /// * 'ctx' - context string
    /// * 'hedged' - wether to use RNG or not
    ///
    /// Returns Option<Signature>
    pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Signature {
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    panic!("ctx length must not be larger than 255");
                }
                let x_len = x.len();
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2 + x_len];
                m[1] = x_len as u8;
                m[2..2 + x_len].copy_from_slice(x);
                m[2 + x_len..].copy_from_slice(msg);
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_87::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                sig
            }
            None => {
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2];
                m[2..].copy_from_slice(msg);
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_87::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                sig
            }
        }
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    /// * 'ctx' - context string
    /// * 'hedged' - wether to use RNG or not
    /// * 'ph' - pre-hash function
    ///
    /// Returns Option<Signature>
    #[cfg(not(feature = "no_std"))]
    pub fn prehash_sign(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        hedged: bool,
        ph: crate::PH,
    ) -> Option<Signature> {
        let mut oid = [0u8; 11];
        let mut phm: Vec<u8> = Vec::new();
        match ph {
            crate::PH::SHA256 => {
                oid.copy_from_slice(&[
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                ]);
                phm.extend_from_slice(Sha256::digest(msg).as_slice());
            }
            crate::PH::SHA512 => {
                oid.copy_from_slice(&[
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                ]);
                phm.extend_from_slice(Sha512::digest(msg).as_slice());
            }
        }
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    return None;
                }
                let x_len = x.len();
                let phm_len = phm.len();
                let mut m = vec![0; 2 + x_len + 11 + phm_len];
                m[0] = 1;
                m[1] = x_len as u8;
                m[2..2 + x_len].copy_from_slice(x);
                m[2 + x_len..2 + x_len + 11].copy_from_slice(&oid);
                m[2 + x_len + 11..].copy_from_slice(phm.as_slice());
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_87::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                Some(sig)
            }
            None => {
                let phm_len = phm.len();
                let mut m = vec![0; 2 + 11 + phm_len];
                m[0] = 1;
                m[2..2 + 11].copy_from_slice(&oid);
                m[2 + 11..].copy_from_slice(phm.as_slice());
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_87::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                Some(sig)
            }
        }
    }
}

#[derive(Eq, Clone, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub struct PublicKey {
    pub bytes: [u8; PUBLICKEYBYTES],
}

impl PublicKey {
    /// Returns a copy of underlying bytes.
    pub fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
        self.bytes.clone()
    }

    /// Create a PublicKey from bytes.
    ///
    /// # Arguments
    ///
    /// * 'bytes' - public key bytes
    ///
    /// Returns a PublicKey
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, KeyParsingError> {
        let result = bytes.try_into();
        match result {
            Ok(bytes) => Ok(PublicKey { bytes }),
            Err(_) => Err(KeyParsingError::BadPublicKey),
        }
    }

    /// Verify a signature for a given message with a public key.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    /// * 'ctx' - context string
    ///
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    return false;
                }
                let x_len = x.len();
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2 + x_len];
                m[1] = x_len as u8;
                m[2..2 + x_len].copy_from_slice(x);
                m[2 + x_len..].copy_from_slice(msg);
                crate::sign::ml_dsa_87::verify(sig, m.as_slice(), &self.bytes)
            }
            None => {
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2];
                m[2..].copy_from_slice(msg);
                crate::sign::ml_dsa_87::verify(sig, m.as_slice(), &self.bytes)
            }
        }
    }

    /// Verify a signature for a given message with a public key.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    /// * 'ctx' - context string
    /// * 'ph' - pre-hash function
    ///
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn prehash_verify(
        &self,
        msg: &[u8],
        sig: &[u8],
        ctx: Option<&[u8]>,
        ph: crate::PH,
    ) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        let mut oid = [0u8; 11];
        let mut phm: Vec<u8> = Vec::new();
        match ph {
            crate::PH::SHA256 => {
                oid.copy_from_slice(&[
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                ]);
                phm.extend_from_slice(Sha256::digest(msg).as_slice());
            }
            crate::PH::SHA512 => {
                oid.copy_from_slice(&[
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                ]);
                phm.extend_from_slice(Sha512::digest(msg).as_slice());
            }
        }
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    return false;
                }
                let x_len = x.len();
                let phm_len = phm.len();
                let mut m = vec![0; 2 + x_len + 11 + phm_len];
                m[0] = 1;
                m[1] = x_len as u8;
                m[2..2 + x_len].copy_from_slice(x);
                m[2 + x_len..2 + x_len + 11].copy_from_slice(&oid);
                m[2 + x_len + 11..].copy_from_slice(phm.as_slice());
                crate::sign::ml_dsa_87::verify(sig, m.as_slice(), &self.bytes)
            }
            None => {
                let phm_len = phm.len();
                let mut m = vec![0; 2 + 11 + phm_len];
                m[0] = 1;
                m[2..2 + 11].copy_from_slice(&oid);
                m[2 + 11..].copy_from_slice(phm.as_slice());
                crate::sign::ml_dsa_87::verify(sig, m.as_slice(), &self.bytes)
            }
        }
    }
}

#[cfg(test)]
#[cfg(not(feature = "no_std"))]
mod tests {
    use super::{
        Keypair, PublicKey, SecretKey, Signature, KEYPAIRBYTES, PUBLICKEYBYTES, SECRETKEYBYTES,
        SIGNBYTES,
    };
    use crate::fips202::KeccakState;
    #[test]
    fn self_verify_hedged() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.sign(&msg, None, true);
        assert!(keys.verify(&msg, &sig, None));
    }
    #[test]
    fn self_verify() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.sign(&msg, None, false);
        assert!(keys.verify(&msg, &sig, None));
    }
    #[test]
    fn self_verify_prehash_hedged() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.prehash_sign(&msg, None, true, crate::PH::SHA256);
        assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
    }
    #[test]
    fn self_verify_prehash() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.prehash_sign(&msg, None, false, crate::PH::SHA256);
        assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
    }

    #[test]
    fn test_memory_usage() {
        println!("=== ML-DSA-87 Memory Usage Test ===");
        println!("Keypair size: {} bytes", std::mem::size_of::<Keypair>());
        println!("SecretKey size: {} bytes", std::mem::size_of::<SecretKey>());
        println!("PublicKey size: {} bytes", std::mem::size_of::<PublicKey>());
        println!("Signature size: {} bytes", std::mem::size_of::<Signature>());
        println!("SECRETKEYBYTES: {}", SECRETKEYBYTES);
        println!("PUBLICKEYBYTES: {}", PUBLICKEYBYTES);
        println!("SIGNBYTES: {}", SIGNBYTES);
        println!("KEYPAIRBYTES: {}", KEYPAIRBYTES);

        // Generate a keypair and signature to verify sizes
        let keys = Keypair::generate(None);
        let msg = b"test message";
        let sig = keys.sign(msg, None, false);

        println!("Generated signature length: {} bytes", sig.len());
        println!(
            "Generated keypair secret key length: {} bytes",
            keys.secret.bytes.len()
        );
        println!(
            "Generated keypair public key length: {} bytes",
            keys.public.bytes.len()
        );
    }

    #[test]
    fn test_generate_memory_usage() {
        println!("=== ML-DSA-87 Generate Memory Usage Test ===");

        // Check structure size before generation
        println!(
            "Keypair struct size: {} bytes",
            std::mem::size_of::<Keypair>()
        );
        println!(
            "SecretKey struct size: {} bytes",
            std::mem::size_of::<SecretKey>()
        );
        println!(
            "PublicKey struct size: {} bytes",
            std::mem::size_of::<PublicKey>()
        );

        // Check array sizes in structures
        println!(
            "SecretKey.bytes array size: {} bytes",
            std::mem::size_of_val(&[0u8; SECRETKEYBYTES])
        );
        println!(
            "PublicKey.bytes array size: {} bytes",
            std::mem::size_of_val(&[0u8; PUBLICKEYBYTES])
        );

        // Check total data size
        println!("Total secret key data: {} bytes", SECRETKEYBYTES);
        println!("Total public key data: {} bytes", PUBLICKEYBYTES);
        println!("Total keypair data: {} bytes", KEYPAIRBYTES);

        // Check if structures have padding
        println!(
            "SecretKey padding: {} bytes",
            std::mem::size_of::<SecretKey>() - SECRETKEYBYTES
        );
        println!(
            "PublicKey padding: {} bytes",
            std::mem::size_of::<PublicKey>() - PUBLICKEYBYTES
        );
        println!(
            "Keypair padding: {} bytes",
            std::mem::size_of::<Keypair>() - KEYPAIRBYTES
        );

        // Generate keys and check actual sizes
        let keys = Keypair::generate(None);
        println!(
            "Generated keypair total size: {} bytes",
            std::mem::size_of_val(&keys)
        );
        println!(
            "Generated secret key total size: {} bytes",
            std::mem::size_of_val(&keys.secret)
        );
        println!(
            "Generated public key total size: {} bytes",
            std::mem::size_of_val(&keys.public)
        );
    }

    #[test]
    fn test_generate_process_memory() {
        println!("=== ML-DSA-87 Generate Process Memory Test ===");

        // Check structure sizes used in generation process
        println!("=== Structures used in generate() ===");

        // Check sizes of types used in sign::ml_dsa_87::keypair
        // (we need to check in the sign module)
        println!("=== Let's check sizes in the sign module ===");

        // Check basic type sizes
        println!("u8 size: {} bytes", std::mem::size_of::<u8>());
        println!("u32 size: {} bytes", std::mem::size_of::<u32>());
        println!("usize size: {} bytes", std::mem::size_of::<usize>());

        // Check array sizes used in algorithm
        println!("=== Array sizes in algorithm ===");
        println!("[u8; 32] size: {} bytes", std::mem::size_of::<[u8; 32]>());
        println!("[u8; 64] size: {} bytes", std::mem::size_of::<[u8; 64]>());
        println!("[u8; 128] size: {} bytes", std::mem::size_of::<[u8; 128]>());
        println!("[u8; 256] size: {} bytes", std::mem::size_of::<[u8; 256]>());
        println!("[u8; 512] size: {} bytes", std::mem::size_of::<[u8; 512]>());
        println!(
            "[u8; 1024] size: {} bytes",
            std::mem::size_of::<[u8; 1024]>()
        );
        println!(
            "[u8; 2048] size: {} bytes",
            std::mem::size_of::<[u8; 2048]>()
        );

        // Check sizes of types from crate::poly
        println!("=== Sizes of types from poly ===");
        // println!("Poly size: {} bytes", std::mem::size_of::<crate::poly::ml_dsa_87::Poly>());

        // Check sizes of types from crate::polyvec
        println!("=== Sizes of types from polyvec ===");
        // println!("Polyvec size: {} bytes", std::mem::size_of::<crate::polyvec::lvl5::Polyvec>());

        // Check sizes of types from crate::packing
        println!("=== Sizes of types from packing ===");
        // println!("PackedPolyvec size: {} bytes", std::mem::size_of::<crate::packing::ml_dsa_87::PackedPolyvec>());

        println!("=== Note: To check exact sizes of types from other modules,");
        println!("   we need to add tests in the respective modules or use extern crate ===");
    }

    #[test]
    fn test_generate_actual_memory() {
        println!("=== ML-DSA-87 Actual Generate Memory Usage ===");

        // Check sizes of structures used in keypair()
        println!("=== Structures in keypair() ===");

        // Check sizes from params
        println!("SEEDBYTES: {} bytes", crate::params::SEEDBYTES);
        println!("CRHBYTES: {} bytes", crate::params::CRHBYTES);
        println!("TR_BYTES: {} bytes", crate::params::TR_BYTES);

        // Check sizes of arrays used in keypair()
        let _seedbuf_len = 2 * crate::params::SEEDBYTES + crate::params::CRHBYTES;
        println!(
            "seedbuf array size: {} bytes",
            std::mem::size_of::<[u8; 2 * crate::params::SEEDBYTES + crate::params::CRHBYTES]>()
        );
        println!(
            "rho array size: {} bytes",
            std::mem::size_of::<[u8; crate::params::SEEDBYTES]>()
        );
        println!(
            "rhoprime array size: {} bytes",
            std::mem::size_of::<[u8; crate::params::CRHBYTES]>()
        );
        println!(
            "key array size: {} bytes",
            std::mem::size_of::<[u8; crate::params::SEEDBYTES]>()
        );
        println!(
            "tr array size: {} bytes",
            std::mem::size_of::<[u8; crate::params::TR_BYTES]>()
        );

        // Check sizes of Polyvecl and Polyveck
        println!("=== Sizes of Polyvecl and Polyveck ===");
        // println!("Polyvecl size: {} bytes", std::mem::size_of::<crate::polyvec::lvl5::Polyvecl>());
        // println!("Polyveck size: {} bytes", std::mem::size_of::<crate::polyvec::lvl5::Polyveck>());

        // Check sizes of Poly
        println!("=== Sizes of Poly ===");
        // println!("Poly size: {} bytes", std::mem::size_of::<crate::poly::ml_dsa_87::Poly>());

        // Check sizes of mat (array of Polyvecl)
        let k = crate::params::ml_dsa_87::K;
        let l = crate::params::ml_dsa_87::L;
        println!("K (number of Polyveck): {}", k);
        println!("L (number of Polyvecl): {}", l);
        // println!("mat array size: {} bytes", std::mem::size_of::<[crate::polyvec::lvl5::Polyvecl; crate::params::ml_dsa_87::K]>());

        // Check sizes of KeccakState
        println!("=== Sizes of KeccakState ===");
        println!(
            "KeccakState size: {} bytes",
            std::mem::size_of::<KeccakState>()
        );
        println!(
            "KeccakState.s array size: {} bytes",
            std::mem::size_of::<[u64; 25]>()
        );
        println!(
            "KeccakState.pos size: {} bytes",
            std::mem::size_of::<usize>()
        );

        // Check total size of input and output data
        println!("=== Data sizes ===");
        println!("Input pk buffer: {} bytes", PUBLICKEYBYTES);
        println!("Input sk buffer: {} bytes", SECRETKEYBYTES);
        println!(
            "Total input/output: {} bytes",
            PUBLICKEYBYTES + SECRETKEYBYTES
        );

        // Check sizes of Vec used in keypair()
        println!("=== Vec sizes ===");
        println!(
            "init_seed Vec (max): {} bytes",
            std::mem::size_of::<Vec<u8>>() + crate::params::SEEDBYTES
        );
    }
}
