use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "no_std")]
use alloc::{boxed::Box, vec, vec::Vec};

#[cfg(not(feature = "no_std"))]
use std::boxed::Box;

use crate::{
	params,
	poly::Poly,
	polyvec::lvl2::{Polyveck, Polyvecl},
};

const K: usize = params::ml_dsa_44::K;
const L: usize = params::ml_dsa_44::L;

pub const SECRETKEYBYTES: usize = crate::params::ml_dsa_44::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::ml_dsa_44::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::ml_dsa_44::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type Signature = [u8; SIGNBYTES];

/// Workspace to avoid stack allocation of large matrices and vectors
struct CryptoWorkspace {
	// Matrix A (K x L polynomial vectors)
	mat: Box<[Polyvecl; K]>,
	// Polynomial vectors for various operations
	s1: Box<Polyvecl>,
	s2: Box<Polyveck>,
	t0: Box<Polyveck>,
	t1: Box<Polyveck>,
	y: Box<Polyvecl>,
	z: Box<Polyvecl>,
	w0: Box<Polyveck>,
	w1: Box<Polyveck>,
	h: Box<Polyveck>,
	cp: Box<Poly>,
	// Temporary polynomials to avoid stack allocations
	temp_poly1: Box<Poly>,
	temp_poly2: Box<Poly>,
	// Temporary polynomial vectors for copying operations
	temp_polyvecl: Box<Polyvecl>,
	temp_polyveck: Box<Polyveck>,
}

impl CryptoWorkspace {
	fn new() -> Self {
		Self {
			mat: Box::new([Polyvecl::default(); K]),
			s1: Box::new(Polyvecl::default()),
			s2: Box::new(Polyveck::default()),
			t0: Box::new(Polyveck::default()),
			t1: Box::new(Polyveck::default()),
			y: Box::new(Polyvecl::default()),
			z: Box::new(Polyvecl::default()),
			w0: Box::new(Polyveck::default()),
			w1: Box::new(Polyveck::default()),
			h: Box::new(Polyveck::default()),
			cp: Box::new(Poly::default()),
			temp_poly1: Box::new(Poly::default()),
			temp_poly2: Box::new(Poly::default()),
			temp_polyvecl: Box::new(Polyvecl::default()),
			temp_polyveck: Box::new(Polyveck::default()),
		}
	}
}

/// A pair of private and public keys.
#[derive(Clone)]
#[cfg(not(feature = "no_std"))]
pub struct Keypair {
	pub secret: SecretKey,
	pub public: PublicKey,
}

#[cfg(not(feature = "no_std"))]
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
		keypair(&mut pk, &mut sk, entropy);
		Keypair { secret: SecretKey::from_bytes(&sk), public: PublicKey::from_bytes(&pk) }
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
	pub fn from_bytes(bytes: &[u8]) -> Keypair {
		Keypair {
			secret: SecretKey::from_bytes(&bytes[..SECRETKEYBYTES]),
			public: PublicKey::from_bytes(&bytes[SECRETKEYBYTES..]),
		}
	}

	/// Compute a signature for a given message.
	///
	/// # Arguments
	///
	/// * 'msg' - message to sign
	///
	/// Returns Option<Signature>
	pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Option<Signature> {
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

/// Private key.
#[derive(Clone)]
#[cfg(not(feature = "no_std"))]
pub struct SecretKey {
	pub bytes: [u8; SECRETKEYBYTES],
}

#[cfg(not(feature = "no_std"))]
impl SecretKey {
	/// Returns a copy of underlying bytes.
	pub fn to_bytes(&self) -> [u8; SECRETKEYBYTES] {
		self.bytes
	}

	/// Create a SecretKey from bytes.
	///
	/// # Arguments
	///
	/// * 'bytes' - private key bytes
	///
	/// Returns a SecretKey
	pub fn from_bytes(bytes: &[u8]) -> SecretKey {
		SecretKey { bytes: bytes.try_into().expect("") }
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
	pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Option<Signature> {
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return None;
				}
				let x_len = x.len();
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2 + x_len];
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..].copy_from_slice(msg);
				let mut sig: Signature = [0u8; SIGNBYTES];
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
			},
			None => {
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2];
				m[2..].copy_from_slice(msg);
				let mut sig: Signature = [0u8; SIGNBYTES];
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
			},
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
			},
			crate::PH::SHA512 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
				]);
				phm.extend_from_slice(Sha512::digest(msg).as_slice());
			},
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
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
			},
			None => {
				let phm_len = phm.len();
				let mut m = vec![0; 2 + 11 + phm_len];
				m[0] = 1;
				m[2..2 + 11].copy_from_slice(&oid);
				m[2 + 11..].copy_from_slice(phm.as_slice());
				let mut sig: Signature = [0u8; SIGNBYTES];
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
			},
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
		self.bytes
	}

	/// Create a PublicKey from bytes.
	///
	/// # Arguments
	///
	/// * 'bytes' - public key bytes
	///
	/// Returns a PublicKey
	pub fn from_bytes(bytes: &[u8]) -> PublicKey {
		PublicKey { bytes: bytes.try_into().expect("") }
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
				verify(sig, m.as_slice(), &self.bytes)
			},
			None => {
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2];
				m[2..].copy_from_slice(msg);
				verify(sig, m.as_slice(), &self.bytes)
			},
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
			},
			crate::PH::SHA512 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
				]);
				phm.extend_from_slice(Sha512::digest(msg).as_slice());
			},
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
				verify(sig, m.as_slice(), &self.bytes)
			},
			None => {
				let phm_len = phm.len();
				let mut m = vec![0; 2 + 11 + phm_len];
				m[0] = 1;
				m[2..2 + 11].copy_from_slice(&oid);
				m[2 + 11..].copy_from_slice(phm.as_slice());
				verify(sig, m.as_slice(), &self.bytes)
			},
		}
	}
}

/// Generate public and private key with heap-allocated workspace.
///
/// # Arguments
///
/// * 'pk' - preallocated buffer for public key
/// * 'sk' - preallocated buffer for private key
/// * 'seed' - optional seed; if None random_bytes() is used for randomness generation
#[cfg(not(feature = "no_std"))]
pub fn keypair(pk: &mut [u8], sk: &mut [u8], seed: Option<&[u8]>) {
	let mut workspace = CryptoWorkspace::new();

	let mut init_seed: Vec<u8>;
	match seed {
		Some(x) => init_seed = x.to_vec(),
		None => {
			#[cfg(feature = "no_std")]
			unimplemented!("must provide entropy in verifier only mode");
			#[cfg(not(feature = "no_std"))]
			{
				init_seed = vec![0u8; params::SEEDBYTES];
				crate::random_bytes(&mut init_seed, params::SEEDBYTES);
			}
		}
	};
	init_seed.push(K as u8);
	init_seed.push(L as u8);

	const SEEDBUF_LEN: usize = 2 * params::SEEDBYTES + params::CRHBYTES;
	let mut seedbuf = [0u8; SEEDBUF_LEN];
	crate::fips202::shake256(&mut seedbuf, SEEDBUF_LEN, &init_seed, init_seed.len());

	let mut rho = [0u8; params::SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

	let mut rhoprime = [0u8; params::CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

	let mut key = [0u8; params::SEEDBYTES];
	key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

	crate::polyvec::lvl2::matrix_expand(&mut *workspace.mat, &rho);

	crate::polyvec::lvl2::l_uniform_eta(&mut workspace.s1, &rhoprime, 0);
	crate::polyvec::lvl2::k_uniform_eta(&mut workspace.s2, &rhoprime, L as u16);

	// Copy s1 to z using clone_from to avoid stack allocation
	workspace.z.clone_from(&workspace.s1); // s1hat = s1
	crate::polyvec::lvl2::l_ntt(&mut workspace.z);

	crate::polyvec::lvl2::matrix_pointwise_montgomery(&mut workspace.t1, &*workspace.mat, &workspace.z, &mut workspace.temp_poly1);
	crate::polyvec::lvl2::k_reduce(&mut workspace.t1);
	crate::polyvec::lvl2::k_invntt_tomont(&mut workspace.t1);
	crate::polyvec::lvl2::k_add(&mut workspace.t1, &*workspace.s2);
	crate::polyvec::lvl2::k_caddq(&mut workspace.t1);

	crate::polyvec::lvl2::k_power2round(&mut workspace.t1, &mut workspace.t0);

	crate::packing::ml_dsa_44::pack_pk(pk, &rho, &*workspace.t1);

	let mut tr = [0u8; params::TR_BYTES];
	crate::fips202::shake256(&mut tr, params::TR_BYTES, pk, PUBLICKEYBYTES);

	crate::packing::ml_dsa_44::pack_sk(sk, &rho, &tr, &key, &*workspace.t0, &*workspace.s1, &*workspace.s2);
}

/// Compute a signature for a given message from a private (secret) key with heap-allocated workspace.
///
/// # Arguments
///
/// * 'sig' - preallocated with at least SIGNBYTES buffer
/// * 'msg' - message to sign
/// * 'sk' - private key to use
/// * 'hedged' - indicates whether to randomize the signature or to act deterministically
#[cfg(not(feature = "no_std"))]
pub fn signature(sig: &mut [u8], msg: &[u8], sk: &[u8], hedged: bool) {
	let mut workspace = CryptoWorkspace::new();

	let mut rho = [0u8; params::SEEDBYTES];
	let mut tr = [0u8; params::TR_BYTES];
	let mut keymu = [0u8; params::SEEDBYTES + params::CRHBYTES];

	crate::packing::ml_dsa_44::unpack_sk(
		&mut rho,
		&mut tr,
		&mut keymu[..params::SEEDBYTES],
		&mut workspace.t0,
		&mut workspace.s1,
		&mut workspace.s2,
		sk,
	);

	let mut state = crate::fips202::KeccakState::default();
	crate::fips202::shake256_absorb(&mut state, &tr, params::TR_BYTES);
	crate::fips202::shake256_absorb(&mut state, msg, msg.len());
	crate::fips202::shake256_finalize(&mut state);
	crate::fips202::shake256_squeeze(&mut keymu[params::SEEDBYTES..], params::CRHBYTES, &mut state);

	let mut rnd = [0u8; params::SEEDBYTES];
	if hedged {
		crate::random_bytes(&mut rnd, params::SEEDBYTES);
	}
	state.init();
	crate::fips202::shake256_absorb(&mut state, &keymu[..params::SEEDBYTES], params::SEEDBYTES);
	crate::fips202::shake256_absorb(&mut state, &rnd, params::SEEDBYTES);
	crate::fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
	crate::fips202::shake256_finalize(&mut state);
	let mut rhoprime = [0u8; params::CRHBYTES];
	crate::fips202::shake256_squeeze(&mut rhoprime, params::CRHBYTES, &mut state);

	crate::polyvec::lvl2::matrix_expand(&mut *workspace.mat, &rho);
	crate::polyvec::lvl2::l_ntt(&mut workspace.s1);
	crate::polyvec::lvl2::k_ntt(&mut workspace.s2);
	crate::polyvec::lvl2::k_ntt(&mut workspace.t0);

	let mut nonce: u16 = 0;
	loop {
		crate::polyvec::lvl2::l_uniform_gamma1(&mut workspace.y, &rhoprime, nonce);
		nonce += 1;

		workspace.z.clone_from(&workspace.y);
		crate::polyvec::lvl2::l_ntt(&mut workspace.z);
		crate::polyvec::lvl2::matrix_pointwise_montgomery(&mut workspace.w1, &*workspace.mat, &*workspace.z, &mut workspace.temp_poly1);
		crate::polyvec::lvl2::k_reduce(&mut workspace.w1);
		crate::polyvec::lvl2::k_invntt_tomont(&mut workspace.w1);
		crate::polyvec::lvl2::k_caddq(&mut workspace.w1);

		crate::polyvec::lvl2::k_decompose(&mut workspace.w1, &mut workspace.w0);
		crate::polyvec::lvl2::k_pack_w1(sig, &*workspace.w1);

		state.init();
		crate::fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
		crate::fips202::shake256_absorb(&mut state, sig, K * params::ml_dsa_44::POLYW1_PACKEDBYTES);
		crate::fips202::shake256_finalize(&mut state);
		crate::fips202::shake256_squeeze(sig, params::ml_dsa_44::C_DASH_BYTES, &mut state);

		crate::poly::ml_dsa_44::challenge(&mut workspace.cp, sig);
		crate::poly::ntt(&mut workspace.cp);

		crate::polyvec::lvl2::l_pointwise_poly_montgomery(&mut workspace.z, &*workspace.cp, &*workspace.s1);
		crate::polyvec::lvl2::l_invntt_tomont(&mut workspace.z);
		crate::polyvec::lvl2::l_add(&mut workspace.z, &*workspace.y);
		crate::polyvec::lvl2::l_reduce(&mut workspace.z);

		if crate::polyvec::lvl2::l_chknorm(
			&*workspace.z,
			(params::ml_dsa_44::GAMMA1 - params::ml_dsa_44::BETA) as i32,
		) > 0
		{
			continue;
		}

		crate::polyvec::lvl2::k_pointwise_poly_montgomery(&mut workspace.h, &*workspace.cp, &*workspace.s2);
		crate::polyvec::lvl2::k_invntt_tomont(&mut workspace.h);
		crate::polyvec::lvl2::k_sub(&mut workspace.w0, &*workspace.h);
		crate::polyvec::lvl2::k_reduce(&mut workspace.w0);

		if crate::polyvec::lvl2::k_chknorm(
			&*workspace.w0,
			(params::ml_dsa_44::GAMMA2 - params::ml_dsa_44::BETA) as i32,
		) > 0
		{
			continue;
		}

		crate::polyvec::lvl2::k_pointwise_poly_montgomery(&mut workspace.h, &*workspace.cp, &*workspace.t0);
		crate::polyvec::lvl2::k_invntt_tomont(&mut workspace.h);
		crate::polyvec::lvl2::k_reduce(&mut workspace.h);

		if crate::polyvec::lvl2::k_chknorm(&*workspace.h, params::ml_dsa_44::GAMMA2 as i32) > 0 {
			continue;
		}

		crate::polyvec::lvl2::k_add(&mut workspace.w0, &*workspace.h);

		let n = crate::polyvec::lvl2::k_make_hint(&mut workspace.h, &*workspace.w0, &*workspace.w1);

		if n > params::ml_dsa_44::OMEGA as i32 {
			continue;
		}

		crate::packing::ml_dsa_44::pack_sig(sig, None, &*workspace.z, &*workspace.h);

		return;
	}
}

/// Verify a signature for a given message with a public key using heap-allocated workspace.
///
/// # Arguments
///
/// * 'sig' - signature to verify
/// * 'm' - message that is claimed to be signed
/// * 'pk' - public key
///
/// Returns 'true' if the verification process was successful, 'false' otherwise
pub fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
	if sig.len() != SIGNBYTES {
		return false;
	}

	// Use boxed allocations for large structures
	let mut workspace = CryptoWorkspace::new();
	let mut buf = Box::new([0u8; K * params::ml_dsa_44::POLYW1_PACKEDBYTES]);

	let mut rho = [0u8; params::SEEDBYTES];
	let mut mu = [0u8; params::CRHBYTES];
	let mut c = [0u8; params::ml_dsa_44::C_DASH_BYTES];
	let mut c2 = [0u8; params::ml_dsa_44::C_DASH_BYTES];
	let mut state = crate::fips202::KeccakState::default();

	crate::packing::ml_dsa_44::unpack_pk(&mut rho, &mut workspace.t1, pk);
	if !crate::packing::ml_dsa_44::unpack_sig(&mut c, &mut workspace.z, &mut workspace.h, sig) {
		return false;
	}
	if crate::polyvec::lvl2::l_chknorm(
		&*workspace.z,
		(params::ml_dsa_44::GAMMA1 - params::ml_dsa_44::BETA) as i32,
	) > 0
	{
		return false;
	}

	// Compute CRH(CRH(rho, t1), msg)
	crate::fips202::shake256(&mut mu, params::CRHBYTES, pk, PUBLICKEYBYTES);
	crate::fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	crate::fips202::shake256_absorb(&mut state, m, m.len());
	crate::fips202::shake256_finalize(&mut state);
	crate::fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

	// Matrix-vector multiplication; compute Az - c2^dt1
	crate::poly::ml_dsa_44::challenge(&mut workspace.cp, &c);
	crate::polyvec::lvl2::matrix_expand(&mut *workspace.mat, &rho);

	crate::polyvec::lvl2::l_ntt(&mut workspace.z);
	crate::polyvec::lvl2::matrix_pointwise_montgomery(&mut workspace.w1, &*workspace.mat, &*workspace.z, &mut workspace.temp_poly1);

	crate::poly::ntt(&mut workspace.cp);
	crate::polyvec::lvl2::k_shiftl(&mut workspace.t1);
	crate::polyvec::lvl2::k_ntt(&mut workspace.t1);
	// Copy t1 to temp_polyveck using unsafe ptr::copy to eliminate stack allocation
	unsafe {
		std::ptr::copy_nonoverlapping(
			workspace.t1.vec.as_ptr(),
			workspace.temp_polyveck.vec.as_mut_ptr(),
			K,
		);
	}
	crate::polyvec::lvl2::k_pointwise_poly_montgomery(&mut workspace.t1, &*workspace.cp, &workspace.temp_polyveck);

	crate::polyvec::lvl2::k_sub(&mut workspace.w1, &*workspace.t1);
	crate::polyvec::lvl2::k_reduce(&mut workspace.w1);
	crate::polyvec::lvl2::k_invntt_tomont(&mut workspace.w1);

	// Reconstruct w1
	crate::polyvec::lvl2::k_caddq(&mut workspace.w1);
	crate::polyvec::lvl2::k_use_hint(&mut workspace.w1, &*workspace.h);
	crate::polyvec::lvl2::k_pack_w1(&mut *buf, &*workspace.w1);

	// Call random oracle and verify challenge
	state.init();
	crate::fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	crate::fips202::shake256_absorb(&mut state, &*buf, K * params::ml_dsa_44::POLYW1_PACKEDBYTES);
	crate::fips202::shake256_finalize(&mut state);
	crate::fips202::shake256_squeeze(&mut c2, params::ml_dsa_44::C_DASH_BYTES, &mut state);
	// Doesn't require constant time equality check
	if c != c2 {
		return false;
	}
	true
}

#[cfg(test)]
#[cfg(not(feature = "no_std"))]
mod tests {
	use super::*;
	#[test]
	fn self_verify_hedged() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.sign(&msg, None, true);
		assert!(keys.verify(&msg, &sig.unwrap(), None));
	}
	#[test]
	fn self_verify() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.sign(&msg, None, false);
		assert!(keys.verify(&msg, &sig.unwrap(), None));
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
}
