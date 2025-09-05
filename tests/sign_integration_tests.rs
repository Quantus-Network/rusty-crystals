// tests/sign_integration_tests.rs

use qp_rusty_crystals_hdwallet::{generate_mnemonic, HDLattice};

#[test]
fn test_sign() {
	// Step 1: Generate a random mnemonic and derive Falcon keypair
	let mnemonic = generate_mnemonic(24).expect("Failed to generate mnemonic");
	let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
		.expect("Failed to create HDLattice from mnemonic");

	let dilithium_keypair = hd_lattice.generate_keys();

	// Step 2: Define the message to sign
	let message = b"Hello, Dilithium!";

	// Step 3: Sign the message using the secret key
	let signature = dilithium_keypair.sign(message, None, false);

	// Step 4: Verify the signature using the public key
	let verify_result = dilithium_keypair.verify(message, &signature, None);

	assert!(verify_result, "Signature verification failed",);
}
