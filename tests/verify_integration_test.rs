// tests/verify_integration_test.rs

#[cfg(feature = "dilithium")]
mod helpers;
#[cfg(feature = "dilithium")]
use helpers::kat::{parse_test_vectors, TestVector};
#[cfg(feature = "dilithium")]
use rusty_crystals_dilithium::ml_dsa_87::{Keypair, PUBLICKEYBYTES};

#[cfg(feature = "dilithium")]
fn keypair_from_test(test: &TestVector) -> Keypair {
    let total_len = test.sk.len() + test.pk.len();
    let mut result = vec![0; total_len];
    result[..test.sk.len()].copy_from_slice(&test.sk);
    result[test.sk.len()..].copy_from_slice(&test.pk);
    Keypair::from_bytes(&result)
}

#[cfg(feature = "dilithium")]
#[test]
fn test_nist_kat() {
    let kat_data = include_str!("../test_vectors/PQCsignKAT_Dilithium5.rsp");
    let test_vectors = parse_test_vectors(kat_data);
    for test in test_vectors {
        verify_test_vector(&test);
    }
}

/// Verifies a single test vector for Falcon-1024 (padded).
///
/// # Arguments
///
/// * `test` - A reference to the `TestVector` struct containing all the necessary fields.
#[cfg(feature = "dilithium")]
fn verify_test_vector(test: &TestVector) {
    // Check if the fields have correct lengths
    assert_eq!(
        test.msg.len(),
        test.mlen,
        "Message length mismatch from test vector"
    );
    assert_eq!(
        test.sm.len(),
        test.smlen,
        "Signed message length mismatch from test vector"
    );
    // Check public key length for Dilithium3
    assert_eq!(test.pk.len(), PUBLICKEYBYTES, "Public key length mismatch");

    let signature = test.extract_signature();

    // Now call verify with the extracted signature

    let keypair = keypair_from_test(test);
    let result = keypair.verify(&test.msg, &signature, None);

    assert!(result, "Signature verification failed",);
}

#[cfg(feature = "dilithium")]
#[test]
fn test_verify_invalid_signature() {
    // Generate Dilithium keypair
    let keys_1 = Keypair::generate(None);
    let keys_2 = Keypair::generate(None);
    let keys_3 = Keypair::generate(None);

    // Message to sign
    let message = b"Hello, Resonance!";
    // Sign the message
    let signature = keys_2.sign(message, None, false).unwrap();

    // Verify the signature with wrong key
    let result = keys_1.verify(&signature, message, None);

    assert!(!result, "Expected verification to fail, but it succeeded");

    let result = keys_3.verify(&signature, message, None);

    assert!(!result, "Expected verification to fail, but it succeeded");
}
