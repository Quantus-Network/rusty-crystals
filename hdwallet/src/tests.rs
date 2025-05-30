#[cfg(test)]
mod hdwallet_tests {
    use rand::Rng;
    use rusty_crystals_dilithium::ml_dsa_87::{Keypair};
    use crate::{generate_mnemonic, test_vectors::get_test_vectors, HDLattice, HDLatticeError};

    #[test]
    fn test_from_seed() {
        let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd1 = HDLattice::from_mnemonic(&mnemonic, None).unwrap();
        let hd2 = HDLattice::from_seed(hd1.seed).unwrap();
        assert_eq!(hd1.master_key, hd2.master_key);
        assert_eq!(hd1.seed, hd2.seed);
    }

    #[test]
    fn test_mnemonic_creation() {
        // Test generating new mnemonic
        let mnemonic = dbg!(generate_mnemonic(12).unwrap());
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        println!("Generated mnemonic: {}", mnemonic);
        // Test creating HDEntropy from mnemonic
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();
        let hd2 = HDLattice::from_mnemonic(&mnemonic, None).unwrap();
        let hd3 = HDLattice::from_mnemonic(&mnemonic, Some("password")).unwrap();
        println!("Generated hd: {:?}", hd.master_key);

        // Derive some child seeds
        let master_key = hd.generate_keys();
        let key2 = hd2.generate_keys();
        let key3 = hd3.generate_keys();
        println!("Generated keyz: {:?}", master_key.public.to_bytes());

        // // Seeds should be different but deterministic
        assert_ne!(
            master_key.secret.bytes, key3.secret.bytes,
            "password has no effect"
        );
        assert_eq!(
            master_key.secret.bytes, key2.secret.bytes,
            "keys are not deterministic"
        );

        let derived_key = hd.generate_derived_keys("0/2147483647/1");
        assert_ne!(
            master_key.secret.bytes, derived_key.secret.bytes,
            "derived key not derived"
        );

        // UNCOMMENT THIS AND RUN WITH `cargo test -- --nocapture` TO GENERATE TEST VECTORS
        // let vecs = generate_test_vectors(10);
        // print_keys_mnemonics_paths_as_test_vector(&vecs);
    }

    fn generate_test_vectors(n: u8) -> Vec<(Keypair, String, String)> {
        (0..n).map(|_| {
            let mnemonic = generate_mnemonic(12).unwrap();
            let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();
            let path = generate_random_path();
            let k = hd.generate_derived_keys(&path);
            (k, mnemonic, path)
        }).collect()
    }

    fn generate_random_path() -> String {
        let mut rng = rand::thread_rng();
        let length = rng.gen_range(5..15);

        (0..length)
            .map(|_| rng.gen_range(1..100))
            .map(|num| num.to_string())
            .collect::<Vec<_>>()
            .join("/")
    }

    // Leave this in, we may need to generate new test vectors
    fn print_keys_mnemonics_paths_as_test_vector(keys: &[(Keypair, String, String)]) {
        let mut vector_str = String::from("[\n");
        for (_i, (key, mnemonic, path)) in keys.iter().enumerate() {
            vector_str.push_str(&format!(
                "    (Keypair::from_bytes(&*vec![{}]), \"{}\", \"{}\"),\n",
                key.to_bytes().iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<String>>().join(", "),
                mnemonic,
                path
            ));
        }
        vector_str.push_str("]");

        println!("{}", vector_str);
    }

    #[test]
    fn test_derive_seed() {
        for (expected_keys, mnemonic_str, derivation_path) in get_test_vectors() {
            let hd = HDLattice::from_mnemonic(mnemonic_str, None).unwrap();
            println!("Deriving seed for path: {}", derivation_path);
            // Generate keys based on the derivation path
            let generated_keys = if derivation_path == "" {
                hd.generate_keys()
            } else {
                hd.generate_derived_keys(derivation_path)
            };

            // Compare secret keys
            assert_eq!(
                generated_keys.secret.bytes,
                expected_keys.secret.bytes,
                "Secret key mismatch for path: {}",
                derivation_path
            );

            // Compare public keys
            assert_eq!(
                generated_keys.public.bytes,
                expected_keys.public.bytes,
                "Public key mismatch for path: {}",
                derivation_path
            );
        }
    }

    #[test]
    fn test_generate_mnemonic_valid_lengths() {
        let valid_lengths = [12, 15, 18, 21, 24];
        for &word_count in &valid_lengths {
            let mnemonic = generate_mnemonic(word_count)
                .expect(&format!("Failed to generate mnemonic for {} words", word_count));

            // Split mnemonic into words and count them
            let word_count_result = mnemonic.split_whitespace().count();

            // Assert the word count matches the expected
            assert_eq!(
                word_count_result, word_count,
                "Expected {} words, but got {}",
                word_count, word_count_result
            );
        }
    }

    #[test]
    fn test_generate_mnemonic_invalid_length() {
        let invalid_lengths = [10, 14, 19, 25]; // Invalid word counts not allowed by BIP-39
        for &word_count in &invalid_lengths {
            let result = generate_mnemonic(word_count);

            // Assert that the result is an error
            assert!(
                result.is_err(),
                "Expected an error for invalid word count {}, but got Ok()",
                word_count
            );

            // Check the specific error type
            if let Err(err) = result {
                assert!(
                    matches!(err, HDLatticeError::BadEntropyBitCount(_)),
                    "Unexpected error type for word count {}: {:?}",
                    word_count, err
                );
            }
        }
    }

    #[test]
    fn test_derive_invalid_path() {
        // Create a sample HDLattice instance
        let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();

        // Attempt to derive a key with an invalid path
        let result = hd.derive_entropy("abc");

        assert!(
            matches!(result, Err(HDLatticeError::KeyDerivationFailed(msg)) if msg == "Non-integer path"),
            "Expected KeyDerivationFailed Non-integer path"
        );
    }

    #[test]
    fn test_derive_invalid_index() {
        // Create a sample HDLattice instance
        let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();

        // Attempt to derive a key with an invalid index
        let result = hd.derive_entropy("2147483648"); // Index exceeds HARDENED_OFFSET (2^31)

        assert!(
            matches!(result, Err(HDLatticeError::KeyDerivationFailed(msg)) if msg == "Path index >= 0x80000000"),
            "Expected KeyDerivationFailed Path index >= 0x80000000"
        );
    }

    #[test]
    fn test_derive_with_non_integer_path() {
        let mnemonic= "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();

        // Valid derivation path with multiple levels
        let result = hd.derive_entropy("1/a/2");

        assert!(
            matches!(result, Err(HDLatticeError::KeyDerivationFailed(msg)) if msg == "Non-integer path"),
            "Expected KeyDerivationFailed Non-integer path"
        );
    }


    #[test]
    fn test_generate_derived_keys_0() {
        // Rename test since it's no longer about 'm' path
        let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();

        // Test with empty string instead of "m"
        let derived_key_0 = hd.derive_entropy("").unwrap();

        assert_eq!(
            hd.master_key, derived_key_0,
            "Derived key from empty path should match the master seed"
        );
    }

    #[test]
    fn test_wormhole_path_derivation() {
        let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();

        // Test regular path
        let regular_keys = hd.generate_derived_keys("0/1/2");
        
        // Test wormhole path
        let wormhole_keys = hd.generate_derived_keys("w/0/1/2");

        // Keys should be different
        assert_ne!(
            regular_keys.secret.bytes,
            wormhole_keys.secret.bytes,
            "Wormhole and regular keys should be different"
        );

        // Same wormhole path should be deterministic
        let wormhole_keys2 = hd.generate_derived_keys("w/0/1/2");
        assert_eq!(
            wormhole_keys.secret.bytes,
            wormhole_keys2.secret.bytes,
            "Wormhole keys should be deterministic"
        );

        // Different wormhole paths should be different
        let wormhole_keys3 = hd.generate_derived_keys("w/0/1/3");
        assert_ne!(
            wormhole_keys.secret.bytes,
            wormhole_keys3.secret.bytes,
            "Different wormhole paths should produce different keys"
        );
    }

    #[test]
    fn test_wormhole_path_validation() {
        let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();

        // Test invalid wormhole path format
        let result = hd.derive_entropy("w");
        assert!(result.is_err(), "Path 'w' should be invalid");

        // Test valid wormhole path
        let result = hd.derive_entropy("w/0/1/2");
        assert!(result.is_ok(), "Path 'w/0/1/2' should be valid");
    }

    #[test]
    fn test_wormhole_path_seed_separation() {
        let mnemonic = "rocket primary way job input cactus submit menu zoo burger rent impose";
        let hd = HDLattice::from_mnemonic(&mnemonic, None).unwrap();

        // Test that wormhole paths with same indices but different prefixes produce different keys
        let regular_path = hd.generate_derived_keys("0/1/2");
        let wormhole_path = hd.generate_derived_keys("w/0/1/2");

        assert_ne!(
            regular_path.secret.bytes,
            wormhole_path.secret.bytes,
            "Wormhole and regular paths with same indices should produce different keys"
        );
    }
}
