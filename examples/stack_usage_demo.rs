//! Stack Usage Demonstration for ML-DSA (44, 65, 87)
//!
//! This example demonstrates that the current ML-DSA implementations
//! work with very small stack sizes, making them suitable for embedded
//! systems, blockchain VMs, and other constrained environments.

use rusty_crystals_dilithium::ml_dsa_44;
use rusty_crystals_dilithium::ml_dsa_65;
use rusty_crystals_dilithium::ml_dsa_87;
use std::{
	panic,
	sync::mpsc,
	thread,
	time::Duration,
};

/// Test ML-DSA key generation with a specific stack size
fn test_keygen_with_stack_size<T>(stack_kb: usize, variant_name: &str, keygen_fn: T) -> bool
where
	T: FnOnce() -> bool + Send + 'static,
{
	let stack_bytes = stack_kb * 1024;
	let (tx, rx) = mpsc::channel();

	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let tx_clone = tx.clone();
		let handle = thread::Builder::new()
			.name(format!("{}-keygen-{}kb", variant_name, stack_kb))
			.stack_size(stack_bytes)
			.spawn(move || {
				let result = panic::catch_unwind(panic::AssertUnwindSafe(keygen_fn));
				let _ = tx_clone.send(result.is_ok() && result.unwrap_or(false));
			});

		match handle {
			Ok(thread_handle) => {
				// Wait for result with timeout
				match rx.recv_timeout(Duration::from_secs(10)) {
					Ok(success) => {
						let _ = thread_handle.join();
						success
					},
					Err(_) => {
						// Timeout or channel error - likely stack overflow
						false
					},
				}
			},
			Err(_) => false, // Failed to spawn thread
		}
	}));

	result.unwrap_or(false)
}

/// Test ML-DSA signing with a specific stack size
fn test_sign_with_stack_size<T>(stack_kb: usize, variant_name: &str, sign_fn: T) -> bool
where
	T: FnOnce() -> bool + Send + 'static,
{
	let stack_bytes = stack_kb * 1024;
	let (tx, rx) = mpsc::channel();

	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let tx_clone = tx.clone();
		let handle = thread::Builder::new()
			.name(format!("{}-sign-{}kb", variant_name, stack_kb))
			.stack_size(stack_bytes)
			.spawn(move || {
				let result = panic::catch_unwind(panic::AssertUnwindSafe(sign_fn));
				let _ = tx_clone.send(result.is_ok() && result.unwrap_or(false));
			});

		match handle {
			Ok(thread_handle) => {
				// Wait for result with timeout
				match rx.recv_timeout(Duration::from_secs(10)) {
					Ok(success) => {
						let _ = thread_handle.join();
						success
					},
					Err(_) => {
						// Timeout or channel error - likely stack overflow
						false
					},
				}
			},
			Err(_) => false, // Failed to spawn thread
		}
	}));

	result.unwrap_or(false)
}

/// Test ML-DSA verification with a specific stack size
fn test_verify_with_stack_size<T>(stack_kb: usize, variant_name: &str, verify_fn: T) -> bool
where
	T: FnOnce() -> bool + Send + 'static,
{
	let stack_bytes = stack_kb * 1024;
	let (tx, rx) = mpsc::channel();

	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let tx_clone = tx.clone();
		let handle = thread::Builder::new()
			.name(format!("{}-verify-{}kb", variant_name, stack_kb))
			.stack_size(stack_bytes)
			.spawn(move || {
				let result = panic::catch_unwind(panic::AssertUnwindSafe(verify_fn));
				let _ = tx_clone.send(result.is_ok() && result.unwrap_or(false));
			});

		match handle {
			Ok(thread_handle) => {
				// Wait for result with timeout
				match rx.recv_timeout(Duration::from_secs(10)) {
					Ok(success) => {
						let _ = thread_handle.join();
						success
					},
					Err(_) => {
						// Timeout or channel error - likely stack overflow
						false
					},
				}
			},
			Err(_) => false, // Failed to spawn thread
		}
	}));

	result.unwrap_or(false)
}

fn main() {
    println!("=== ML-DSA Stack Usage Analysis ===\n");

    // Pre-generate test data for all variants
    let ml44_keypair = ml_dsa_44::Keypair::generate(None);
    let ml65_keypair = ml_dsa_65::Keypair::generate(None);
    let ml87_keypair = ml_dsa_87::Keypair::generate(None);

    let test_msg = b"stack usage test message";

    let ml44_sig = ml44_keypair.sign(test_msg, None, false).unwrap();
    let ml65_sig = ml65_keypair.sign(test_msg, None, false);
    let ml87_sig = ml87_keypair.sign(test_msg, None, false);

    // Test with progressively smaller stack sizes
    let stack_sizes = [
        2048, // 2MB - should definitely work
        1024, // 1MB - large
        512,  // 512KB - medium
        384,  // 384KB
        320,  // 320KB
        288,  // 288KB
        256,  // 256KB - small
        224,  // 224KB
        192,  // 192KB
        160,  // 160KB
        128,  // 128KB - typical small embedded system
        96,   // 96KB
        64,   // 64KB - large microcontroller
        32,   // 32KB - medium microcontroller
        16,   // 16KB - small microcontroller
        8,    // 8KB - very constrained
        4,    // 4KB - extremely constrained
        2,    // 2KB - minimal
        1,    // 1KB - tiny
    ];

    println!("Stack Size | ML-DSA-44 KeyGen | ML-DSA-44 Sign | ML-DSA-44 Verify | ML-DSA-65 KeyGen | ML-DSA-65 Sign | ML-DSA-65 Verify | ML-DSA-87 KeyGen | ML-DSA-87 Sign | ML-DSA-87 Verify");
    println!("-----------|-------------------|-----------------|-------------------|-------------------|-----------------|-------------------|-------------------|-----------------|-------------------");

    let mut min_sizes = [None; 9]; // [ml44_keygen, ml44_sign, ml44_verify, ml65_keygen, ml65_sign, ml65_verify, ml87_keygen, ml87_sign, ml87_verify]

    for &size_kb in &stack_sizes {
        // Test ML-DSA-44

        let ml44_keygen = test_keygen_with_stack_size(size_kb, "ml-dsa-44", move || {
            let _kp = ml_dsa_44::Keypair::generate(Some(&[1u8; 32]));
            true
        });

        let ml44_keypair_clone = ml44_keypair.clone();
        let ml44_sign = test_sign_with_stack_size(size_kb, "ml-dsa-44", move || {
            let _sig = ml44_keypair_clone.sign(test_msg, None, false);
            true
        });

        let ml44_keypair_clone2 = ml44_keypair.clone();
        let ml44_sig_clone = ml44_sig.clone();
        let ml44_verify = test_verify_with_stack_size(size_kb, "ml-dsa-44", move || {
            ml44_keypair_clone2.verify(test_msg, &ml44_sig_clone, None)
        });

        // Test ML-DSA-65
        let ml65_keygen = test_keygen_with_stack_size(size_kb, "ml-dsa-65", move || {
            let _kp = ml_dsa_65::Keypair::generate(Some(&[1u8; 32]));
            true
        });

        let ml65_keypair_clone = ml65_keypair.clone();
        let ml65_sign = test_sign_with_stack_size(size_kb, "ml-dsa-65", move || {
            let _sig = ml65_keypair_clone.sign(test_msg, None, false);
            true
        });

        let ml65_keypair_clone2 = ml65_keypair.clone();
        let ml65_sig_clone = ml65_sig.clone();
        let ml65_verify = test_verify_with_stack_size(size_kb, "ml-dsa-65", move || {
            ml65_keypair_clone2.verify(test_msg, &ml65_sig_clone, None)
        });

        // Test ML-DSA-87
        let ml87_keygen = test_keygen_with_stack_size(size_kb, "ml-dsa-87", move || {
            let _kp = ml_dsa_87::Keypair::generate(Some(&[1u8; 32]));
            true
        });

        let ml87_keypair_clone = ml87_keypair.clone();
        let ml87_sign = test_sign_with_stack_size(size_kb, "ml-dsa-87", move || {
            let _sig = ml87_keypair_clone.sign(test_msg, None, false);
            true
        });

        let ml87_keypair_clone2 = ml87_keypair.clone();
        let ml87_sig_clone = ml87_sig.clone();
        let ml87_verify = test_verify_with_stack_size(size_kb, "ml-dsa-87", move || {
            ml87_keypair_clone2.verify(test_msg, &ml87_sig_clone, None)
        });

        println!("{:>8} KB | {:>17} | {:>15} | {:>17} | {:>17} | {:>15} | {:>17} | {:>17} | {:>15} | {:>17}",
                size_kb,
                if ml44_keygen { "✅ Works" } else { "❌ Fails" },
                if ml44_sign { "✅ Works" } else { "❌ Fails" },
                if ml44_verify { "✅ Works" } else { "❌ Fails" },
                if ml65_keygen { "✅ Works" } else { "❌ Fails" },
                if ml65_sign { "✅ Works" } else { "❌ Fails" },
                if ml65_verify { "✅ Works" } else { "❌ Fails" },
                if ml87_keygen { "✅ Works" } else { "❌ Fails" },
                if ml87_sign { "✅ Works" } else { "❌ Fails" },
                if ml87_verify { "✅ Works" } else { "❌ Fails" });

        // Track minimum working stack sizes
        let results = [ml44_keygen, ml44_sign, ml44_verify, ml65_keygen, ml65_sign, ml65_verify, ml87_keygen, ml87_sign, ml87_verify];
        for (i, &works) in results.iter().enumerate() {
            if works {
                min_sizes[i] = Some(size_kb);
            }
        }
    }

    println!("\n=== Results ===");

    let operation_names = [
        "ML-DSA-44 Key Generation", "ML-DSA-44 Signing", "ML-DSA-44 Verification",
        "ML-DSA-65 Key Generation", "ML-DSA-65 Signing", "ML-DSA-65 Verification",
        "ML-DSA-87 Key Generation", "ML-DSA-87 Signing", "ML-DSA-87 Verification",
    ];

    println!("Minimum stack requirements:");
    for (i, &min_size) in min_sizes.iter().enumerate() {
        println!("• {}: {}KB",
                    operation_names[i],
                    min_size.map_or("Unknown".to_string(), |kb| format!("≤{}", kb)));
        }

        let min_overall = min_sizes
            .iter()
            .filter_map(|&x| x)
            .max()
            .unwrap_or(128);

        println!("\nOverall minimum stack requirement: ≤{}KB", min_overall);

        if min_overall <= 8 {
            println!("🎯 All ML-DSA variants work with ≤8KB stack - excellent for constrained environments!");
        } else if min_overall <= 32 {
            println!("✅ All ML-DSA variants work with ≤{}KB stack - suitable for embedded systems", min_overall);
        } else {
            println!("⚠️  ML-DSA variants require ≤{}KB stack", min_overall);
        }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_4kb_stack() {
        // Test that all variants work with 4KB stack
        assert!(test_keygen_with_stack_size(4, "ml-dsa-44", || {
            let _kp = ml_dsa_44::Keypair::generate(Some(&[1u8; 32]));
            true
        }), "ML-DSA-44 key generation should work with 4KB stack");

        assert!(test_keygen_with_stack_size(4, "ml-dsa-65", || {
            let _kp = ml_dsa_65::Keypair::generate(Some(&[1u8; 32]));
            true
        }), "ML-DSA-65 key generation should work with 4KB stack");

        assert!(test_keygen_with_stack_size(4, "ml-dsa-87", || {
            let _kp = ml_dsa_87::Keypair::generate(Some(&[1u8; 32]));
            true
        }), "ML-DSA-87 key generation should work with 4KB stack");
    }
}
