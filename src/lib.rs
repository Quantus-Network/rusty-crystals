#![cfg_attr(test, feature(test))]
#![cfg_attr(feature = "no_std", no_std)]

#[cfg(all(feature = "dilithium", feature = "hdwallet"))]
pub use rusty_crystals_dilithium::*;

#[cfg(all(feature = "dilithium", feature = "hdwallet"))]
pub use rusty_crystals_hdwallet::*;
