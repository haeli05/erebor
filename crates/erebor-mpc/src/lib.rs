//! # Erebor MPC
//!
//! Multi-Party Computation Threshold Signature Scheme (CGGMP21) implementation
//! with social recovery and anomaly detection for the Erebor wallet.

// Complex implementations (temporarily disabled due to compilation issues)
// pub mod dkg;
// pub mod signing;
// pub mod refresh;
// pub mod recovery;
// pub mod anomaly;
// pub mod types;

pub mod errors;
pub mod simple_types;
pub mod simple_api;

pub use errors::*;
pub use simple_types::*;
pub use simple_api::*;

/// Re-export commonly used types
pub use k256::ecdsa::{SigningKey, VerifyingKey, Signature};
pub use k256::Secp256k1;