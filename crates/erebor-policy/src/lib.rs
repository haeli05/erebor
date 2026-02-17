//! Erebor Policy Engine
//!
//! A comprehensive policy evaluation system that provides rule-based transaction control,
//! condition sets, aggregation tracking, and multi-party approval workflows.

mod aggregation;
mod condition;
mod engine;
mod error;
mod quorum;
mod rule;

pub use aggregation::*;
pub use condition::*;
pub use engine::*;
pub use error::*;
pub use quorum::*;
pub use rule::*;

#[cfg(test)]
mod tests;