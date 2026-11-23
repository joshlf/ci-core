//! Effectful CLI and runtime adapters for `ci-core` (`#![forbid(unsafe_code)]`).

pub mod ghcr;
pub mod git_bare;
pub mod github_api;
pub mod sandbox;
pub mod signer;
