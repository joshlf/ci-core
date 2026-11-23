//! Pure domain, static Cargo closure, TCB policy, and offline Sigstore
//! verification crate for `ci-core`.
//!
//! `ci-core-model` compiles under `#![forbid(unsafe_code)]` with zero HTTP,
//! async runtime, subprocess, or host filesystem crates.

pub mod attest;
pub mod cargo_static;
pub mod config;
pub mod digest;
pub mod engine;
pub mod store;
pub mod tcb;
pub mod tree;
pub mod types;
