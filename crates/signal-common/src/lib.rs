//! Shared utilities for Signal crates.
//!
//! The modules contained here provide basic types that are shared among
//! other crates in the Signal project.

extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate rand;
extern crate sha2;
extern crate x25519_dalek;

pub mod convert;
pub mod error;
pub mod keys;
