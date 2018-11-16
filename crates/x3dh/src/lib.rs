//! An implementation of the X3DH key agreement algorithm.
//!
//! See the documentation for [`Keyserver`] and [`Participant`]
//! for more details.
//!
//! [`Keyserver`]: keyserver/struct.Keyserver.html
//! [`Participant`]: participant/struct.Participant.html

extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate orion;
extern crate rand;
extern crate sha2;
extern crate x25519_dalek;

pub mod convert;
pub mod keyserver;
pub mod participant;
pub mod peer;

#[cfg(test)]
pub mod one;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        one::example();
    }
}
