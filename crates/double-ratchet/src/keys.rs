use std::hash::{Hash, Hasher};

use curve25519_dalek::montgomery::MontgomeryPoint;
use rand::{CryptoRng, Rng};

#[derive(Debug, PartialEq, Eq)]
pub struct ChainKey(pub(crate) [u8; 32]);

impl std::ops::Deref for ChainKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for ChainKey {
    fn from(slice: &[u8]) -> ChainKey {
        let len = if slice.len() < 32 { slice.len() } else { 32 };

        let mut arr = [0; 32];
        for i in 0..len {
            arr[i] = slice[i];
        } 

        ChainKey(arr)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionKey(pub(crate) [u8; 32]);

impl std::ops::Deref for SessionKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for SessionKey {
    fn from(slice: &[u8]) -> SessionKey {
        let len = if slice.len() < 32 { slice.len() } else { 32 };

        let mut arr = [0; 32];
        for i in 0..len {
            arr[i] = slice[i];
        } 

        SessionKey(arr)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MessageKey(pub(crate) [u8; 32]);

impl std::ops::Deref for MessageKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for MessageKey {
    fn from(slice: &[u8]) -> MessageKey {
        let len = if slice.len() < 32 { slice.len() } else { 32 };

        let mut arr = [0; 32];
        for i in 0..len {
            arr[i] = slice[i];
        } 

        MessageKey(arr)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RatchetKeySecret(pub(crate) [u8; 32]);

impl RatchetKeySecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::ops::Deref for RatchetKeySecret {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for RatchetKeySecret {
    fn from(slice: &[u8]) -> RatchetKeySecret {
        let len = if slice.len() < 32 { slice.len() } else { 32 };

        let mut arr = [0; 32];
        for i in 0..len {
            arr[i] = slice[i];
        } 

        RatchetKeySecret(arr)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetKeyPublic(pub(crate) MontgomeryPoint);

impl std::ops::Deref for RatchetKeyPublic {
    type Target = MontgomeryPoint;

    fn deref(&self) -> &MontgomeryPoint {
        &self.0
    }
}

impl Hash for RatchetKeyPublic {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.0.as_bytes().hash(hasher);
    }
}

impl<'a> From<&'a MontgomeryPoint> for RatchetKeyPublic {
    fn from(point: &MontgomeryPoint) -> RatchetKeyPublic {
        RatchetKeyPublic(point.clone())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RatchetKeyPair {
    pub public: RatchetKeyPublic,
    pub secret: RatchetKeySecret,
}

impl RatchetKeyPair {
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> RatchetKeyPair {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use sha2::{Digest, Sha512};

        let ed_pair = ed25519_dalek::Keypair::generate::<Sha512, _>(csprng);

        let public = RatchetKeyPublic(CompressedEdwardsY::from_slice(
            ed_pair.public.as_bytes()
        ).decompress().unwrap().to_montgomery());

        let secret = {
            let mut hasher = Sha512::new();
            hasher.input(ed_pair.secret.as_bytes());
            let hash = hasher.result();

            let mut secret = [0; 32];
            secret.copy_from_slice(&hash[..32]);

            secret[0] &= 248;
            secret[31] &= 127;
            secret[31] |= 64;

            RatchetKeySecret(secret)
        };

        RatchetKeyPair { public, secret }
    }
}
