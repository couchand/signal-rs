use rand::{CryptoRng, RngCore};

use crate::error::Result;

// TODO: elsewhere?
#[derive(Clone)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Signature> {
        Ok(Signature(ed25519_dalek::Signature::from_bytes(&bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    pub fn as_dalek(&self) -> &ed25519_dalek::Signature {
        &self.0
    }
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(sig: ed25519_dalek::Signature) -> Signature {
        Signature(sig)
    }
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for SessionKey {
    fn from(bytes: [u8; 32]) -> SessionKey { SessionKey(bytes) }
}

pub struct PrekeyBundle {
    pub ik: IdentityKeyPublic,
    pub spk: SignedPrekeyPublic,
    pub spk_sig: Signature,
    pub opk: Option<OneTimePrekeyPublic>,
}

pub trait PublicKey {
    fn key(&self) -> &Ed25519KeyPublic;
}

pub struct IdentityKeyPair(Ed25519KeyPair);
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(Debug))]
pub struct IdentityKeyPublic(Ed25519KeyPublic);

impl IdentityKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> IdentityKeyPair {
        IdentityKeyPair(Ed25519KeyPair::generate(csprng))
    }

    pub fn public(&self) -> IdentityKeyPublic {
        IdentityKeyPublic(self.0.public.clone())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }

    pub fn diffie_hellman<K: PublicKey>(&self, pk: &K) -> Result<SessionKey> {
        self.0.diffie_hellman(pk.key())
    }
}

impl IdentityKeyPublic {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<IdentityKeyPublic> {
        Ok(IdentityKeyPublic(Ed25519KeyPublic::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.0.verify(msg, sig)
    }
}

impl PublicKey for IdentityKeyPublic {
    fn key(&self) -> &Ed25519KeyPublic { &self.0 }
}

pub struct SignedPrekeyPair(Ed25519KeyPair);
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct SignedPrekeyPublic(Ed25519KeyPublic);

impl SignedPrekeyPair {
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> SignedPrekeyPair {
        SignedPrekeyPair(Ed25519KeyPair::generate(csprng))
    }

    pub fn public(&self) -> SignedPrekeyPublic {
        SignedPrekeyPublic(self.0.public.clone())
    }

    pub fn diffie_hellman<K: PublicKey>(&self, pk: &K) -> Result<SessionKey> {
        self.0.diffie_hellman(pk.key())
    }
}

impl SignedPrekeyPublic {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<SignedPrekeyPublic> {
        Ok(SignedPrekeyPublic(Ed25519KeyPublic::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl PublicKey for SignedPrekeyPublic {
    fn key(&self) -> &Ed25519KeyPublic { &self.0 }
}

pub struct OneTimePrekeyPair(u64, Ed25519KeyPair);
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct OneTimePrekeyPublic(u64, Ed25519KeyPublic);

impl OneTimePrekeyPair {
    pub fn generate<R>(csprng: &mut R, index: u64) -> OneTimePrekeyPair
    where R: CryptoRng + RngCore {
        OneTimePrekeyPair(index, Ed25519KeyPair::generate(csprng))
    }

    pub fn public(&self) -> OneTimePrekeyPublic {
        OneTimePrekeyPublic(self.0, self.1.public.clone())
    }

    pub fn diffie_hellman<K: PublicKey>(&self, pk: &K) -> Result<SessionKey> {
        self.1.diffie_hellman(pk.key())
    }
}

impl OneTimePrekeyPublic {
    pub fn from_bytes(
        index: u64,
        bytes: [u8; 32],
    ) -> Result<OneTimePrekeyPublic> {
        Ok(OneTimePrekeyPublic(index, Ed25519KeyPublic::from_bytes(bytes)?))
    }

    pub fn index(&self) -> u64 {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.1.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.1.as_bytes()
    }
}

impl PublicKey for OneTimePrekeyPublic {
    fn key(&self) -> &Ed25519KeyPublic { &self.1 }
}

pub struct EphemeralKeyPair(Ed25519KeyPair);
#[derive(Clone)]
pub struct EphemeralKeyPublic(Ed25519KeyPublic);

impl EphemeralKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> EphemeralKeyPair {
        EphemeralKeyPair(Ed25519KeyPair::generate(csprng))
    }

    pub fn public(&self) -> EphemeralKeyPublic {
        EphemeralKeyPublic(self.0.public.clone())
    }

    pub fn diffie_hellman<K: PublicKey>(&self, pk: &K) -> Result<SessionKey> {
        self.0.diffie_hellman(pk.key())
    }
}

impl EphemeralKeyPublic {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<EphemeralKeyPublic> {
        Ok(EphemeralKeyPublic(Ed25519KeyPublic::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl PublicKey for EphemeralKeyPublic {
    fn key(&self) -> &Ed25519KeyPublic { &self.0 }
}

pub struct Ed25519KeyPair {
    pub public: Ed25519KeyPublic,
    secret: ed25519_dalek::SecretKey,
}
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Ed25519KeyPublic(ed25519_dalek::PublicKey);


impl Ed25519KeyPair {
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> Ed25519KeyPair {
        use ed25519_dalek::Keypair;
        use sha2::Sha512;
        let Keypair { public, secret } = Keypair::generate::<Sha512, _>(csprng);
        Ed25519KeyPair {
            public: Ed25519KeyPublic(public),
            secret,
        }
    }

    // TODO: some way to serialize/deserialize secret key for storage

    pub fn sign(&self, msg: &[u8]) -> Signature {
        use sha2::Sha512;
        self.secret.expand::<Sha512>()
            .sign::<Sha512>(msg, &self.public.0).into()
    }

    pub fn diffie_hellman(&self, peer: &Ed25519KeyPublic) -> Result<SessionKey> {
        use x25519_dalek::diffie_hellman;
        use crate::convert::{convert_public_key, convert_secret_key};
        let secret = convert_secret_key(&self.secret)?;
        let public = convert_public_key(&peer.to_bytes())?;
        Ok(diffie_hellman(secret.as_bytes(), public.as_bytes()).into())
    }
}

impl Ed25519KeyPublic {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Ed25519KeyPublic> {
        Ok(Ed25519KeyPublic(ed25519_dalek::PublicKey::from_bytes(&bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        use sha2::Sha512;
        Ok(self.0.verify::<Sha512>(msg, sig.as_dalek())?)
    }
}

impl std::hash::Hash for Ed25519KeyPublic {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        hasher.write(self.0.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use rand::OsRng;

    use super::*;

    #[test]
    fn test_signature() {
        let mut csprng = OsRng::new().unwrap();
        let keypair = IdentityKeyPair::generate(&mut csprng);
        let public_key = keypair.public();
        let message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let signature = keypair.sign(&message);

        assert!(public_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_diffie_hellman() {
        let mut csprng = OsRng::new().unwrap();
        let alice = IdentityKeyPair::generate(&mut csprng);
        let bob = EphemeralKeyPair::generate(&mut csprng);

        let session_key_alice = alice.diffie_hellman(&bob.public()).unwrap();
        let session_key_bob = bob.diffie_hellman(&alice.public()).unwrap();

        assert_eq!(session_key_alice, session_key_bob);
    }

    #[test]
    fn test_x3dh() {
        let mut csprng = OsRng::new().unwrap();

        let alice = IdentityKeyPair::generate(&mut csprng);

        let bob = IdentityKeyPair::generate(&mut csprng);
        let bob_spk = SignedPrekeyPair::generate(&mut csprng);
        let bob_opk = OneTimePrekeyPair::generate(&mut csprng, 42);

        let ek = EphemeralKeyPair::generate(&mut csprng);

        let dh1_a = alice.diffie_hellman(&bob_spk.public()).unwrap();
        let dh2_a = ek.diffie_hellman(&bob.public()).unwrap();
        let dh3_a = ek.diffie_hellman(&bob_spk.public()).unwrap();
        let dh4_a = ek.diffie_hellman(&bob_opk.public()).unwrap();

        let dh1_b = bob_spk.diffie_hellman(&alice.public()).unwrap();
        let dh2_b = bob.diffie_hellman(&ek.public()).unwrap();
        let dh3_b = bob_spk.diffie_hellman(&ek.public()).unwrap();
        let dh4_b = bob_opk.diffie_hellman(&ek.public()).unwrap();

        assert_eq!(dh1_a, dh1_b);
        assert_eq!(dh2_a, dh2_b);
        assert_eq!(dh3_a, dh3_b);
        assert_eq!(dh4_a, dh4_b);
    }
}
