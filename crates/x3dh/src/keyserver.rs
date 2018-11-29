use std::collections::HashMap;

use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::Sha512;

use crate::convert::convert_public_key;

#[derive(Debug, Clone)]
pub struct CryptoError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let ed25519_pk = ed25519_dalek::PublicKey::from_bytes(self.as_bytes())
            .map_err(|_| CryptoError)?;

        ed25519_pk.verify::<Sha512>(message, &signature.as_dalek()?)
            .map_err(|_| CryptoError)?;

        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_x25519(&self) -> MontgomeryPoint {
        // TODO: not unwrap
        convert_public_key(&self.0).unwrap()
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> PublicKey {
        PublicKey(bytes)
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(key: ed25519_dalek::PublicKey) -> PublicKey {
        PublicKey(key.to_bytes())
    }
}

#[derive(Clone)]
pub struct Signature([u8; 64]);

impl Signature {
    fn as_dalek(&self) -> Result<ed25519_dalek::Signature, CryptoError> {
        ed25519_dalek::Signature::from_bytes(&self.0)
            .map_err(|_| CryptoError)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Signature {
        Signature(bytes)
    }
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(sig: ed25519_dalek::Signature) -> Signature {
        Signature(sig.to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OneTimePrekey {
    pub id: u64,
    pub key: PublicKey,
}

pub struct PrekeyBundle {
    pub ik: PublicKey,
    pub spk: PublicKey,
    pub spk_sig: Signature,
    pub opk: Option<OneTimePrekey>,
}

pub struct KeyEntry {
    spk: PublicKey,
    spk_sig: Signature,
    opks: Vec<OneTimePrekey>,
}

/// A server storing public keys and prekey material of participants.
pub struct Keyserver {
    entries: HashMap<PublicKey, KeyEntry>,
}

impl Keyserver {
    /// Initialize a new key server.
    pub fn new() -> Keyserver {
        Keyserver { entries: HashMap::new() }
    }

    /// Get the prekey bundle for a participant based on their public key.
    pub fn prekey_bundle(&mut self, ik: &PublicKey) -> Option<PrekeyBundle> {
        self.entries.get_mut(ik).map(|entry| {
            let opk = if entry.opks.len() > 0 {
                let mine = entry.opks.pop().unwrap();
                Some(mine)
            } else {
                None
            };
            PrekeyBundle {
                ik: ik.clone(),
                spk: entry.spk.clone(),
                spk_sig: entry.spk_sig.clone(),
                opk,
            }
        })
    }

    /// Add the identity of a new participant to the server, along with
    /// their initial signed prekey.
    pub fn update_identity(
        &mut self,
        ik: &PublicKey,
        spk: &PublicKey,
        spk_sig: &Signature,
    ) -> Result<(), CryptoError> {
        ik.verify(spk.as_bytes(), spk_sig)?;

        self.entries.insert(ik.clone(), KeyEntry {
            spk: spk.clone(),
            spk_sig: spk_sig.clone(),
            opks: vec![],
        });

        Ok(())
    }

/*
    /// Update a participant's signed prekey in the keyserver.
    pub fn update_spk(
        &mut self,
        ik: &PublicKey,
        spk: &PublicKey,
        spk_sig: &Signature,
    ) -> Result<(), CryptoError> {
        ik.verify(spk.as_bytes(), spk_sig)?;

        match self.entries.get_mut(ik) {
            None => Err(CryptoError),
            Some(entry) => {
                entry.spk = spk.clone();
                entry.spk_sig = spk_sig.clone();
                Ok(())
            },
        }
    }
*/

    /// Add a one-time prekey to the server for a participant.
    pub fn add_opk(
        &mut self,
        ik: &PublicKey,
        opk: &OneTimePrekey,
        opk_sig: &Signature,
    ) -> Result<(), CryptoError> {
        ik.verify(opk.key.as_bytes(), opk_sig)?;

        match self.entries.get_mut(ik) {
            None => Err(CryptoError),
            Some(entry) => {
                entry.opks.push(opk.clone());
                Ok(())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Keypair;
    use rand::OsRng;
    use sha2::Sha512;

    use super::*;

    #[test]
    fn test_keyserver() {
        let mut csprng = OsRng::new().unwrap();

        let mut server = Keyserver::new();

        let (ik_b, spk_b, spk_b_sig, opk_b, opk_b_sig) = {
            let ik_b = Keypair::generate::<Sha512, _>(&mut csprng);
            let spk_b = Keypair::generate::<Sha512, _>(&mut csprng);
            let opk_b = Keypair::generate::<Sha512, _>(&mut csprng);

            let spk_b_sig = ik_b.sign::<Sha512>(spk_b.public.as_bytes()).into();
            let opk_b_sig = ik_b.sign::<Sha512>(opk_b.public.as_bytes()).into();

            let ik_b = ik_b.public.into();
            let spk_b = spk_b.public.into();
            let opk_b = OneTimePrekey {
                key: opk_b.public.into(),
                id: 0,
            };

            (ik_b, spk_b, spk_b_sig, opk_b, opk_b_sig)
        };

        server.update_identity(&ik_b, &spk_b, &spk_b_sig).unwrap();
        server.add_opk(&ik_b, &opk_b, &opk_b_sig).unwrap();

        let pkb = server.prekey_bundle(&ik_b).unwrap();
        let opk = pkb.opk.unwrap();

        assert_eq!(pkb.ik, ik_b);
        assert_eq!(pkb.spk, spk_b);
        assert_eq!(opk, opk_b);

        ik_b.verify(pkb.spk.as_bytes(), &spk_b_sig).unwrap();
        ik_b.verify(opk.key.as_bytes(), &opk_b_sig).unwrap();

        assert_eq!(opk.id, 0);
    }

    #[test]
    fn test_rejects_bad_sigs() {
        let mut csprng = OsRng::new().unwrap();

        let mut server = Keyserver::new();

        let (ik_b, spk_b, spk_b_sig, opk_b, opk_b_sig, spk2_b, spk2_b_sig) = {
            let ik_b = Keypair::generate::<Sha512, _>(&mut csprng);
            let spk_b = Keypair::generate::<Sha512, _>(&mut csprng);
            let opk_b = Keypair::generate::<Sha512, _>(&mut csprng);
            let spk2_b = Keypair::generate::<Sha512, _>(&mut csprng);

            let spk_b_sig = ik_b.sign::<Sha512>(spk_b.public.as_bytes()).into();
            let opk_b_sig = ik_b.sign::<Sha512>(opk_b.public.as_bytes()).into();
            let spk2_b_sig = ik_b.sign::<Sha512>(spk_b.public.as_bytes()).into();

            let ik_b = ik_b.public.into();
            let spk_b = spk_b.public.into();
            let spk2_b = spk2_b.public.into();
            let opk_b = OneTimePrekey {
                key: opk_b.public.into(),
                id: 0,
            };

            (ik_b, spk_b, spk_b_sig, opk_b, opk_b_sig, spk2_b, spk2_b_sig)
        };

        let bad_sig = Signature([0; 64]);
        assert!(server.update_identity(&ik_b, &spk_b, &bad_sig).is_err());

        server.update_identity(&ik_b, &spk_b, &spk_b_sig).unwrap();

        assert!(server.add_opk(&ik_b, &opk_b, &bad_sig).is_err());

        server.add_opk(&ik_b, &opk_b, &opk_b_sig).unwrap();

        assert!(server.update_identity(&ik_b, &spk2_b, &bad_sig).is_err());

        server.update_identity(&ik_b, &spk2_b, &spk2_b_sig).is_err();
    }
}
