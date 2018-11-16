use std::collections::HashMap;

use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::Keypair;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;

use crate::convert::{convert_secret_key, SecretKey, SessionKey};
use crate::keyserver::{CryptoError, Keyserver, OneTimePrekey, PublicKey};
use crate::peer::Peer;

/// The state for a participant in an X3DH system.
pub struct Participant {
    ik: Keypair,
    spk: Keypair,
    next_opk: u64,
    opks: HashMap<u64, SecretKey>,
    peers: HashMap<PublicKey, Peer>,
}

impl Participant {
    /// Initialize a new participant, using the given randomness
    /// to generate keys.
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Participant {
        let ik = Keypair::generate::<Sha512, _>(csprng);
        let spk = Keypair::generate::<Sha512, _>(csprng);
        let next_opk = 1;
        let opks = HashMap::new();
        let peers = HashMap::new();

        Participant { ik, spk, next_opk, opks, peers }
    }

    /// The participant's public identity key.
    pub fn ik(&self) -> PublicKey {
        self.ik.public.into()
    }

    /// Create a new one-time prekey for this participant.
    pub fn create_opk<R: CryptoRng + RngCore>(&mut self, csprng: &mut R) -> OneTimePrekey {
        let key = Keypair::generate::<Sha512, _>(csprng);
        let id = self.next_opk;
        self.next_opk = id + 1;

        self.opks.insert(id, convert_secret_key(&key.secret).unwrap());

        OneTimePrekey {
            id,
            key: key.public.into(),
        }
    }

    /// Register this participant with the given key server.
    pub fn register(&self, keyserver: &mut Keyserver) -> Result<(), CryptoError> {
        let ik = self.ik.public.into();
        let spk = self.spk.public.into();
        let spk_sig = self.ik.sign::<Sha512>(self.spk.public.as_bytes()).into();

        keyserver.add_identity(&ik, &spk, &spk_sig)
    }

    /// Add a new one-time prekey to the given key server.
    pub fn add_opk<R: CryptoRng + RngCore>(&mut self, keyserver: &mut Keyserver, csprng: &mut R) -> Result<(), CryptoError> {
        let ik = self.ik.public.into();
        let opk = self.create_opk(csprng);
        let opk_sig = self.ik.sign::<Sha512>(opk.key.as_bytes()).into();

        keyserver.add_opk(&ik, &opk, &opk_sig)
    }

    /// Add a peer, in preparation for future communication.
    pub fn add_peer(&mut self, peer: &PublicKey) {
        self.peers.insert(peer.clone(), Peer::HaveIdentity(peer.clone()));
    }

    /// Begin a key agreement exchange with the peer.
    pub fn begin_exchange<R: CryptoRng + RngCore>(&mut self, peer: &PublicKey, keyserver: &mut Keyserver, csprng: &mut R) -> Result<(SessionKey, u64, MontgomeryPoint), CryptoError> {
        let bundle = match keyserver.get_prekey_bundle(peer) {
            Some(b) => b,
            None => return Err(CryptoError),
        };

        let peer_state = match self.peers.remove(peer) {
            Some(s) => s,
            None => return Err(CryptoError),
        };

        let peer_state = peer_state.accept_prekey_bundle(bundle)?;

        let ik_secret = convert_secret_key(&self.ik.secret)
            .map_err(|_| CryptoError)?;

        let (peer_state, sk, opk_id, ek) = peer_state.derive_key(csprng, &ik_secret)?;

        self.peers.insert(peer.clone(), peer_state);

        Ok((sk, opk_id, ek))
    }

    /// Complete a key agreement exchange previously started by a peer.
    pub fn complete_exchange(&mut self, peer: &PublicKey, opk_id: u64, ek: MontgomeryPoint) -> Result<SessionKey, CryptoError> {
        let ik_secret = convert_secret_key(&self.ik.secret)
            .map_err(|_| CryptoError)?;
        let spk_secret = convert_secret_key(&self.spk.secret)
            .map_err(|_| CryptoError)?;

        let opk_secret = match self.opks.remove(&opk_id) {
            None => return Err(CryptoError),
            Some(opk) => opk,
        };

        // TODO: this????
        self.add_peer(peer);

        let peer_state = match self.peers.remove(peer) {
            Some(s) => s,
            None => return Err(CryptoError),
        };

        let (peer_state, sk) = peer_state.match_key(&ik_secret, &spk_secret, &opk_secret, &ek)?;

        self.peers.insert(peer.clone(), peer_state);

        Ok(sk)
    }
}

#[cfg(test)]
mod tests {
    use rand::OsRng;

    use crate::keyserver::Keyserver;

    use super::*;

    #[test]
    fn test_exchange() {
        let mut csprng = OsRng::new().unwrap();

        let mut server = Keyserver::new();

        let mut alice = Participant::new(&mut csprng);
        alice.register(&mut server).unwrap();

        let mut bob = Participant::new(&mut csprng);
        bob.register(&mut server).unwrap();
        bob.add_opk(&mut server, &mut csprng).unwrap();

        alice.add_peer(&bob.ik());

        let (sk1, opk_id, ek) = alice.begin_exchange(&bob.ik(), &mut server, &mut csprng)
            .unwrap();

        let sk2 = bob.complete_exchange(&alice.ik(), opk_id, ek).unwrap();

        assert_eq!(sk1, sk2);
    }
}
