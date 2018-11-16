use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::Keypair;
use orion::default::hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use x25519_dalek::diffie_hellman;

use crate::convert::*;
use crate::keyserver::*;

pub enum Peer {
    Unknown,
    HaveIdentity(PublicKey),
    HavePrekeyBundle(PrekeyBundle),
    Connected,
}

impl Peer {
    pub fn is_connected(&self) -> bool {
        match self {
            Peer::Connected => true,
            _ => false,
        }
    }

    pub fn ready_to_send(&self) -> bool {
        match self {
            Peer::HavePrekeyBundle(_) => true,
            _ => false,
        }
    }

    pub fn accept_prekey_bundle(self, bundle: PrekeyBundle) -> Result<Peer, CryptoError> {
        bundle.ik.verify(bundle.spk.as_bytes(), &bundle.spk_sig)?;

        Ok(Peer::HavePrekeyBundle(bundle))
    }

    pub fn derive_key<R: CryptoRng + RngCore>(self, csprng: &mut R, me: &SecretKey) -> Result<(Peer, SessionKey, u64, MontgomeryPoint), CryptoError> {
        match self {
            Peer::HavePrekeyBundle(bundle) => {
                let ek = generate_x25519_key(csprng)?;
                let ik = bundle.ik.to_x25519();
                let spk = bundle.spk.to_x25519();

                // TODO: not unwrap
                let opk = bundle.opk.unwrap();
                let (opk, opk_id) = (opk.key.to_x25519(), opk.id);

                let dh1 = diffie_hellman(me.as_bytes(), spk.as_bytes());
                let dh2 = diffie_hellman(ek.secret.as_bytes(), ik.as_bytes());
                let dh3 = diffie_hellman(ek.secret.as_bytes(), spk.as_bytes());
                let dh4 = diffie_hellman(ek.secret.as_bytes(), opk.as_bytes());

                let sk = kdf(&dh1, &dh2, &dh3, &dh4);

                Ok((Peer::Connected, sk, opk_id, ek.public))
            },
            _ => Err(CryptoError),
        }
    }

    pub fn match_key(
        self,
        ik_secret: &SecretKey,
        spk_secret: &SecretKey,
        opk_secret: &SecretKey,
        ek: &MontgomeryPoint,
    ) -> Result<(Peer, SessionKey), CryptoError> {
        let ik = match self {
            Peer::HavePrekeyBundle(bundle) => {
                bundle.ik.to_x25519()
            },
            Peer::HaveIdentity(pk) => {
                pk.to_x25519()
            },
            _ => return Err(CryptoError),
        };

        let dh1 = diffie_hellman(spk_secret.as_bytes(), ik.as_bytes());
        let dh2 = diffie_hellman(ik_secret.as_bytes(), ek.as_bytes());
        let dh3 = diffie_hellman(spk_secret.as_bytes(), ek.as_bytes());
        let dh4 = diffie_hellman(opk_secret.as_bytes(), ek.as_bytes());

        let sk = kdf(&dh1, &dh2, &dh3, &dh4);

        Ok((Peer::Connected, sk))
    }
}

fn generate_x25519_key<R: CryptoRng + RngCore>(csprng: &mut R) -> Result<X25519Keypair, CryptoError> {
    convert_ed25519_to_x25519(
        &Keypair::generate::<Sha512, _>(csprng),
    ).map_err(|_| CryptoError)
}

fn kdf(dh1: &[u8], dh2: &[u8], dh3: &[u8], dh4: &[u8]) -> SessionKey {
    let input: Vec<u8> = std::iter::repeat(0xFF).take(32)
        .chain(dh1.iter().cloned())
        .chain(dh2.iter().cloned())
        .chain(dh3.iter().cloned())
        .chain(dh4.iter().cloned())
        .collect();

    SessionKey::new(hkdf(&[0; 32], &input, b"this is my info string").unwrap())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Keypair;
    use rand::OsRng;
    use sha2::Sha512;

    use crate::keyserver::PrekeyBundle;

    use super::*;

    #[test]
    fn test_key_exchange() {
        let mut csprng = OsRng::new().unwrap();

        let (bundle, secrets) = {
            let ik_b = Keypair::generate::<Sha512, _>(&mut csprng);
            let spk_b = Keypair::generate::<Sha512, _>(&mut csprng);
            let opk_b = Keypair::generate::<Sha512, _>(&mut csprng);

            let spk_b_sig = ik_b.sign::<Sha512>(spk_b.public.as_bytes());

            (
                PrekeyBundle {
                    ik: ik_b.public.into(),
                    spk: spk_b.public.into(),
                    spk_sig: spk_b_sig.into(),
                    opk: Some(OneTimePrekey {
                        id: 0,
                        key: opk_b.public.into(),
                    }),
                },
                (ik_b.secret, spk_b.secret, opk_b.secret),
            )
        };

        let ik_a = Keypair::generate::<Sha512, _>(&mut csprng);
        let ik_a_secret = convert_secret_key(&ik_a.secret).unwrap();

        let peer_b = Peer::HavePrekeyBundle(bundle);

        let (new_peer, sk1, _id, ek) = peer_b.derive_key(&mut csprng, &ik_a_secret).unwrap();

        assert!(new_peer.is_connected());

        let peer_a = Peer::HaveIdentity(ik_a.public.into());

        let (ik_b, spk_b, opk_b) = secrets;
        let ik_b = convert_secret_key(&ik_b).unwrap();
        let spk_b = convert_secret_key(&spk_b).unwrap();
        let opk_b = convert_secret_key(&opk_b).unwrap();

        let (new_peer, sk2) = peer_a.match_key(&ik_b, &spk_b, &opk_b, &ek).unwrap();

        assert!(new_peer.is_connected());

        assert_eq!(sk1, sk2);
    }
}
