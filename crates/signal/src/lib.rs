extern crate curve25519_dalek;
extern crate double_ratchet;
extern crate rand;
extern crate x3dh;

#[cfg(test)]
mod tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use double_ratchet::keys::{ChainKey, Keypair, PublicKey, SecretKey};
    use double_ratchet::session::SessionBuilder;
    use rand::OsRng;
    use x3dh::keyserver::Keyserver;
    use x3dh::participant::Participant;

    #[test]
    fn test_everything() {
        let mut csprng = OsRng::new().unwrap();

        // First, the key agreement with X3DH.

        let mut server = Keyserver::new();

        let mut alice = Participant::new(&mut csprng);
        alice.register(&mut server).unwrap();

        let mut bob = Participant::new(&mut csprng);
        bob.register(&mut server).unwrap();
        bob.add_opk(&mut server, &mut csprng).unwrap();

        alice.add_peer(&bob.ik());

        let (sk, opk_id, ek) = alice.begin_exchange(
            &bob.ik(), &mut server, &mut csprng,
        ).unwrap();

        // And now, the connection with Double Ratchet.

        let info = &b"foobar!"[..];

        let bob_public = PublicKey::from(
            &CompressedEdwardsY::from_slice(bob.spk().as_bytes())
                .decompress().unwrap().to_montgomery()
        );

        let mut alice2 = SessionBuilder::new(
            info, ChainKey::from(&sk.as_bytes()[..]),
        )
            .connect_to(&bob_public, &mut csprng);

        let message1 = b"Hello, Bob! Nice secret channel!";
        let (h1, secret1) = alice2.send(message1);

        let sk = bob.complete_exchange(&alice.ik(), opk_id, ek).unwrap();

        let bob_keys = Keypair {
            public: bob_public,
            secret: SecretKey::from(&bob.spk_secret().as_bytes()[..]),
        };

        let mut bob2 = SessionBuilder::new(
            info, ChainKey::from(&sk.as_bytes()[..])
        )
            .accept_with(bob_keys);

        let decrypt1 = bob2.receive(h1, &secret1, &mut csprng).unwrap();

        assert_eq!(decrypt1, message1);
    }
}
