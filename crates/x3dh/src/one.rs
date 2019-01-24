use ed25519_dalek::Keypair;
use use orion::hazardous::kdf::hkdf;
use rand::OsRng;
use sha2::Sha512;
use x25519_dalek::diffie_hellman;
use x25519_dalek::generate_public;

use signal_common::convert::convert_ed25519_to_x25519;

pub fn example() {
    let mut csprng = OsRng::new().unwrap();

    let info = "foobar!".as_bytes();

    // 2.4 Keys
    let ik_a = convert_ed25519_to_x25519(
        &Keypair::generate::<Sha512, _>(&mut csprng),
    ).unwrap();

    let ik_a_public = generate_public(&ik_a.secret.as_bytes());
    assert_eq!(ik_a_public.as_bytes().len(), ik_a.public.as_bytes().len());
    for i in 0..ik_a_public.as_bytes().len() {
        assert_eq!(ik_a_public.as_bytes()[i], ik_a.public.as_bytes()[i]);
    }

    // 3.2 Publishing keys
    let (
        (iks_b, ik_b, spk_b, spk_b_sig, opk_b),
        b_secrets,
    ) = {
        let iks_b = Keypair::generate::<Sha512, _>(&mut csprng);
        let ik_b = convert_ed25519_to_x25519(&iks_b).unwrap();
        let spk_b = convert_ed25519_to_x25519(
            &Keypair::generate::<Sha512, _>(&mut csprng),
        ).unwrap();
        let opk_b = convert_ed25519_to_x25519(
            &Keypair::generate::<Sha512, _>(&mut csprng),
        ).unwrap();

        let spk_b_sig = iks_b.sign::<Sha512>(spk_b.public.as_bytes());

        (
            (iks_b.public, ik_b.public, spk_b.public, spk_b_sig, opk_b.public),
            (ik_b, spk_b, opk_b),
        )
    };

    // 3.3 Sending the initial message
    iks_b.verify::<Sha512>(spk_b.as_bytes(), &spk_b_sig).unwrap();

    let (sk1, ek_a) = {
        let ek_a = convert_ed25519_to_x25519(
            &Keypair::generate::<Sha512, _>(&mut csprng),
        ).unwrap();

        let dh1 = diffie_hellman(ik_a.secret.as_bytes(), spk_b.as_bytes());
        let dh2 = diffie_hellman(ek_a.secret.as_bytes(), ik_b.as_bytes());
        let dh3 = diffie_hellman(ek_a.secret.as_bytes(), spk_b.as_bytes());
        let dh4 = diffie_hellman(ek_a.secret.as_bytes(), opk_b.as_bytes());

        (kdf(info, &dh1, &dh2, &dh3, &dh4), ek_a.public)
    };

/*
    let ad: Vec<u8> = ik_a.public.as_bytes().iter().chain(
        ik_b.as_bytes().iter()
    ).cloned().collect();
*/

    let message = (ik_a.public, ek_a);

    // 3.4 Receiving the initial message
    let (ik_a, ek_a) = message;
    let (ik_b, spk_b, opk_b) = b_secrets;

    let sk2 = {
        let dh1 = diffie_hellman(spk_b.secret.as_bytes(), ik_a.as_bytes());
        let dh2 = diffie_hellman(ik_b.secret.as_bytes(), ek_a.as_bytes());
        let dh3 = diffie_hellman(spk_b.secret.as_bytes(), ek_a.as_bytes());
        let dh4 = diffie_hellman(opk_b.secret.as_bytes(), ek_a.as_bytes());

        kdf(info, &dh1, &dh2, &dh3, &dh4)
    };

    assert_eq!(sk1.len(), sk2.len());
    for i in 0..sk1.len() {
        assert_eq!(sk1[i], sk2[i]);
    }
}

fn kdf(info: &[u8], dh1: &[u8], dh2: &[u8], dh3: &[u8], dh4: &[u8]) -> [u8; 32] {
    let input: Vec<u8> = std::iter::repeat(0xFF).take(32)
        .chain(dh1.iter().cloned())
        .chain(dh2.iter().cloned())
        .chain(dh3.iter().cloned())
        .chain(dh4.iter().cloned())
        .collect();

    let mut res = [0u8; 32];

    hkdf(&[0; 32], &input, Some(info), &mut res).unwrap();
    res
}
