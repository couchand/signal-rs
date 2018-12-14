extern crate capnp;
#[macro_use]
extern crate capnp_rpc;
extern crate futures;
extern crate rand;
extern crate tokio;

extern crate double_ratchet;
extern crate signal_common;
extern crate x3dh;

use std::io::{Read, Write};

use capnp_rpc::{RpcSystem, twoparty, rpc_twoparty_capnp};
use futures::Future;
use tokio::io::AsyncRead;

use double_ratchet::session::{Header, SessionBuilder};
use signal_common::keys::{
    ChainKey,
    EphemeralKeyPublic,
    IdentityKeyPublic,
    OneTimePrekeyPublic,
    PrekeyBundle,
    RatchetKeyPair,
    RatchetKeyPublic,
    SignedPrekeyPublic,
    Signature,
};
use x3dh::participant::Participant;

pub mod keyserver_capnp {
    include!(concat!(env!("OUT_DIR"), "/keyserver_capnp.rs"));
}

pub mod util_capnp {
    include!(concat!(env!("OUT_DIR"), "/util_capnp.rs"));
}

pub fn main() {
    use std::net::ToSocketAddrs;
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: {} <alice|bob> ADDRESS[:PORT] [KEYFILE] [SHAREFILE]", args[0]);
        return;
    }

    let actor = args[1].to_owned();
    let server_addr = args[2].to_owned();
    let bob_keyfile = args[3].to_owned();
    let alice_sharefile = args[4].to_owned();

    let info = &b"this is my info"[..];

    let mut runtime = ::tokio::runtime::current_thread::Runtime::new().unwrap();

    let addr = server_addr.to_socket_addrs().unwrap().next().expect("could not parse address");
    let stream = runtime.block_on(tokio::net::TcpStream::connect(&addr)).unwrap();
    stream.set_nodelay(true).unwrap();
    let (reader, writer) = stream.split();
    let network =
        Box::new(twoparty::VatNetwork::new(reader, writer,
                                           rpc_twoparty_capnp::Side::Client,
                                           Default::default()));
    let mut rpc_system = RpcSystem::new(network, None);
    let server: keyserver_capnp::keyserver::Client = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);
    runtime.spawn(rpc_system.map_err(|_e| ()));

    use rand::{ChaChaRng, OsRng, SeedableRng};
    let mut csprng = ChaChaRng::from_rng(OsRng::new().unwrap()).unwrap();

    // Initialize my keys
    println!("{}: Intializing my keys...", actor);
    let mut participant = Participant::new(&mut csprng);

    let ik = participant.ik();
    let spk = participant.spk();
    let spk_sig = participant.spk_sig();

    let opk = participant.create_opk(&mut csprng);

    // Send them to the server
    {
        println!("{}: Registering identity with keyserver", actor);

        let mut request = server.update_identity_request();

        {
            let mut body = request.get();

            body.set_ik(ik.as_bytes());

            let mut s = body.init_spk();
            s.set_key(spk.as_bytes()).unwrap();
            s.set_sig(&spk_sig.to_bytes());
        }

        runtime.block_on(request.send().promise).unwrap();
    }

    {
        println!("{}: Registering one-time prekey with keyserver", actor);

        let mut request = server.add_opks_request();

        {
            let mut body = request.get();

            body.set_ik(ik.as_bytes());

            let mut os = body.init_opks(1);

            let mut o = os.reborrow().get(0);
            o.set_sig(&opk.1.to_bytes());

            let mut o = o.init_key();
            o.set_id(opk.0.index());
            o.set_key(opk.0.as_bytes());
        }

        runtime.block_on(request.send().promise).unwrap();
    }

    // [If Bob] Save public key so it can be used to start Alice
    if actor == "bob" {
        println!("bob: Saving public key to {}", bob_keyfile);
        let mut file = std::fs::File::create(bob_keyfile.clone()).unwrap();
        file.write_all(ik.as_bytes()).unwrap();
    }

    let _session = if actor == "alice" {
        // [If Alice] Request Bob's prekey bundle from the server

        println!("alice: Loading Bob's key from {}", bob_keyfile);

        let bob_key = loop {
            let mut file = match std::fs::File::open(bob_keyfile.clone()) {
                Err(e) => {
                    if let std::io::ErrorKind::NotFound = e.kind() {
                        continue;
                    }
                    eprintln!("error opening file: {:?}", e);
                    panic!();
                },
                Ok(f) => f,
            };
            let mut buf_reader = std::io::BufReader::new(file);
            let mut bob_key_bytes = Vec::with_capacity(32);
            buf_reader.read_to_end(&mut bob_key_bytes).unwrap();

            if bob_key_bytes.len() != 32 { continue; }

            let mut bob_key = [0; 32];
            bob_key.copy_from_slice(&bob_key_bytes[0..32]);
            break IdentityKeyPublic::from_bytes(bob_key.into()).unwrap();
        };

        participant.add_peer(&bob_key);

        println!("alice: Requesting Bob's prekey bundle from keyserver");

        let mut request = server.prekey_bundle_request();

        request.get().set_ik(bob_key.as_bytes());

        let ((sk, opk_id, ek), bob_addr) = runtime.block_on(request.send().promise.and_then(|response| {
            let response = pry!(pry!(response.get()).get_bundle());
            let s = pry!(response.get_spk());
            let o = pry!(response.get_opk());

            let ik = {
                let mut ik = [0; 32];
                ik.copy_from_slice(&pry!(response.get_ik())[0..32]);
                IdentityKeyPublic::from_bytes(ik.into()).unwrap()
            };
            let spk = {
                let mut spk = [0; 32];
                spk.copy_from_slice(&pry!(s.get_key())[0..32]);
                SignedPrekeyPublic::from_bytes(spk.into()).unwrap()
            };
            let spk_sig = {
                let mut spk_sig = [0; 64];
                spk_sig.copy_from_slice(&pry!(s.get_sig())[0..64]);
                Signature::from_bytes(spk_sig.into()).unwrap()
            };

            let opk = match o.which() {
                Ok(util_capnp::maybe::Which::None(())) => None,
                Ok(util_capnp::maybe::Which::Some(o)) => {
                    let o = pry!(o);
                    let id = o.get_id();
                    let key = {
                        let mut opk = [0; 32];
                        opk.copy_from_slice(&pry!(o.get_key())[0..32]);
                        opk.into()
                    };
                    match OneTimePrekeyPublic::from_bytes(id, key) {
                        Ok(opk) => Some(opk),
                        _ => return capnp::capability::Promise::err(
                            capnp::Error::failed("unable to get OPK".to_owned()),
                        ),
                    }
                },
                Err(_) => return capnp::capability::Promise::err(
                    capnp::Error::failed("Bad Request".to_owned()),
                ),
            };

            if opk.is_none() {
                panic!("Empty OPK not yet supported!!!!");
            }

            let bob_addr = RatchetKeyPublic::from(&spk);

            let prekey_bundle = PrekeyBundle { ik, spk, spk_sig, opk };

            println!("alice: Generating session key from bundle");

            capnp::capability::Promise::ok((
                participant.accept_bundle(prekey_bundle, &mut csprng).unwrap(),
                bob_addr,
            ))

        })).unwrap();

        println!("alice: Generated session key: {:?}", sk);

        let mut session = SessionBuilder::new(info, ChainKey::from(sk))
            .connect_to(&bob_addr, &mut csprng);

        let message = b"Hello, Bob!  Nice secret channel we have here!";
        let (header, secret) = session.send(message);

        println!("alice: Saving sharefile to {}", alice_sharefile);
        let mut file = std::fs::File::create(alice_sharefile.clone()).unwrap();
        file.write_all(ik.as_bytes()).unwrap();
        file.write_all(&[
            (opk_id >> 56) as u8,
            (opk_id >> 48) as u8,
            (opk_id >> 40) as u8,
            (opk_id >> 32) as u8,
            (opk_id >> 24) as u8,
            (opk_id >> 16) as u8,
            (opk_id >> 8) as u8,
            opk_id as u8,
        ]).unwrap();
        file.write_all(ek.as_bytes()).unwrap();

        file.write_all(&header.public_key.to_bytes()[..]).unwrap();
        file.write_all(&[
            (header.prev_count >> 24) as u8,
            (header.prev_count >> 16) as u8,
            (header.prev_count >> 8) as u8,
            header.prev_count as u8,
        ]).unwrap();
        file.write_all(&[
            (header.count >> 24) as u8,
            (header.count >> 16) as u8,
            (header.count >> 8) as u8,
            header.count as u8,
        ]).unwrap();

        let content_length = secret.len() as u64;
        file.write_all(&[
            (content_length >> 56) as u8,
            (content_length >> 48) as u8,
            (content_length >> 40) as u8,
            (content_length >> 32) as u8,
            (content_length >> 24) as u8,
            (content_length >> 16) as u8,
            (content_length >> 8) as u8,
            content_length as u8,
        ]).unwrap();

        file.write_all(&secret).unwrap();

        session

    } else /* if actor == "bob" */ {
        // [If Bob] Wait until Alice writes her sharefile.

        const SHAREFILE_HEADER: usize = 120;
        let mut sharefile_size = SHAREFILE_HEADER;

        // The first time through we don't know how much to expect.
        'try_read: loop {

            println!("bob: Waiting for Alice to write {}", alice_sharefile);
            let alice_share_bytes = loop {
                let file = match std::fs::File::open(alice_sharefile.clone()) {
                    Err(e) => {
                        if let std::io::ErrorKind::NotFound = e.kind() {
                            continue;
                        }
                        eprintln!("error opening file: {:?}", e);
                        panic!();
                    },
                    Ok(f) => f,
                };

                println!("bob: Got Alice's sharefile, loading...");
                let mut buf_reader = std::io::BufReader::new(file);
                let mut alice_share_bytes = Vec::with_capacity(sharefile_size);
                buf_reader.read_to_end(&mut alice_share_bytes).unwrap();

                if alice_share_bytes.len() < sharefile_size {
                    println!(
                        "bob: Not enough bytes, only {}, wanted {}",
                        alice_share_bytes.len(),
                        sharefile_size,
                    );
                    continue;
                }

                break alice_share_bytes;
            };

            let alice_key = {
                let mut alice_key = [0; 32];
                alice_key.copy_from_slice(&alice_share_bytes[0..32]);
                IdentityKeyPublic::from_bytes(alice_key).unwrap()
            };
            let opk_id = {
                let b = &alice_share_bytes[32..40];

                (b[0] as u64) << 56 |
                    (b[1] as u64) << 48 |
                    (b[2] as u64) << 40 |
                    (b[3] as u64) << 32 |
                    (b[4] as u64) << 24 |
                    (b[5] as u64) << 16 |
                    (b[6] as u64) << 8 |
                    (b[7] as u64)
            };
            let ek = {
                let mut ek_bytes = [0; 32];
                ek_bytes.copy_from_slice(&alice_share_bytes[40..72]);
                EphemeralKeyPublic::from_bytes(ek_bytes).unwrap()
            };
            let public_key = {
                let mut rk_bytes = [0; 32];
                rk_bytes.copy_from_slice(&alice_share_bytes[72..104]);
                RatchetKeyPublic::from_bytes(rk_bytes).unwrap()
            };
            let prev_count = {
                let b = &alice_share_bytes[104..108];

                    (b[0] as u32) << 24 |
                    (b[1] as u32) << 16 |
                    (b[2] as u32) << 8 |
                    (b[3] as u32)
            };
            let count = {
                let b = &alice_share_bytes[108..112];

                    (b[0] as u32) << 24 |
                    (b[1] as u32) << 16 |
                    (b[2] as u32) << 8 |
                    (b[3] as u32)
            };
            let content_length = {
                let b = &alice_share_bytes[112..120];

                (b[0] as u64) << 56 |
                    (b[1] as u64) << 48 |
                    (b[2] as u64) << 40 |
                    (b[3] as u64) << 32 |
                    (b[4] as u64) << 24 |
                    (b[5] as u64) << 16 |
                    (b[6] as u64) << 8 |
                    (b[7] as u64)
            };

            // a pointer to up top when editing.
            assert_eq!(120, SHAREFILE_HEADER);

            sharefile_size = SHAREFILE_HEADER + content_length as usize;

            if alice_share_bytes.len() != sharefile_size {
                continue 'try_read;
            }

            let secret = &alice_share_bytes[SHAREFILE_HEADER..];

            println!("bob: Generating session key from sharefile");

            let sk = participant.complete_exchange(&alice_key, opk_id, ek).unwrap();

            println!("bob: Generated session key: {:?}", sk);

            let ratchet_key = RatchetKeyPair::from(participant.spk_pair());

            let mut session = SessionBuilder::new(info, ChainKey::from(sk))
                .accept_with(ratchet_key);

            let header = Header { public_key, prev_count, count };

            let message = session.receive(header, &secret, &mut csprng).unwrap();

            println!("bob: Received: {:?}", String::from_utf8(message).unwrap());

            break session;
        }
    };
}
