extern crate capnp;
extern crate capnp_rpc;
extern crate futures;
extern crate tokio;
extern crate x3dh;

use std::collections::HashMap;

use capnp_rpc::{RpcSystem, twoparty, rpc_twoparty_capnp};
use futures::{Future, Stream};
use tokio::io::AsyncRead;
use tokio::runtime::current_thread;
use x3dh::keyserver;
use x3dh::keyserver::PublicKey;

mod keyserver_capnp {
    include!(concat!(env!("OUT_DIR"), "/keyserver_capnp.rs"));
}
mod relay_capnp {
    include!(concat!(env!("OUT_DIR"), "/relay_capnp.rs"));
}
mod util_capnp {
    include!(concat!(env!("OUT_DIR"), "/util_capnp.rs"));
}

struct Server {
    server: keyserver::Keyserver,
    mailboxes: HashMap<PublicKey, Mailbox>,
}

struct Mailbox {
    handshakes: Vec<bool>,
    messages: Vec<bool>,
}

impl Server {
    fn new() -> Server {
        Server {
            server: keyserver::Keyserver::new(),
            mailboxes: HashMap::new(),
        }
    }
}

impl relay_capnp::relay::Server for Server {
    fn handshake(
        &mut self,
        params: relay_capnp::relay::HandshakeParams,
        result: relay_capnp::relay::HandshakeResults,
    ) -> capnp::capability::Promise<(), capnp::Error> {
        capnp::capability::Promise::err(
            capnp::Error::failed("implement it doofus!".to_owned())
        )
    }

    fn send(
        &mut self,
        params: relay_capnp::relay::SendParams,
        result: relay_capnp::relay::SendResults,
    ) -> capnp::capability::Promise<(), ::capnp::Error> {
        capnp::capability::Promise::err(
            capnp::Error::failed("implement it doofus!".to_owned())
        )
    }
}

impl keyserver_capnp::keyserver::Server for Server {
    fn prekey_bundle(
        &mut self,
        params: keyserver_capnp::keyserver::PrekeyBundleParams,
        mut result: keyserver_capnp::keyserver::PrekeyBundleResults,
    ) -> capnp::capability::Promise<(), capnp::Error> {
        println!("server: Responding to prekeyBundle");

        let params = match params.get() {
            Ok(ps) => ps,
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get params?"))
            ),
        };
        let ik = match params.get_ik() {
            Ok(ik) if ik.len() == 32 => {
                let mut arr = [0; 32];
                arr.copy_from_slice(ik);
                arr.into()
            },
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get IK."))
            ),
        };
        use x3dh::keyserver::Keyserver;
        match self.server.prekey_bundle(&ik) {
            Some(bundle) => {
                let mut b = result.get().init_bundle();

                b.set_ik(bundle.ik.as_bytes());

                {
                    let mut s = b.reborrow().init_spk();

                    s.set_key(bundle.spk.as_bytes());
                    s.set_sig(bundle.spk_sig.as_bytes());
                }

                match bundle.opk {
                    None => b.init_opk().set_none(()),
                    Some(opk) => {
                        let mut o = b.init_opk().init_some();

                        o.set_id(opk.id);
                        o.set_key(opk.key.as_bytes());
                    },
                }

                capnp::capability::Promise::ok(())
            },
            None => capnp::capability::Promise::err(
                capnp::Error::failed(format!("Identity unknown."))
            ),
        }
    }

    fn update_identity(
        &mut self,
        params: keyserver_capnp::keyserver::UpdateIdentityParams,
        _: keyserver_capnp::keyserver::UpdateIdentityResults,
    ) -> capnp::capability::Promise<(), capnp::Error> {
        println!("server: Responding to updateIdentity");

        let params = match params.get() {
            Ok(ps) => ps,
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get params?"))
            ),
        };
        let ik = match params.get_ik() {
            Ok(k) if k.len() == 32 => {
                let mut arr = [0; 32];
                arr.copy_from_slice(k);
                arr.into()
            },
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get IK."))
            ),
        };
        let (spk, spk_sig) = match params.get_spk() {
            Ok(k) => {
                let key = match k.get_key() {
                    Ok(k) => k,
                    _ => return capnp::capability::Promise::err(
                        capnp::Error::failed(format!("Unable to get SPK."))
                    ),
                };
                let sig = match k.get_sig() {
                    Ok(k) => k,
                    _ => return capnp::capability::Promise::err(
                        capnp::Error::failed(format!("Unable to get SPK sig."))
                    ),
                };
                if key.len() == 32 && sig.len() == 64 {
                    let mut karr = [0; 32];
                    karr.copy_from_slice(key);
                    let mut sarr = [0; 64];
                    sarr.copy_from_slice(sig);
                    (karr.into(), sarr.into())
                } else {
                    return capnp::capability::Promise::err(
                        capnp::Error::failed(format!("Unable to get SPK."))
                    );
                }
            },
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get SPK."))
            ),
        };

        use x3dh::keyserver::Keyserver;
        self.server.update_identity(&ik, &spk, &spk_sig);

        capnp::capability::Promise::ok(())
    }

    fn add_opks(
        &mut self,
        params: keyserver_capnp::keyserver::AddOpksParams,
        _: keyserver_capnp::keyserver::AddOpksResults,
    ) -> capnp::capability::Promise<(), capnp::Error> {
        println!("server: Responding to addOpks");

        let params = match params.get() {
            Ok(ps) => ps,
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get params?"))
            ),
        };
        let ik = match params.get_ik() {
            Ok(ik) if ik.len() == 32 => {
                let mut arr = [0; 32];
                arr.copy_from_slice(ik);
                arr.into()
            },
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get IK."))
            ),
        };
        let opks = match params.get_opks() {
            Ok(os) => os,
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get OPKS."))
            ),
        };
        for i in 0..opks.len() {
            let signed_opk = opks.get(i);

            let opk = match signed_opk.get_key() {
                Ok(k) => k,
                _ => return capnp::capability::Promise::err(
                    capnp::Error::failed(format!("Unable to get OPK."))
                ),
            };
            let sig = match signed_opk.get_sig() {
                Ok(k) => k,
                _ => return capnp::capability::Promise::err(
                    capnp::Error::failed(format!("Unable to get OPK sig."))
                ),
            };

            let id = opk.get_id();
            let key = match opk.get_key() {
                Ok(k) => k,
                _ => return capnp::capability::Promise::err(
                    capnp::Error::failed(format!("Unable to get OPK key."))
                ),
            };

            let mut new_key = [0; 32];
            new_key.copy_from_slice(key);
            let opk = keyserver::OneTimePrekey { id, key: new_key.into() };

            let mut new_sig = [0; 64];
            new_sig.copy_from_slice(sig);
            use x3dh::keyserver::Keyserver;
            self.server.add_opk(&ik, &opk, &new_sig.into());
        }
        capnp::capability::Promise::ok(())
    }
}

pub fn main() {
    use std::net::ToSocketAddrs;
    let args: Vec<String> = ::std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} ADDRESS[:PORT]", args[0]);
        return;
    }

    let addr = args[1].to_socket_addrs().unwrap().next().expect("could not parse address");
    let socket = ::tokio::net::TcpListener::bind(&addr).unwrap();

    let server =
        keyserver_capnp::keyserver::ToClient::new(Server::new()).from_server::<::capnp_rpc::Server>();

    let done = socket.incoming().for_each(move |socket| {
        println!("server: Accepting incoming connection.");

        socket.set_nodelay(true)?;
        let (reader, writer) = socket.split();

        let network =
            twoparty::VatNetwork::new(reader, writer,
                                      rpc_twoparty_capnp::Side::Server, Default::default());

        let rpc_system = RpcSystem::new(Box::new(network), Some(server.clone().client));
        current_thread::spawn(rpc_system.map_err(|e| eprintln!("server error: {:?}", e)));
        Ok(())
    });

    println!("server: Listening on {}...", args[1]);

    current_thread::block_on_all(done).unwrap();
}
