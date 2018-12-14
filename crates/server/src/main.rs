extern crate capnp;
extern crate capnp_rpc;
extern crate futures;
extern crate tokio;

extern crate signal_common;
extern crate x3dh;

use capnp_rpc::{RpcSystem, twoparty, rpc_twoparty_capnp};
use futures::{Future, Stream};
use tokio::io::AsyncRead;
use tokio::runtime::current_thread;

use signal_common::keys::{
    IdentityKeyPublic,
    OneTimePrekeyPublic,
    SignedPrekeyPublic,
    Signature,
};
use x3dh::keyserver;

pub mod keyserver_capnp {
    include!(concat!(env!("OUT_DIR"), "/keyserver_capnp.rs"));
}

pub mod util_capnp {
    include!(concat!(env!("OUT_DIR"), "/util_capnp.rs"));
}

struct Keyserver {
    server: keyserver::Keyserver,
}

impl Keyserver {
    fn new() -> Keyserver {
        Keyserver { server: keyserver::Keyserver::new() }
    }
}

impl keyserver_capnp::keyserver::Server for Keyserver {
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
                match IdentityKeyPublic::from_bytes(arr) {
                    Ok(ik) => ik,
                    _ => return capnp::capability::Promise::err(
                        capnp::Error::failed(format!("Unable to get IK."))
                    ),
                }
            },
            _ => return capnp::capability::Promise::err(
                capnp::Error::failed(format!("Unable to get IK."))
            ),
        };
        match self.server.prekey_bundle(&ik) {
            Some(bundle) => {
                let mut b = result.get().init_bundle();

                b.set_ik(bundle.ik.as_bytes());

                {
                    let mut s = b.reborrow().init_spk();

                    s.set_key(bundle.spk.as_bytes()).unwrap();
                    s.set_sig(&bundle.spk_sig.to_bytes());
                }

                match bundle.opk {
                    None => b.init_opk().set_none(()),
                    Some(opk) => {
                        let mut o = b.init_opk().init_some();

                        o.set_id(opk.index());
                        o.set_key(opk.as_bytes());
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
                match IdentityKeyPublic::from_bytes(arr) {
                    Ok(ik) => ik,
                    _ => return capnp::capability::Promise::err(
                        capnp::Error::failed(format!("Unable to get IK."))
                    ),
                }
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
                    let spk = match SignedPrekeyPublic::from_bytes(karr) {
                        Ok(spk) => spk,
                        _ => return capnp::capability::Promise::err(
                            capnp::Error::failed(format!("Unable to get SPK."))
                        ),
                    };
                    let spk_sig = match Signature::from_bytes(sarr) {
                        Ok(spk_sig) => spk_sig,
                        _ => return capnp::capability::Promise::err(
                            capnp::Error::failed(format!("Unable to get SPK sig."))
                        ),
                    };
                    (spk, spk_sig)
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

        self.server.update_identity(&ik, &spk, &spk_sig).unwrap();

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
                match IdentityKeyPublic::from_bytes(arr) {
                    Ok(ik) => ik,
                    _ => return capnp::capability::Promise::err(
                        capnp::Error::failed(format!("Unable to get IK."))
                    ),
                }
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
            let opk = OneTimePrekeyPublic::from_bytes(id, new_key).unwrap();

            let mut new_sig = [0; 64];
            new_sig.copy_from_slice(sig);
            let opk_sig = match Signature::from_bytes(new_sig) {
                Ok(opk_sig) => opk_sig,
                _ => return capnp::capability::Promise::err(
                    capnp::Error::failed(format!("Unable to get OPK sig."))
                ),
            };
            self.server.add_opk(&ik, &opk, &opk_sig).unwrap();
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
        keyserver_capnp::keyserver::ToClient::new(Keyserver::new()).from_server::<::capnp_rpc::Server>();

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
