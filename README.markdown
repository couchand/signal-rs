signal-rs
=========

A Rust implementation of the [Signal Protocol].  Quite rough around
the edges, and no security guarantees given.  Just for curiosity.

* Overview
* Quick Start
* Components
* Road Map
* More Information

Overview
--------

The Signal Protocol is at the heart of all mainstream end-to-end
encrypted messaging these days: in addition to Signal, both Whats
App and Facebook Messenger use it (along with a lot of other
messaging apps).  It is composed of two main parts: the X3DH key
exchange protocol, and the Double Ratchet algorithm.

Quick Start
-----------

Run `cargo test --all`.  Among others, this runs the test in
`crates/signal/src/lib.rs`, which is a mockup of a complete end-to-end
conversation including both key exchange and several iterations of
the ratchet, however, it is entirely in-process.

Then try `make server`, followed by (in another tab) `make`.  This
runs the multi-process example.  The first command starts the server,
which provides key & message relay.  The second command starts the
two client processes, which communicate with one another via the
server.

Components
----------

The two key crates are `x3dh`, which implements the key exchange
algorithm, and `double-ratchet`, which implements the session key
ratcheting algorithm.

### `x3dh`

The main entity is the `Participant`, which manages generating and
storing the various keys in play.  In addition, you can create a
local `Keyserver` to simulate the key relay functions in-process.

### `double-ratchet`

The main entity is the `Session`, which can be created with a
`SessionBuilder`.  Initialize it with the shared session key,
begin a connection, and then use the `Session` to encrypt and
decrypt messages.

Road Map
--------

- Extract common data types for keys.
- Make `Keyserver` trait asyncable so we can use it with a
  remote server.
- Make a `Relayserver` trait for `double-ratchet` that
  corresponds to the `Keyserver `trait for `x3dh`.
- Clean up `x3dh` and `double-ratchet` public APIs & docs.
- Complete `client` and `server` example implementations.
- Make a little interactive chat client example.

More Information
----------------

* The Signal Protocol [Specifications], specifically:
  * [X3DH], and
  * [Double Ratchet].
* Curve25519 math by Dalek Cryptography
  * [`curve25519-dalek`]
  * [`ed25519-dalek`]
  * [`x25519-dalek`]
* Some primitives from RustCrypto: [`aes`] and [`sha2`].
* HMAC and HKDF implementations from [`orion`].

[Signal Protocol]: https://signal.org/docs/
[Specifications]: https://signal.org/docs/
[X3DH]: https://signal.org/docs/specifications/x3dh/
[Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/
[`curve25519-dalek`]: https://doc.dalek.rs/curve25519_dalek/index.html
[`ed25519-dalek`]: https://doc.dalek.rs/ed25519_dalek/index.html
[`x25519-dalek`]: https://doc.dalek.rs/x25519_dalek/index.html
[`aes`]: https://github.com/RustCrypto/block-ciphers
[`sha2`]: https://github.com/RustCrypto/hashes
[`orion`]: https://github.com/brycx/orion
