.PHONY: default
default: target/debug/server target/debug/client
	rm -rf bob_key alice_share
	target/debug/client bob localhost:9999 bob_key alice_share &
	target/debug/client alice localhost:9999 bob_key alice_share
	rm -rf bob_key alice_share

.PHONY: server
server:
	target/debug/server localhost:9999

target/debug/server: crates/server/src/main.rs
	cargo build --bin server

target/debug/client: crates/client/src/main.rs
	cargo build --bin client
