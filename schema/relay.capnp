@0xee7b09e3b9613c73;

using Util = import "util.capnp";
using Signed = Util.Signed;

using PublicKey = Data;
using Signature = Data;

# The header of a double-ratchet message.
struct Header {
    # The next double-ratchet public key to use.
    publicKey @0 :PublicKey;
    # The number of messages in the previous chain.
    prevCount @1 :UInt32;
    # The number of messages in this chain.
    count @2 :UInt32;
}

# A double-ratchet message.
struct Message {
    # The message header.
    header @0 :Header;
    # The encrypted contents.
    body @1 :Data;
}

# An X3DH handshake.
struct Handshake(M) {
    # The id of the one-time prekey used for the exchange.
    opkId @0 :UInt64;
    # The public ephemeral key for the exchange.
    ek @1 :PublicKey;
    # The initial message contents.
    # Should be encrypted with a key derived from the
    # shared session key.
    message @2 :M;
}

# An envelope with relay metadata and containing a message.
struct Envelope(M) {
    # The message's origin.
    origin @0 :PublicKey;
    # The message's destination.
    destination @1 :PublicKey;
    # The contents of the message.
    contents @2 :M;
}

# A relay server.
interface Relay {
    # Send a handshake to another user to initiate a new conversation.
    handshake @0 (handshake :Signed(Envelope(Handshake(Message))));
    # Send a regular message to another user.
    send @1 (message :Signed(Envelope(Message)));
    # Connect to your mailbox on this relay.
    mailbox @2 (ik :PublicKey) -> (mailbox :LockedMailbox);
}

# A mailbox that hasn't yet been unlocked.
interface LockedMailbox {
    # Unlock the mailbox by providing a valid signature
    # for the nonce.
    open @0 (signedNonce :Signature) -> (mailbox :OpenedMailbox);
    # The nonce to use to open the mailbox.
    nonce @1 () -> (nonce :Data);
}

# An opened mailbox.
interface OpenedMailbox {
    # Get new handshake messages.
    handshakes @0 () -> (handshakes :List(Envelope(Handshake(Message))));
    # Get new regular messages.
    messages @1 () -> (messages :List(Envelope(Message)));
}
