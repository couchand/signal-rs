@0xb18650cec7d93286;

using Util = import "util.capnp";
using Signed = Util.Signed;
using Maybe = Util.Maybe;

interface Keyserver {
    prekeyBundle @0 (ik :Data) -> (bundle :PrekeyBundle);
    updateIdentity @1 (ik :Data, spk :Signed(PublicKey));
    addOpks @2 (ik :Data, opks :List(Signed(OneTimePrekey)));
}

using PublicKey = Data;

struct PrekeyBundle {
    ik @0 :PublicKey;
    spk @1 :Signed(PublicKey);
    opk @2 :Maybe(OneTimePrekey);
}

struct OneTimePrekey {
    id @0 :UInt64;
    key @1 :PublicKey;
}
