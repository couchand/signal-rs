@0xb18650cec7d93286;

interface Keyserver {
    prekeyBundle @0 (ik: Data) -> (bundle :PrekeyBundle);
    updateIdentity @1 (ik :Data, spk :Signed(PublicKey));
    addOpks @2 (ik :Data, opks :List(Signed(OneTimePrekey)));
}

using PublicKey = Data;
using Signature = Data;

struct PrekeyBundle {
    ik @0 :PublicKey;
    spk @1 :Signed(PublicKey);
    opk @2 :Maybe(OneTimePrekey);
}

struct OneTimePrekey {
    id @0 :UInt64;
    key @1 :PublicKey;
}

struct Signed(T) {
    key @0 :T;
    sig @1 :Signature;
}

struct Maybe(T) {
    union {
        none @0 :Void;
        some @1 :T;
    }
}
