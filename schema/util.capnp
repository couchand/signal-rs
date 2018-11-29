@0x8d97c14f572a2ee7;

using Signature = Data;

# A signature that accompanies some signed content.  The content
# signed might be all of T or it could be some part, the exact
# bits and the necessary keys are left up to the context of use.
struct Signed(T) {
    # The value that has been signed.
    key @0 :T;
    # The signature of the value.
    sig @1 :Signature;
}

# An optional value analogous to standard Option.
struct Maybe(T) {
    union {
        # No value exists.
        none @0 :Void;
        # A value.
        some @1 :T;
    }
}
