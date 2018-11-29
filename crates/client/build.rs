extern crate capnpc;

fn main() {
    ::capnpc::CompilerCommand::new()
        .src_prefix("../../schema/")
        .file("../../schema/keyserver.capnp")
        .file("../../schema/util.capnp")
        .run()
        .unwrap();
}
