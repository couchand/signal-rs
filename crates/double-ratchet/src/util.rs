//! Various cryptographic utility functions.
//!
//! These simply wrap the actual implementations, locking
//! in parameters and exposing an interface focused on their
//! use in this project.  You are recommended to use the
//! underlying functions themselves.

use signal_common::error::{Error, Result};

pub fn hkdf(
    salt: &[u8],
    input: &[u8],
    info: &[u8],
) -> [u8; 64] {
    use orion::hazardous::kdf::hkdf;

    let mut key = [0; 64];

    // TODO: not unwrap!
    hkdf::derive_key(&salt, &input, Some(&info), &mut key).unwrap();

    key
}

pub fn hkdf_sha512(
    salt: &[u8],
    input: &[u8],
    info: &[u8],
    key: &mut [u8],
) {
    use orion::hazardous::kdf::hkdf;

    // TODO: not unwrap!
    hkdf::derive_key(salt, input, Some(info), key).unwrap();
}

pub fn hmac(
    key: &[u8],
    input: &[u8],
) -> [u8; 32] {
    use orion::hazardous::mac::hmac;

    // TODO: not unwrap!
    let hmac_key = hmac::SecretKey::from_slice(key).unwrap();

    // TODO: not unwrap!
    let hash = hmac::hmac(&hmac_key, input).unwrap();

    let mut res = [0; 32];
    res.copy_from_slice(hash.unprotected_as_bytes()[..32]);

    res
}

pub fn hmac_sha512(
    key: &[u8],
    input: &[u8],
) -> [u8; 64] {
    use orion::hazardous::mac::hmac;

    // TODO: not unwrap!
    let hmac_key = hmac::SecretKey::from_slice(key).unwrap();

    // TODO: not unwrap!
    let hash = hmac::hmac(&hmac_key, input).unwrap();

    let mut res = [0; 64];
    res.copy_from_slice(hash.unprotected_as_bytes());

    res
}

pub fn hmac_sha512_two_slices(
    key: &[u8],
    input1: &[u8],
    input2: &[u8],
) -> [u8; 64] {
    use orion::hazardous::mac::hmac;

    // TODO: not unwrap!
    let hmac_key = hmac::SecretKey::from_slice(key).unwrap();

    let mut mac = hmac::init(&hmac_key);

    // TODO: not unwrap!
    mac.update(input1).unwrap();

    // TODO: not unwrap!
    mac.update(input2).unwrap();

    // TODO: not unwrap!
    mac.finalize().unwrap()
}

pub fn aes256_cbc_pkcs7_encrypt<'a>(
    key: &[u8],
    iv: &[u8],
    buffer: &'a mut [u8],
    len: usize,
) -> &'a [u8] {
    use aes::Aes256;
    use aes::block_cipher_trait::generic_array::GenericArray;
    use block_modes::{BlockMode, BlockModeIv, Cbc};
    use block_modes::block_padding::Pkcs7;

    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    //let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    let cipher = Aes256Cbc::new_varkey(key, iv).unwrap();

    // TODO: not unwrap!
    cipher.encrypt_pad(buffer, len).unwrap()
}

pub fn aes256_cbc_pkcs7_decrypt<'a>(
    key: &[u8],
    iv: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a [u8]> {
    use aes::Aes256;
    use aes::block_cipher_trait::generic_array::GenericArray;
    use block_modes::{BlockMode, BlockModeIv, Cbc};
    use block_modes::block_padding::Pkcs7;

    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    //let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    let cipher = Aes256Cbc::new_varkey(key, iv).unwrap();

    cipher.decrypt_pad(buffer).map_err(|_| Error)
}
