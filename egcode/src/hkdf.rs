use hmac::{KeyInit as _, Mac as _};

pub(crate) fn hkdf<D: digest::Digest + digest::common::BlockSizeUser>(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
) -> [u8; 32] {
    // Expand
    let mut hmac = crate::hmac::Hmac::<D>::new_from_slice(salt).unwrap();
    hmac.update(ikm);
    let prk: [u8; 32] = hmac.finalize().into_bytes().as_slice().try_into().unwrap();
    // Extract
    let mut hmac = crate::hmac::Hmac::<D>::new_from_slice(&prk).unwrap();
    hmac.update(info);
    hmac.update(&1u32.to_be_bytes());
    hmac.finalize().into_bytes().as_slice().try_into().unwrap()
}
