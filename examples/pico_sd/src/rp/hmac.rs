use digest::{
    FixedOutput, MacMarker, OutputSizeUser, Update,
    common::{Block, BlockSizeUser, KeySizeUser},
};
use hmac::KeyInit;
use sha2::Digest;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

#[derive(Clone)]
pub struct Hmac<D>
where
    D: Digest + BlockSizeUser,
{
    opad: Block<D>,
    digest: D,
}

impl<D> Hmac<D>
where
    D: Digest + BlockSizeUser + Clone,
{
    fn new_from_slice(key: &[u8]) -> Self {
        // Compute the block sized key
        let mut block_key = Block::<D>::default();
        let block_key_len = block_key.len();
        if key.len() <= block_key_len {
            block_key[..key.len()].copy_from_slice(key);
        } else {
            let hash = D::digest(key);
            if hash.len() <= block_key_len {
                block_key[..hash.len()].copy_from_slice(&hash);
            } else {
                block_key.copy_from_slice(&hash[..block_key_len]);
            }
        }

        let mut opad = Block::<D>::default();
        opad.copy_from_slice(&block_key);
        opad.iter_mut().for_each(|b| *b ^= OPAD);

        let mut ipad = Block::<D>::default();
        ipad.copy_from_slice(&block_key);
        ipad.iter_mut().for_each(|b| *b ^= IPAD);

        let mut digest = D::new();
        digest.update(&ipad);

        Self { opad, digest }
    }
}

impl<D> KeySizeUser for Hmac<D>
where
    D: Digest + BlockSizeUser + Clone,
{
    type KeySize = D::BlockSize;
}

impl<D> MacMarker for Hmac<D> where D: Digest + BlockSizeUser {}

impl<D> KeyInit for Hmac<D>
where
    D: Digest + BlockSizeUser + Clone,
{
    fn new(key: &digest::Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice())
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        Ok(Self::new_from_slice(key))
    }
}

impl<D> Update for Hmac<D>
where
    D: Digest + BlockSizeUser + Clone,
{
    fn update(&mut self, data: &[u8]) {
        self.digest.update(data);
    }
}

impl<D> OutputSizeUser for Hmac<D>
where
    D: Digest + BlockSizeUser + Clone,
{
    type OutputSize = D::OutputSize;
}

impl<D> FixedOutput for Hmac<D>
where
    D: Digest + BlockSizeUser + Clone,
{
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let hash = self.digest.finalize();
        let mut digest = D::new();
        digest.update(self.opad);
        digest.update(hash);
        digest.finalize_into(out);
    }
}

impl<D> hkdf::HmacImpl for Hmac<D>
where
    D: Digest + BlockSizeUser + Clone,
{
    fn new_from_slice(key: &[u8]) -> Self {
        Self::new_from_slice(key)
    }

    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    fn finalize(self) -> digest::Output<Self> {
        FixedOutput::finalize_fixed(self)
    }
}
