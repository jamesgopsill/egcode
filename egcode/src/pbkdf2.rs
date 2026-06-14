#![allow(unused)]

use core::{iter::zip, task::Poll};

use futures::executor::block_on;
use sha2::{Digest, Sha256};

pub(crate) struct AsyncPbkdf2<'a> {
    password: &'a [u8],
    salt: &'a [u8],
}

impl<'a> AsyncPbkdf2<'a> {
    pub fn new(password: &'a [u8], salt: &'a [u8]) -> Self {
        Self { password, salt }
    }

    pub fn generate(&'a self, rounds: u32) -> HashFuture<'a> {
        HashFuture::new(self.password, self.salt, rounds)
    }

    pub fn block_on_generate(&'a self, rounds: u32) -> [u8; 32] {
        block_on(self.generate(rounds))
    }
}

pub(crate) struct HashFuture<'a> {
    password: &'a [u8],
    salt: &'a [u8],
    rounds: u32,
    round: u32,
    hash: [u8; 32],
    accumulator: [u8; 32],
}

impl<'a> HashFuture<'a> {
    fn new(password: &'a [u8], salt: &'a [u8], rounds: u32) -> Self {
        // Round 1
        let mut data = [0u8; 16];
        for (i, b) in salt.iter().enumerate() {
            data[i] = *b;
        }
        // add the block index
        // [0x00, 0x00, 0x00, 0x01];
        data[15] = 0x01;

        let mut hasher = Sha256::new();
        hasher.update(data.as_slice());
        let hash = hasher.finalize();

        Self {
            password,
            salt,
            rounds,
            round: 1,
            hash: hash.into(),
            accumulator: hash.into(),
        }
    }
}

impl<'a> Future for HashFuture<'a> {
    type Output = [u8; 32];

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        if self.round >= self.rounds {
            Poll::Ready(core::mem::take(&mut self.accumulator))
        } else {
            self.round += 1;
            let mut hasher = Sha256::new();
            hasher.update(self.hash.as_slice());
            self.hash = hasher.finalize().into();
            for i in 0..32 {
                self.accumulator[i] ^= self.hash[i];
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use futures::executor::block_on;
    use rand_core::{OsRng, RngCore};

    use super::*;

    #[test]
    fn test_async_pbkdf2() {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let password = b"password";
        let hasher = AsyncPbkdf2::new(password.as_slice(), salt.as_slice());
        let hash = hasher.block_on_generate(1_000);
        std::println!("{:?}", hash);
    }
}
