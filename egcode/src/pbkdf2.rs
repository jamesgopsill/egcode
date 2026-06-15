#![allow(unused)]

use core::{iter::zip, task::Poll};

use futures::executor::block_on;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub(crate) struct AsyncPbkdf2<'a> {
    password: &'a [u8],
    salt: &'a [u8],
    rounds: u32,
    round: u32,
    hash: [u8; 32],
    accumulator: [u8; 32],
}

impl<'a> AsyncPbkdf2<'a> {
    pub fn new(password: &'a [u8], salt: &'a [u8], rounds: u32) -> Self {
        // HMAC U_1
        let mut hmac = Hmac::<Sha256>::new_from_slice(password).unwrap();
        hmac.update(salt);
        // block number
        hmac.update(&1u32.to_be_bytes());
        let hash = hmac.finalize().into_bytes();

        Self {
            password,
            salt,
            rounds,
            round: 1,
            hash: hash.into(),
            accumulator: hash.into(),
        }
    }

    pub async fn generate(self) -> [u8; 32] {
        self.await
    }

    pub fn block_on_generate(self) -> [u8; 32] {
        block_on(self.generate())
    }
}

impl<'a> Future for AsyncPbkdf2<'a> {
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
        let hasher = AsyncPbkdf2::new(password.as_slice(), salt.as_slice(), 1_000);
        let hash = hasher.block_on_generate();
        std::println!("{:?}", hash);
    }
}
