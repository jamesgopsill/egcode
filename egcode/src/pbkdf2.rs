#![allow(unused)]

use core::{fmt::Error, hash::Hasher, iter::zip, marker::PhantomData, task::Poll};

use futures::FutureExt;
use hmac::{KeyInit as _, Mac as _, SimpleHmacReset};

/// A PseudoRandomFunction trait alias that lists the combination of trait that a struct
/// needs to implement.
pub trait Prf:
    digest::Digest + digest::FixedOutputReset + digest::block_api::BlockSizeUser + Clone + Unpin
{
}

impl<T> Prf for T where
    T: digest::Digest + digest::FixedOutputReset + digest::block_api::BlockSizeUser + Clone + Unpin
{
}

/// An asynchronous implementation of PBKDF2-HMAC-SHA2 for a single block hash. Requires
/// auditing. PBKDF2 was selected for password hashing as we need to meet the microcontroller
/// requirements where memory is in short supply so CPU-bound hardening was deemed appropriate.
pub(crate) struct AsyncPbkdf2<P>
where
    P: Prf,
{
    //password: &'a [u8],
    //salt: &'a [u8],
    rounds: u32,
    round: u32,
    hash: [u8; 32],
    accumulator: [u8; 32],
    hmac: SimpleHmacReset<P>,
}

impl<P> AsyncPbkdf2<P>
where
    P: Prf,
{
    /// Create a new instance specifying the password, salt and number of rounds to
    /// harden the resulting hash. The entropy of the password and number of rounds
    /// play a role into the hardness of the resulting hash. The instantiation invokes
    /// the first round of hashing. Rounds of `500_000`+ are typically used. Given that someone
    /// with the file could keep trialling hashes then you may want to consider setting
    /// this higher that user login service where the service could identify repeated attempts.
    /// The time to compute the hash is also not as much of a concern as CNC manufacturing
    /// typically takes hours so a minute or so file check would not have a major impact on
    /// operations.
    pub fn new(password: &[u8], salt: &[u8], rounds: u32) -> Result<Self, ()> {
        // HMAC U_1
        let Ok(mut hmac) = SimpleHmacReset::<P>::new_from_slice(password) else {
            return Err(());
        };
        hmac.update(salt);
        // block number
        hmac.update(&1u32.to_be_bytes());
        let hash = hmac.finalize_reset().into_bytes();

        Ok(Self {
            // password,
            // salt,
            rounds,
            round: 1,
            hash: hash.as_slice().try_into().unwrap(),
            accumulator: hash.as_slice().try_into().unwrap(),
            hmac,
        })
    }

    /// A convenience function around the structs future implementation
    /// that returns the resulting password hash.
    pub async fn generate(self) -> [u8; 32] {
        self.await
    }
}

/// Explicitly declare unpin to help the checker
impl<P> Unpin for AsyncPbkdf2<P> where P: Prf {}

impl<P> Future for AsyncPbkdf2<P>
where
    P: Prf,
{
    type Output = [u8; 32];

    /// Performs a round on every poll until the specified number
    /// of rounds is completed.
    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        // Because we can safely unpin
        let this = self.get_mut();
        if this.round >= this.rounds {
            Poll::Ready(core::mem::take(&mut this.accumulator))
        } else {
            this.round += 1;
            this.hmac.update(this.hash.as_slice());
            let hash = this.hmac.finalize_reset().into_bytes();
            this.hash.copy_from_slice(&hash);
            for i in 0..32 {
                this.accumulator[i] ^= this.hash[i];
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
    use sha2::Sha256;

    use super::*;

    #[test]
    fn test_async_pbkdf2() {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let password = b"password";
        let hasher =
            AsyncPbkdf2::<Sha256>::new(password.as_slice(), salt.as_slice(), 1_000).unwrap();
        let hash = block_on(hasher.generate());
        std::println!("{:?}", hash);
    }
}
