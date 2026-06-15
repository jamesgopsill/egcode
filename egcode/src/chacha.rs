#![allow(unused)]

use core::{num::ParseIntError, task::Poll};

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use embedded_io::{ErrorType, Read, Write};

use crate::{BLOCK_SIZE, encrypt::Error};

pub(crate) struct ChaChaEncrypt<'a, R, W>
where
    R: Read,
    W: Write + ErrorType,
{
    reader: &'a mut R,
    writer: &'a mut W,
    secret: &'a [u8],
    nonce: &'a [u8],
    cipher: ChaCha20Poly1305,
}

impl<'a, R, W> ChaChaEncrypt<'a, R, W>
where
    R: Read,
    W: Write + ErrorType,
{
    pub fn new(
        reader: &'a mut R,
        writer: &'a mut W,
        secret: &'a [u8],
        nonce: &'a [u8],
    ) -> Result<Self, Error<W::Error>> {
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(secret) else {
            return Err(Error::CipherError);
        };
        Ok(Self {
            reader,
            writer,
            secret,
            nonce,
            cipher,
        })
    }

    pub async fn encrypt(self) -> Result<(), Error<W::Error>> {
        self.await
    }
}

impl<'a, R, W> Future for ChaChaEncrypt<'a, R, W>
where
    R: Read,
    W: Write + ErrorType,
{
    type Output = Result<(), Error<W::Error>>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let nonce = Nonce::from_slice(self.nonce);
        let mut block = [0u8; BLOCK_SIZE];

        let Ok(n) = self.reader.read(&mut block) else {
            return Poll::Ready(Err(Error::ReadError));
        };

        if n == 0 {
            return Poll::Ready(Ok(()));
        }

        let Ok(tag) = self
            .cipher
            .encrypt_in_place_detached(nonce, &[], &mut block[..n])
        else {
            return Poll::Ready(Err(Error::BlockError));
        };
        self.writer.write_all(&tag)?;
        self.writer.write_all(&block[..n])?;

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
