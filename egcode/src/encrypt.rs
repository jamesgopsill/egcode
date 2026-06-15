use embedded_io::{ErrorType, Read, Write};
use futures::executor::block_on;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{Method, chacha::ChaChaEncrypt, pbkdf2::AsyncPbkdf2};

#[derive(Debug)]
pub enum Error<E> {
    UnprocessablePublicKey,
    CipherCreationFailed,
    BlockError,
    KeyError,
    WriteError(E),
    ReadError,
}

impl<E> From<E> for Error<E> {
    fn from(error: E) -> Self {
        Self::WriteError(error)
    }
}

/// Encrypts gcode.
pub struct Encrypt<T: Read, R: RngCore + CryptoRng> {
    /// A reader of gcode.
    reader: T,
    /// A cryptographically secure source of randomness.
    rng: R,
}

impl<T: Read, R: RngCore + CryptoRng> Encrypt<T, R> {
    /// Create a encrypter which requires a reader over the gcode
    /// and a source of randomness which could come from the
    /// operating system or microcontroller hardware. `Encrypt`
    /// implements `embedded_io::Read` so `embedded_io_adaptors::std::FromStd`
    /// can be used to convert a `std` reader.
    /// ```rust,ignore
    /// use embedded_io_adapters::std::FromStd;
    /// use rand_core::OsRng;
    /// use egcode::encrypt::Encrypt;
    ///
    /// /* code */
    ///
    /// let file = std::fs::File::open("<gcode_file>").unwrap();
    /// let reader = std::io::BufReader::new(file);
    /// let reader = FromStd::new(reader);
    /// let e = Encrypt::new(reader, OsRng);
    /// ```
    pub fn new(reader: T, rng: R) -> Self {
        Self { reader, rng }
    }

    /// TODO
    pub async fn with_password<W>(
        mut self,
        writer: &mut W,
        pwd: &[u8],
        rounds: u32,
    ) -> Result<(), Error<W::Error>>
    where
        W: Write + ErrorType,
    {
        // Generate a secret from a password
        let mut salt = [0u8; 16];
        self.rng.fill_bytes(&mut salt);

        // let mut secret = [0u8; 32];
        // pbkdf2_hmac::<Sha256>(pwd, &salt, rounds, &mut secret);
        let hasher = AsyncPbkdf2::new(pwd, salt.as_slice(), rounds);
        let secret = hasher.generate().await;

        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut nonce);

        writer.write_all(b"EGCO")?;
        writer.write_all(&1u16.to_le_bytes())?;
        writer.write_all(&rounds.to_le_bytes())?;
        writer.write_all(salt.as_slice())?;
        writer.write_all(nonce.as_slice())?;
        let cc = ChaChaEncrypt::new(
            &mut self.reader,
            writer,
            secret.as_slice(),
            nonce.as_slice(),
        )?;
        cc.encrypt().await?;
        Ok(())
    }

    pub fn block_on_with_password<W>(
        self,
        writer: &mut W,
        pwd: &[u8],
        rounds: u32,
    ) -> Result<(), Error<W::Error>>
    where
        W: Write + ErrorType,
    {
        let fut = self.with_password(writer, pwd, rounds);
        block_on(fut)
    }

    pub async fn with_device_key<W>(
        mut self,
        writer: &mut W,
        device_private_key: &[u8],
    ) -> Result<(), Error<W::Error>>
    where
        W: Write + ErrorType,
    {
        let Ok(bob): Result<[u8; 32], _> = device_private_key.try_into() else {
            return Err(Error::UnprocessablePublicKey);
        };
        let bob = PublicKey::from(bob);

        let ephemeral_private_key = EphemeralSecret::random_from_rng(&mut self.rng);
        let ephemeral_public_key = PublicKey::from(&ephemeral_private_key);

        let shared_secret = ephemeral_private_key.diffie_hellman(&bob);

        // A shared secret is unsuitable for chacha20 so we derive a new
        // secret based on it using HKDF
        let mut salt = [0u8; 16];
        self.rng.fill_bytes(&mut salt);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());

        let mut okm = [0u8; 32];
        if hk.expand(b"egcode", &mut okm).is_err() {
            return Err(Error::KeyError);
        }

        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut nonce);

        writer.write_all(b"EGCO")?;
        writer.write_all(&Method::WithDeviceKey.as_bytes())?;
        writer.write_all(&salt)?;
        writer.write_all(&nonce)?;
        writer.write_all(ephemeral_public_key.as_bytes())?;
        let cc = ChaChaEncrypt::new(&mut self.reader, writer, okm.as_slice(), nonce.as_slice())?;
        cc.encrypt().await?;

        Ok(())
    }

    pub fn block_on_with_device_key<W>(
        self,
        writer: &mut W,
        device_private_key: &[u8],
    ) -> Result<(), Error<W::Error>>
    where
        W: Write + ErrorType,
    {
        let fut = self.with_device_key(writer, device_private_key);
        block_on(fut)
    }

    pub async fn with_password_and_device_key<W>(
        mut self,
        writer: &mut W,
        pwd: &[u8],
        rounds: u32,
        device_private_key: &[u8],
    ) -> Result<(), Error<W::Error>>
    where
        W: Write + ErrorType,
    {
        let Ok(bob): Result<[u8; 32], _> = device_private_key.try_into() else {
            return Err(Error::UnprocessablePublicKey);
        };
        let bob = PublicKey::from(bob);

        let ephemeral_private_key = EphemeralSecret::random_from_rng(&mut self.rng);
        let ephemeral_public_key = PublicKey::from(&ephemeral_private_key);

        let shared_secret = ephemeral_private_key.diffie_hellman(&bob);

        let mut gcode_salt = [0u8; 16];
        self.rng.fill_bytes(&mut gcode_salt);
        let hk = Hkdf::<Sha256>::new(Some(&gcode_salt), shared_secret.as_bytes());

        let mut gcode_secret = [0u8; 32];
        if hk.expand(b"egcode", &mut gcode_secret).is_err() {
            return Err(Error::KeyError);
        }

        let mut gcode_nonce = [0u8; 12];
        self.rng.fill_bytes(&mut gcode_nonce);

        // Generate a secret from a password
        let mut pwd_salt = [0u8; 16];
        self.rng.fill_bytes(&mut pwd_salt);
        let mut pwd_nonce = [0u8; 12];
        self.rng.fill_bytes(&mut pwd_nonce);

        //let mut pwd_secret = [0u8; 32];
        //pbkdf2_hmac::<Sha256>(pwd, &pwd_salt, rounds, &mut pwd_secret);
        let hasher = AsyncPbkdf2::new(pwd, pwd_salt.as_slice(), rounds);
        let pwd_secret = hasher.generate().await;

        writer.write_all(b"EGCO")?;
        writer.write_all(&Method::WithPasswordAndDeviceKey.as_bytes())?;
        writer.write_all(&rounds.to_le_bytes())?;
        writer.write_all(&pwd_salt)?;
        writer.write_all(&pwd_nonce)?;
        writer.write_all(&gcode_salt)?;
        writer.write_all(&gcode_nonce)?;

        let mut key_slice = ephemeral_public_key.as_bytes().as_slice();
        let cc = ChaChaEncrypt::new(
            &mut key_slice,
            writer,
            pwd_secret.as_slice(),
            pwd_nonce.as_slice(),
        )?;
        cc.encrypt().await?;
        let cc = ChaChaEncrypt::new(
            &mut self.reader,
            writer,
            gcode_secret.as_slice(),
            gcode_nonce.as_slice(),
        )?;
        cc.encrypt().await?;

        Ok(())
    }

    pub fn block_on_with_password_and_device_key<W>(
        self,
        writer: &mut W,
        pwd: &[u8],
        rounds: u32,
        device_private_key: &[u8],
    ) -> Result<(), Error<W::Error>>
    where
        W: Write + ErrorType,
    {
        let fut = self.with_password_and_device_key(writer, pwd, rounds, device_private_key);
        block_on(fut)
    }
}

#[cfg(test)]
mod tests {
    use embedded_io_adapters::std::FromStd;
    use rand_core::OsRng;

    use super::*;

    extern crate std;

    #[test]
    fn test_encrypt_with_password() {
        let file = std::fs::File::open("test_data/box.gcode").unwrap();
        let reader = std::io::BufReader::new(file);
        let reader = FromStd::new(reader);
        let pwd = "test";
        let mut writer = std::vec::Vec::new();
        let e = Encrypt::new(reader, OsRng);
        let r = e.block_on_with_password(&mut writer, pwd.as_bytes(), 10_000);
        std::println!("Encrypted Gcode Length: {:?}", writer.len());
        assert!(r.is_ok())
    }

    #[test]
    fn test_encrypt_with_device_key() {
        let file = std::fs::File::open("test_data/box.gcode").unwrap();
        let reader = std::io::BufReader::new(file);
        let reader = FromStd::new(reader);
        let mut writer = std::vec::Vec::new();
        let mut device_key = [0u8; 32];
        OsRng.fill_bytes(&mut device_key);
        let e = Encrypt::new(reader, OsRng);
        let r = e.block_on_with_device_key(&mut writer, device_key.as_slice());
        assert!(r.is_ok())
    }

    #[test]
    fn test_encrypt_with_password_and_device_key() {
        let file = std::fs::File::open("test_data/box.gcode").unwrap();
        let reader = std::io::BufReader::new(file);
        let reader = FromStd::new(reader);
        let mut writer = std::vec::Vec::new();
        let mut device_key = [0u8; 32];
        OsRng.fill_bytes(&mut device_key);
        let pwd = "test";
        let e = Encrypt::new(reader, OsRng);
        let r = e.block_on_with_password_and_device_key(
            &mut writer,
            pwd.as_bytes(),
            10_000,
            device_key.as_slice(),
        );
        assert!(r.is_ok())
    }
}
