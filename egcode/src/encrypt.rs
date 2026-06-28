use embedded_io::{ErrorType, Read, Write};
// use hkdf::GenericHkdf;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    Method,
    chacha::ChaChaEncrypt,
    pbkdf2::{AsyncPbkdf2, Prf},
};

/// The types of error that might be encountered when
/// using `Encrypt`.
#[derive(Debug)]
pub enum Error<E> {
    PublicKeyError,
    CipherError,
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

impl<T, R> Encrypt<T, R>
where
    T: Read,
    R: RngCore + CryptoRng,
{
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

    /// Password protects an encrypted gcode file. A password is provide by the user
    /// and a specified set out of rounds for the async PBKDF2-HMAC-SHA2 (`AsyncPbkdf2`) implementation
    /// to run to generate a hash that is then used as the key for the `ChaCha20Poly1305`
    /// encryption algorithm. See `AsyncPbkdf2` on recoommendations on the number of rounds.
    pub async fn with_password<PRF, W>(
        mut self,
        writer: &mut W,
        pwd: &[u8],
        rounds: u32,
    ) -> Result<usize, Error<W::Error>>
    where
        PRF: Prf,
        W: Write + ErrorType,
    {
        // Generate a secret from a password
        let mut salt = [0u8; 16];
        self.rng.fill_bytes(&mut salt);

        let Ok(hasher) = AsyncPbkdf2::<PRF>::new(pwd, salt.as_slice(), rounds) else {
            return Err(Error::CipherError);
        };
        let secret = hasher.generate().await;

        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut nonce);

        let mut written: usize = 0;

        // NOTE. Using write and flush to accommodate SD card block writing
        // and prevent spin locks on embedded devices.
        written += writer.write(b"EGCO")?;
        written += writer.write(&1u16.to_le_bytes())?;
        written += writer.write(&rounds.to_le_bytes())?;
        written += writer.write(salt.as_slice())?;
        written += writer.write(nonce.as_slice())?;
        writer.flush()?;
        let cc = ChaChaEncrypt::new(
            &mut self.reader,
            writer,
            secret.as_slice(),
            nonce.as_slice(),
        )?;
        written += cc.encrypt().await?;
        Ok(written)
    }

    /// End-to-end protects a gcode file against a specific device public-private key pair.
    /// The process generates an ephemeral public-private key pair. The ephemeral private key
    /// is combined with the device public key to generate a shared secret. The shared secret
    /// is then passed through a HMAC-based Key Derivation Function (HKDF) to provide a secret
    /// suitable for `ChaCha20Poly1305`. The code is then ecnrypted and the ephemeral public key
    /// is provided in the header. Only a device with the device private key will be able to
    /// decrypt the gcode.
    pub async fn with_device_key<PRF, W>(
        mut self,
        writer: &mut W,
        device_public_key: &[u8],
    ) -> Result<usize, Error<W::Error>>
    where
        PRF: Prf,
        W: Write + ErrorType,
    {
        let Ok(bob): Result<[u8; 32], _> = device_public_key.try_into() else {
            return Err(Error::PublicKeyError);
        };
        let bob = PublicKey::from(bob);

        let ephemeral_private_key = EphemeralSecret::random_from_rng(&mut self.rng);
        let ephemeral_public_key = PublicKey::from(&ephemeral_private_key);

        let shared_secret = ephemeral_private_key.diffie_hellman(&bob);

        // A shared secret is unsuitable for chacha20 so we derive a new
        // secret based on it using HKDF
        let mut salt = [0u8; 16];
        self.rng.fill_bytes(&mut salt);
        let okm = crate::hkdf::hkdf::<PRF>(&salt, shared_secret.as_bytes(), b"egcode");
        /*
        let hk = GenericHkdf::<PRF>::new(Some(&salt), shared_secret.as_bytes());

        let mut okm = [0u8; 32];
        if hk.expand(b"egcode", &mut okm).is_err() {
            return Err(Error::KeyError);
        }
        */

        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut nonce);

        // NOTE. Using write and flush to accommodate SD card block writing
        // and prevent spin locks on embedded devices.
        let mut written: usize = 0;
        written += writer.write(b"EGCO")?;
        written += writer.write(&Method::WithDeviceKey.as_bytes())?;
        written += writer.write(&salt)?;
        written += writer.write(&nonce)?;
        written += writer.write(ephemeral_public_key.as_bytes())?;
        writer.flush()?;
        let cc = ChaChaEncrypt::new(&mut self.reader, writer, okm.as_slice(), nonce.as_slice())?;
        written += cc.encrypt().await?;

        Ok(written)
    }

    /// Combines `with_password` and `with_device_key`. The HKDF derive secret from the shared secret
    /// derived from the ephemeral private key and device public key is used to encrypt the gcode. The
    /// hash generated from PBKDF2-SHA2-HMAC is used to encrypt the ephemeral public key. Thus, you
    /// need the password to decrypt the ephemeral public key and then pair the ephemeral public key
    /// with the device key to decrypt the gcode thereby providing the need for the gcode to be placed
    /// on the right device and authorised in the presence of a trusted individual who knows the password
    /// to that code.
    pub async fn with_password_and_device_key<PRF, W>(
        mut self,
        writer: &mut W,
        pwd: &[u8],
        rounds: u32,
        device_public_key: &[u8],
    ) -> Result<usize, Error<W::Error>>
    where
        PRF: Prf,
        W: Write + ErrorType,
    {
        let Ok(bob): Result<[u8; 32], _> = device_public_key.try_into() else {
            return Err(Error::PublicKeyError);
        };
        let bob = PublicKey::from(bob);

        let ephemeral_private_key = EphemeralSecret::random_from_rng(&mut self.rng);
        let ephemeral_public_key = PublicKey::from(&ephemeral_private_key);

        let shared_secret = ephemeral_private_key.diffie_hellman(&bob);

        let mut gcode_salt = [0u8; 16];
        self.rng.fill_bytes(&mut gcode_salt);
        let gcode_secret =
            crate::hkdf::hkdf::<PRF>(&gcode_salt, shared_secret.as_bytes(), b"egcode");
        /*
        let hk = GenericHkdf::<PRF>::new(Some(&gcode_salt), shared_secret.as_bytes());

        let mut gcode_secret = [0u8; 32];
        if hk.expand(b"egcode", &mut gcode_secret).is_err() {
            return Err(Error::KeyError);
        }
        */

        let mut gcode_nonce = [0u8; 12];
        self.rng.fill_bytes(&mut gcode_nonce);

        // Generate a secret from a password
        let mut pwd_salt = [0u8; 16];
        self.rng.fill_bytes(&mut pwd_salt);
        let mut pwd_nonce = [0u8; 12];
        self.rng.fill_bytes(&mut pwd_nonce);

        let Ok(hasher) = AsyncPbkdf2::<PRF>::new(pwd, pwd_salt.as_slice(), rounds) else {
            return Err(Error::CipherError);
        };
        let pwd_secret = hasher.generate().await;

        let mut written: usize = 0;
        written += writer.write(b"EGCO")?;
        written += writer.write(&Method::WithPasswordAndDeviceKey.as_bytes())?;
        written += writer.write(&rounds.to_le_bytes())?;
        written += writer.write(&pwd_salt)?;
        written += writer.write(&pwd_nonce)?;
        written += writer.write(&gcode_salt)?;
        written += writer.write(&gcode_nonce)?;
        writer.flush()?;

        let mut key_slice = ephemeral_public_key.as_bytes().as_slice();
        let cc = ChaChaEncrypt::new(
            &mut key_slice,
            writer,
            pwd_secret.as_slice(),
            pwd_nonce.as_slice(),
        )?;
        written += cc.encrypt().await?;
        let cc = ChaChaEncrypt::new(
            &mut self.reader,
            writer,
            gcode_secret.as_slice(),
            gcode_nonce.as_slice(),
        )?;
        written += cc.encrypt().await?;

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use embedded_io_adapters::std::FromStd;
    use futures::executor::block_on;
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
        let r = block_on(e.with_password::<sha2::Sha256, _>(&mut writer, pwd.as_bytes(), 10_000));
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
        let r = block_on(e.with_device_key::<sha2::Sha256, _>(&mut writer, device_key.as_slice()));
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
        let r = block_on(e.with_password_and_device_key::<sha2::Sha256, _>(
            &mut writer,
            pwd.as_bytes(),
            10_000,
            device_key.as_slice(),
        ));
        assert!(r.is_ok())
    }
}
