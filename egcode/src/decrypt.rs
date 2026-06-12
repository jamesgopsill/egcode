use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use embedded_io::{Read, Write};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{BLOCK_SIZE, Method, TAG_SIZE};

extern crate std;

#[derive(Debug)]
pub enum Error {
    MustValidateFirst,
    InvalidMagic,
    InvalidMethod,
    WrongVersion,
    SeekError,
    CipherCreationFailed,
    ReadError,
    WriteError,
    DecryptError,
    KeyError,
}

pub struct Decrypt<T: Read> {
    reader: T,
    cipher: Option<ChaCha20Poly1305>,
    nonce: Option<Nonce>,
    buffer: [u8; BLOCK_SIZE * 2],
}

impl<T: Read> Decrypt<T> {
    pub fn new(reader: T) -> Self {
        Self {
            reader,
            cipher: None,
            nonce: None,
            buffer: [0u8; BLOCK_SIZE * 2],
        }
    }

    pub fn with_password(&mut self, pwd: &[u8]) -> Result<(), Error> {
        self.read_magic()?;
        let method = self.read_method()?;
        if method != Method::WithPassword {
            return Err(Error::InvalidMethod);
        }
        let salt = self.read_salt()?;
        let nonce = self.read_nonce()?;
        self.nonce = Some(nonce);

        let mut secret = [0u8; 32];
        pbkdf2_hmac::<Sha256>(pwd, &salt, 10_000, &mut secret);

        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&secret) else {
            return Err(Error::CipherCreationFailed);
        };
        self.cipher = Some(cipher);

        Ok(())
    }

    pub fn with_device_key(&mut self, device_private_key: [u8; 32]) -> Result<(), Error> {
        self.read_magic()?;
        let method = self.read_method()?;
        if method != Method::WithDeviceKey {
            return Err(Error::InvalidMethod);
        }
        let salt = self.read_salt()?;
        let nonce = self.read_nonce()?;
        self.nonce = Some(nonce);

        let mut ephemeral_public_key = [0u8; 32];
        self.reader
            .read_exact(&mut ephemeral_public_key)
            .map_err(|_| Error::ReadError)?;
        let ephemeral_public_key = PublicKey::from(ephemeral_public_key);

        let device_private_key = StaticSecret::from(device_private_key);
        let shared_secret = device_private_key.diffie_hellman(&ephemeral_public_key);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
        let mut gcode_secret = [0u8; 32];
        if hk.expand(b"egcode", &mut gcode_secret).is_err() {
            return Err(Error::KeyError);
        }

        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&gcode_secret) else {
            return Err(Error::CipherCreationFailed);
        };
        self.cipher = Some(cipher);

        Ok(())
    }

    pub fn with_password_and_device_key(
        &mut self,
        pwd: &[u8],
        device_private_key: [u8; 32],
    ) -> Result<(), Error> {
        self.read_magic()?;
        let method = self.read_method()?;
        if method != Method::WithPasswordAndDeviceKey {
            return Err(Error::InvalidMethod);
        }

        let pwd_salt = self.read_salt()?;
        let pwd_nonce = self.read_nonce()?;
        let gcode_salt = self.read_salt()?;
        let gcode_nonce = self.read_nonce()?;
        self.nonce = Some(gcode_nonce);

        // Create the cipher from the password to
        // decode the ephemeral_public_key

        let mut pwd_secret = [0u8; 32];
        pbkdf2_hmac::<Sha256>(pwd, &pwd_salt, 10_000, &mut pwd_secret);

        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(pwd_secret.as_slice()) else {
            return Err(Error::CipherCreationFailed);
        };

        let mut ephemeral_public_key = [0u8; 32];
        let mut tag = [0u8; TAG_SIZE];
        self.reader
            .read_exact(&mut tag)
            .map_err(|_| Error::ReadError)?;
        self.reader
            .read_exact(&mut ephemeral_public_key)
            .map_err(|_| Error::ReadError)?;

        cipher
            .decrypt_in_place_detached(&pwd_nonce, &[], &mut ephemeral_public_key, &tag.into())
            .map_err(|_| Error::DecryptError)?;

        let ephemeral_public_key = PublicKey::from(ephemeral_public_key);

        // Now use the ephemeral public key with the device private key
        // to decrypt the gcode.

        let device_private_key = StaticSecret::from(device_private_key);
        let shared_secret = device_private_key.diffie_hellman(&ephemeral_public_key);

        let hk = Hkdf::<Sha256>::new(Some(&gcode_salt), shared_secret.as_bytes());
        let mut gcode_secret = [0u8; 32];
        if hk.expand(b"egcode", &mut gcode_secret).is_err() {
            return Err(Error::KeyError);
        }

        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&gcode_secret) else {
            return Err(Error::CipherCreationFailed);
        };
        self.cipher = Some(cipher);

        Ok(())
    }

    fn read_salt(&mut self) -> Result<[u8; 16], Error> {
        let mut salt = [0u8; 16];
        self.reader
            .read_exact(&mut salt)
            .map_err(|_| Error::ReadError)?;
        Ok(salt)
    }

    fn read_nonce(&mut self) -> Result<Nonce, Error> {
        let mut nonce = [0u8; 12];
        self.reader
            .read_exact(&mut nonce)
            .map_err(|_| Error::ReadError)?;
        let nonce = Nonce::from_slice(&nonce);
        Ok(*nonce)
    }

    fn read_magic(&mut self) -> Result<(), Error> {
        let mut header: [u8; 4] = [0u8; 4];
        self.reader
            .read_exact(&mut header)
            .map_err(|_| Error::ReadError)?;
        if header != *b"EGCO" {
            return Err(Error::InvalidMagic);
        }
        Ok(())
    }

    fn read_method(&mut self) -> Result<Method, Error> {
        let mut method: [u8; 2] = [0u8; 2];
        self.reader
            .read_exact(&mut method)
            .map_err(|_| Error::ReadError)?;
        let method = u16::from_le_bytes(method);
        match Method::try_from(method) {
            Ok(m) => Ok(m),
            Err(_) => Err(Error::InvalidMethod),
        }
    }

    pub fn next(&mut self, writer: &mut impl Write) -> Result<Option<usize>, Error> {
        let Some(cipher) = self.cipher.as_ref() else {
            return Err(Error::MustValidateFirst);
        };
        let Some(nonce) = self.nonce.as_ref() else {
            return Err(Error::MustValidateFirst);
        };

        // Is there a line in the buffer
        if let Some(idx) = self.buffer.iter().position(|&b| b == b'\n') {
            let idx = idx + 1; // include the new line byte
            // Found a newline.
            writer
                .write_all(&self.buffer[..idx])
                .map_err(|_| Error::WriteError)?;
            self.buffer.copy_within(idx.., 0);
            let l = self.buffer.len();
            self.buffer[l - idx..].fill(0);
            // Could add a check for all zeros to denote we're at the end of the
            // stream
            Ok(Some(idx))
        } else {
            // No more lines in the buffer
            // Try and read another
            let mut block = [0u8; BLOCK_SIZE];
            let mut tag = [0u8; TAG_SIZE];
            let n = self.reader.read(&mut tag).map_err(|_| Error::ReadError)?;
            if n == 0 {
                // No more blocks. We must have read everything
                return Ok(None);
            }
            let tag = Tag::from_slice(&tag);
            let n = self.reader.read(&mut block).map_err(|_| Error::ReadError)?;
            cipher
                .decrypt_in_place_detached(nonce, &[], &mut block[..n], tag)
                .map_err(|_| Error::DecryptError)?;
            // Find the first null byte
            let Some(idx) = self.buffer.iter().position(|&b| b == 0) else {
                return Err(Error::DecryptError);
            };
            self.buffer[idx..idx + BLOCK_SIZE].copy_from_slice(&block);
            // Now we have some new data we should be able to find a line
            if let Some(idx) = self.buffer.iter().position(|&b| b == b'\n') {
                let idx = idx + 1;
                writer
                    .write_all(&self.buffer[..idx])
                    .map_err(|_| Error::WriteError)?;
                self.buffer.copy_within(idx.., 0);
                let l = self.buffer.len();
                self.buffer[l - idx..].fill(0);
                // Could add a check for all zeros to denote we're at the end of the
                // stream
                Ok(Some(idx))
            } else {
                Err(Error::DecryptError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use embedded_io_adapters::std::FromStd;
    use rand_core::OsRng;

    use crate::encrypt::Encrypt;

    use super::*;

    extern crate std;

    #[test]
    fn test_encrypt_decrypt_password() {
        let file = std::fs::File::open("test_data/box.gcode").unwrap();
        let reader = std::io::BufReader::new(file);
        let reader = FromStd::new(reader);
        let pwd = "test";
        let mut writer = std::vec::Vec::new();
        let e = Encrypt::new(reader, OsRng);
        e.with_password(&mut writer, pwd.as_bytes()).unwrap();
        std::println!("Encrypted Gcode Length: {:?}", writer.len());

        let reader = FromStd::new(writer.as_slice());
        let mut d = Decrypt::new(reader);
        d.with_password(pwd.as_bytes()).unwrap();

        let mut line = std::vec::Vec::new();

        loop {
            match d.next(&mut line) {
                Ok(Some(n)) => {
                    let _l = std::string::String::from_utf8(line[..n].to_vec()).unwrap();
                    // std::print!("[LINE]{l}");
                    line.clear();
                }
                Ok(None) => {
                    std::println!("EOF");
                    break;
                }
                Err(e) => {
                    std::println!("[Error] {e:?}");
                    panic!("Errored");
                }
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_device_key() {
        let file = std::fs::File::open("test_data/box.gcode").unwrap();
        let reader = std::io::BufReader::new(file);
        let reader = FromStd::new(reader);
        let mut writer = std::vec::Vec::new();
        let e = Encrypt::new(reader, OsRng);
        let device_private_key = StaticSecret::random_from_rng(OsRng);
        let device_public_key = PublicKey::from(&device_private_key);
        e.with_device_key(&mut writer, device_public_key.as_bytes())
            .unwrap();
        std::println!("Encrypted Gcode Length: {:?}", writer.len());

        let reader = FromStd::new(writer.as_slice());
        let mut d = Decrypt::new(reader);
        let bytes: [u8; 32] = device_private_key.to_bytes();
        d.with_device_key(bytes).unwrap();

        let mut line = std::vec::Vec::new();

        loop {
            match d.next(&mut line) {
                Ok(Some(n)) => {
                    let _l = std::string::String::from_utf8(line[..n].to_vec()).unwrap();
                    // std::print!("[LINE]{l}");
                    line.clear();
                }
                Ok(None) => {
                    std::println!("EOF");
                    break;
                }
                Err(e) => {
                    std::println!("Error {e:?}");
                    panic!("Errored");
                }
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_with_password_and_device_key() {
        let file = std::fs::File::open("test_data/box.gcode").unwrap();
        let reader = std::io::BufReader::new(file);
        let reader = FromStd::new(reader);
        let mut writer = std::vec::Vec::new();
        let device_private_key = StaticSecret::random_from_rng(OsRng);
        let device_public_key = PublicKey::from(&device_private_key);
        let pwd = "test";
        let e = Encrypt::new(reader, OsRng);
        e.with_password_and_device_key(&mut writer, pwd.as_bytes(), device_public_key.as_bytes())
            .unwrap();
        std::println!("Encrypted Gcode Length: {:?}", writer.len());
        let reader = FromStd::new(writer.as_slice());
        let mut d = Decrypt::new(reader);
        let device_private_key: [u8; 32] = device_private_key.to_bytes();
        d.with_password_and_device_key(pwd.as_bytes(), device_private_key)
            .unwrap();

        let mut line = std::vec::Vec::new();
        loop {
            match d.next(&mut line) {
                Ok(Some(n)) => {
                    let l = std::string::String::from_utf8(line[..n].to_vec()).unwrap();
                    std::print!("[LINE]{l}");
                    line.clear();
                }
                Ok(None) => {
                    std::println!("EOF");
                    break;
                }
                Err(e) => {
                    std::println!("Error {e:?}");
                    panic!("Errored");
                }
            }
        }
    }
}
