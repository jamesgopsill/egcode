#![no_std]
#![doc = include_str!("../README.md")]
use embedded_io::Read;

/// Decryption methods.
pub mod decrypt;

/// Encryption methods.
pub mod encrypt;

pub(crate) mod chacha;
pub(crate) mod pbkdf2;

// The default block size used by chacha20poly1305.
const BLOCK_SIZE: usize = 1024;

/// Industry standard AES-GCM tag size.
const TAG_SIZE: usize = 16;

/// The enum represents the available encryption methods.
#[derive(PartialEq, Eq)]
pub enum Method {
    WithPassword,
    WithDeviceKey,
    WithPasswordAndDeviceKey,
}

impl TryFrom<u16> for Method {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::WithPassword),
            2 => Ok(Self::WithDeviceKey),
            3 => Ok(Self::WithPasswordAndDeviceKey),
            _ => Err(()),
        }
    }
}

impl Method {
    /// Turn the method into its bytes representation to
    /// be appended to the file.
    fn as_bytes(&self) -> [u8; 2] {
        match self {
            Self::WithPassword => 1u16.to_le_bytes(),
            Self::WithDeviceKey => 2u16.to_le_bytes(),
            Self::WithPasswordAndDeviceKey => 3u16.to_le_bytes(),
        }
    }

    /// Tries to read a method number from a reader.
    fn try_from_reader(reader: &mut impl Read) -> Result<Method, ()> {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes).map_err(|_| ())?;
        let value = u16::from_le_bytes(bytes);
        match value {
            1 => Ok(Self::WithPassword),
            2 => Ok(Self::WithDeviceKey),
            3 => Ok(Self::WithPasswordAndDeviceKey),
            _ => Err(()),
        }
    }
}
