#![no_std]
pub mod decrypt;
pub mod encrypt;

const BLOCK_SIZE: usize = 1024;
const TAG_SIZE: usize = 16;

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
            0 => Err(()),
            1 => Ok(Self::WithPassword),
            2 => Ok(Self::WithDeviceKey),
            3 => Ok(Self::WithPasswordAndDeviceKey),
            _ => Err(()),
        }
    }
}

impl Method {
    fn as_bytes(&self) -> [u8; 2] {
        match self {
            Self::WithPassword => 1u16.to_le_bytes(),
            Self::WithDeviceKey => 2u16.to_le_bytes(),
            Self::WithPasswordAndDeviceKey => 3u16.to_le_bytes(),
        }
    }
}
