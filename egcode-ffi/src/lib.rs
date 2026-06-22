#![no_std]
#![allow(unused)]

use core::{
    ffi::{CStr, c_char, c_int, c_uint, c_void},
    num::{NonZero, NonZeroU32},
};

use egcode::encrypt::{self, Encrypt};
use futures::executor::block_on;
use rand_core::{CryptoRng, Error, RngCore};
use sha2::Sha256;

pub type CReadFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize;
pub type CWriteFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> isize;
pub type CFlushFn = unsafe extern "C" fn(*mut c_void) -> c_int;
pub type CRngFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32;

struct CReader {
    c_data: *mut c_void,
    c_read: CReadFn,
}

impl embedded_io::ErrorType for CReader {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for CReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        let read = unsafe { (self.c_read)(self.c_data, buf.as_mut_ptr(), buf.len()) };
        if read < 0 {
            return Err(embedded_io::ErrorKind::Other);
        }

        Ok(read as usize)
    }
}

struct CWriter {
    c_data: *mut c_void,
    c_write: CWriteFn,
    c_flush: CFlushFn,
}

impl embedded_io::ErrorType for CWriter {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Write for CWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        let written = unsafe { (self.c_write)(self.c_data, buf.as_ptr(), buf.len()) };

        if written < 0 {
            return Err(embedded_io::ErrorKind::Other);
        }

        Ok(written as usize)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        let result = unsafe { (self.c_flush)(self.c_data) };

        if result != 0 {
            return Err(embedded_io::ErrorKind::Other);
        }

        Ok(())
    }
}

#[repr(C)]
pub struct ExternalRng {
    c_ctx: *mut c_void,
    c_rng: CRngFn,
}

impl RngCore for ExternalRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_ne_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_ne_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if dest.is_empty() {
            return;
        }
        let status = unsafe { (self.c_rng)(self.c_ctx, dest.as_mut_ptr(), dest.len()) };
        assert_eq!(status, 0, "C random number generator error")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        if dest.is_empty() {
            return Ok(());
        }
        let status = unsafe { (self.c_rng)(self.c_ctx, dest.as_mut_ptr(), dest.len()) };
        match status {
            0 => Ok(()),
            _ => {
                let code = Error::CUSTOM_START + 1;
                Err(Error::from(NonZeroU32::new(code).unwrap()))
            }
        }
    }
}

impl CryptoRng for ExternalRng {}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt_with_password(
    c_data_in: *mut c_void,
    c_read: CReadFn,
    c_data_out: *mut c_void,
    c_write: CWriteFn,
    c_flush: CFlushFn,
    c_password: *const c_char,
    c_rounds: c_uint,
    rng: ExternalRng,
) -> c_int {
    if c_data_in.is_null() || c_data_out.is_null() || c_password.is_null() {
        return -1;
    }

    let reader = CReader {
        c_data: c_data_in,
        c_read,
    };

    let mut writer = CWriter {
        c_data: c_data_in,
        c_write,
        c_flush,
    };

    let password = unsafe { CStr::from_ptr(c_password) };

    let encrypt = Encrypt::new(password.to_bytes(), rng);
    let written =
        block_on(encrypt.with_password::<Sha256, _>(&mut writer, password.to_bytes(), c_rounds));
    match written {
        Ok(_w) => 0,
        Err(_e) => -1,
    }
}
