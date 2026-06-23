#![no_std]
#![allow(unused)]

use core::{
    cell::UnsafeCell,
    ffi::{CStr, c_char, c_int, c_uint, c_void},
    num::{NonZero, NonZeroU32},
};

use egcode::{
    decrypt::{DecryptBuilder, DecryptReader},
    encrypt::{self, Encrypt},
};
use futures::executor::block_on;
use rand_core::{CryptoRng, Error, RngCore};
use sha2::{Sha256, digest::CollisionResistance};

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
pub struct CRng {
    c_ctx: *mut c_void,
    c_rng: CRngFn,
}

impl RngCore for CRng {
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

impl CryptoRng for CRng {}

struct SyncUnsafeCell<T>(UnsafeCell<Option<T>>);
unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    fn get_inner(&self, ref_ptr: *mut c_void) -> Result<T, i32> {
        let cell_ptr = self.0.get();
        // Check they're passing they are passing the right ptr
        if ref_ptr != cell_ptr as *mut c_void {
            return Err(-3);
        }
        // Take the instance and use it
        let instance = unsafe { (*cell_ptr).take() };
        match instance {
            Some(i) => Ok(i),
            None => Err(-2), // Error: Not initialized or already consumed
        }
    }
}

static ENCRYPT_CELL: SyncUnsafeCell<Encrypt<CReader, CRng>> = SyncUnsafeCell(UnsafeCell::new(None));

/// # Safety
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_encrypt(
    c_data_in: *mut c_void,
    c_read: CReadFn,
    rng: CRng,
) -> *mut c_void {
    if c_data_in.is_null() {
        return core::ptr::null_mut();
    }
    let reader = CReader {
        c_data: c_data_in,
        c_read,
    };
    let encrypt = Encrypt::new(reader, rng);
    unsafe {
        let cell_ptr = ENCRYPT_CELL.0.get();
        *cell_ptr = Some(encrypt);
        match (*cell_ptr).as_mut() {
            Some(inner) => inner as *mut Encrypt<CReader, CRng> as *mut c_void,
            None => core::ptr::null_mut(),
        }
    }
}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt_with_password(
    encrypt: *mut c_void,
    c_data_out: *mut c_void,
    c_write: CWriteFn,
    c_flush: CFlushFn,
    c_pwd: *const u8,
    c_pwd_len: usize,
    c_rounds: c_uint,
) -> c_int {
    if encrypt.is_null() || c_data_out.is_null() || c_pwd.is_null() {
        return -1;
    }

    let Ok(encrypt) = ENCRYPT_CELL.get_inner(encrypt) else {
        return -2;
    };

    let mut writer = CWriter {
        c_data: c_data_out,
        c_write,
        c_flush,
    };

    let pwd = unsafe { core::slice::from_raw_parts(c_pwd, c_pwd_len) };

    let written = block_on(encrypt.with_password::<Sha256, _>(&mut writer, pwd, c_rounds));

    match written {
        Ok(_w) => 0,
        Err(_e) => -1,
    }
}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt_with_password_and_device_key(
    encrypt: *mut c_void,
    c_data_out: *mut c_void,
    c_write: CWriteFn,
    c_flush: CFlushFn,
    c_pwd: *const u8,
    c_pwd_len: usize,
    c_device_key: *const u8,
    c_device_key_len: usize,
    c_rounds: c_uint,
) -> c_int {
    if encrypt.is_null() || c_data_out.is_null() || c_pwd.is_null() || c_device_key.is_null() {
        return -1;
    }

    let Ok(encrypt) = ENCRYPT_CELL.get_inner(encrypt) else {
        return -2;
    };

    let mut writer = CWriter {
        c_data: c_data_out,
        c_write,
        c_flush,
    };

    let pwd = unsafe { core::slice::from_raw_parts(c_pwd, c_pwd_len) };
    let device_key = unsafe { core::slice::from_raw_parts(c_device_key, c_device_key_len) };

    let written = block_on(encrypt.with_password_and_device_key::<Sha256, _>(
        &mut writer,
        pwd,
        c_rounds,
        device_key,
    ));

    match written {
        Ok(_w) => 0,
        Err(_e) => -1,
    }
}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt_with_device_key(
    encrypt: *mut c_void,
    c_data_out: *mut c_void,
    c_write: CWriteFn,
    c_flush: CFlushFn,
    c_device_key: *const u8,
    c_device_key_len: usize,
) -> c_int {
    if encrypt.is_null() || c_data_out.is_null() || c_device_key.is_null() {
        return -1;
    }

    let Ok(encrypt) = ENCRYPT_CELL.get_inner(encrypt) else {
        return -2;
    };

    let mut writer = CWriter {
        c_data: c_data_out,
        c_write,
        c_flush,
    };

    let device_key = unsafe { core::slice::from_raw_parts(c_device_key, c_device_key_len) };

    let written = block_on(encrypt.with_device_key::<Sha256, _>(&mut writer, device_key));
    match written {
        Ok(_w) => 0,
        Err(_e) => -1,
    }
}

/// # Safety
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_encrypt_instance(encrypt: *mut c_void) -> i32 {
    if encrypt.is_null() {
        return -1;
    }
    // Taking it will drop it.
    let Ok(encrypt) = ENCRYPT_CELL.get_inner(encrypt) else {
        return -2;
    };
    0
}

static DECRYPT_BUILDER_CELL: SyncUnsafeCell<DecryptBuilder<CReader>> =
    SyncUnsafeCell(UnsafeCell::new(None));
static DECRYPT_READER_CELL: SyncUnsafeCell<DecryptReader<CReader>> =
    SyncUnsafeCell(UnsafeCell::new(None));

/// # Safety
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_decrypt_builder(
    c_data_in: *mut c_void,
    c_read: CReadFn,
) -> *mut c_void {
    if c_data_in.is_null() {
        return core::ptr::null_mut();
    }
    let reader = CReader {
        c_data: c_data_in,
        c_read,
    };
    let decrypt_builder = DecryptBuilder::new(reader);
    unsafe {
        let cell_ptr = DECRYPT_BUILDER_CELL.0.get();
        *cell_ptr = Some(decrypt_builder);
        match (*cell_ptr).as_mut() {
            Some(inner) => inner as *mut DecryptBuilder<CReader> as *mut c_void,
            None => core::ptr::null_mut(),
        }
    }
}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decrypt_with_password(
    decrypt_builder: *mut c_void,
    c_pwd: *const u8,
    c_pwd_len: usize,
) -> *mut c_void {
    if decrypt_builder.is_null() || c_pwd.is_null() {
        return core::ptr::null_mut();
    }

    let Ok(builder) = DECRYPT_BUILDER_CELL.get_inner(decrypt_builder) else {
        return core::ptr::null_mut();
    };

    let pwd = unsafe { core::slice::from_raw_parts(c_pwd, c_pwd_len) };
    let Ok(reader) = block_on(builder.with_password::<Sha256>(pwd)) else {
        return core::ptr::null_mut();
    };

    unsafe {
        let cell_ptr = DECRYPT_READER_CELL.0.get();
        *cell_ptr = Some(reader);
        match (*cell_ptr).as_mut() {
            Some(inner) => inner as *mut DecryptReader<CReader> as *mut c_void,
            None => core::ptr::null_mut(),
        }
    }
}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decrypt_with_password_and_device_key(
    decrypt_builder: *mut c_void,
    c_pwd: *const u8,
    c_pwd_len: usize,
    c_device_key: *const u8,
    c_device_key_len: usize,
) -> *mut c_void {
    if decrypt_builder.is_null() || c_pwd.is_null() || c_device_key.is_null() {
        return core::ptr::null_mut();
    }

    let Ok(builder) = DECRYPT_BUILDER_CELL.get_inner(decrypt_builder) else {
        return core::ptr::null_mut();
    };

    let pwd = unsafe { core::slice::from_raw_parts(c_pwd, c_pwd_len) };
    let device_key = unsafe { core::slice::from_raw_parts(c_device_key, c_device_key_len) };
    let Ok(device_key): Result<[u8; 32], _> = device_key.try_into() else {
        return core::ptr::null_mut();
    };

    let Ok(reader) = block_on(builder.with_password_and_device_key::<Sha256>(pwd, device_key))
    else {
        return core::ptr::null_mut();
    };

    unsafe {
        let cell_ptr = DECRYPT_READER_CELL.0.get();
        *cell_ptr = Some(reader);
        match (*cell_ptr).as_mut() {
            Some(inner) => inner as *mut DecryptReader<CReader> as *mut c_void,
            None => core::ptr::null_mut(),
        }
    }
}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decrypt_with_device_key(
    decrypt_builder: *mut c_void,
    c_device_key: *const u8,
    c_device_key_len: usize,
) -> *mut c_void {
    if decrypt_builder.is_null() || c_device_key.is_null() {
        return core::ptr::null_mut();
    }

    let Ok(builder) = DECRYPT_BUILDER_CELL.get_inner(decrypt_builder) else {
        return core::ptr::null_mut();
    };

    let device_key = unsafe { core::slice::from_raw_parts(c_device_key, c_device_key_len) };
    let Ok(device_key): Result<[u8; 32], _> = device_key.try_into() else {
        return core::ptr::null_mut();
    };

    let Ok(reader) = block_on(builder.with_device_key::<Sha256>(device_key)) else {
        return core::ptr::null_mut();
    };

    unsafe {
        let cell_ptr = DECRYPT_READER_CELL.0.get();
        *cell_ptr = Some(reader);
        match (*cell_ptr).as_mut() {
            Some(inner) => inner as *mut DecryptReader<CReader> as *mut c_void,
            None => core::ptr::null_mut(),
        }
    }
}

/// TODO:
/// # Safety
/// TODO
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read_line(
    decrypt_reader: *mut c_void,
    c_data_out: *mut c_void,
    c_write: CWriteFn,
    c_flush: CFlushFn,
) -> c_uint {
    if decrypt_reader.is_null() || c_data_out.is_null() {
        return 0;
    }

    let Ok(mut reader) = DECRYPT_READER_CELL.get_inner(decrypt_reader) else {
        return 0;
    };

    let mut writer = CWriter {
        c_data: c_data_out,
        c_write,
        c_flush,
    };

    let Ok(Some(written)) = reader.read_line(&mut writer) else {
        return 0;
    };

    // Put it back for subsequent calls
    unsafe {
        let cell_ptr = DECRYPT_READER_CELL.0.get();
        *cell_ptr = Some(reader);
        match (*cell_ptr).as_mut() {
            Some(inner) => inner as *mut DecryptReader<CReader> as *mut c_void,
            None => return 0,
        };
    }

    written as c_uint
}

/// # Safety
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_decrypt_builder_instance(ptr: *mut c_void) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    // Taking it will drop it.
    let Ok(d) = DECRYPT_BUILDER_CELL.get_inner(ptr) else {
        return -2;
    };
    0
}

/// # Safety
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_decrypt_reader_instance(ptr: *mut c_void) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    // Taking it will drop it.
    let Ok(d) = DECRYPT_READER_CELL.get_inner(ptr) else {
        return -2;
    };
    0
}
