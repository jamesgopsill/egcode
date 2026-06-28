#![no_std]
#![no_main]

use core::cell::RefCell;

use defmt::{error, info, warn};
use digest::Digest as _;
use egcode::{
    decrypt::{DecryptBuilder, Error},
    encrypt::Encrypt,
    pbkdf2::AsyncPbkdf2,
};
use embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice;
use embassy_executor::Spawner;
use embassy_rp::{
    clocks::RoscRng,
    gpio::Output,
    peripherals::SPI0,
    spi::{Blocking, Spi},
};
use embassy_sync::{blocking_mutex::Mutex, blocking_mutex::raw::ThreadModeRawMutex};
use embassy_time::{Delay, Instant};
use embedded_io::{Read as _, Seek as _, SeekFrom, Write as _};
use embedded_sdmmc::{BlockDevice, File, TimeSource, Timestamp};
use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use static_cell::StaticCell;
use x25519_dalek::{PublicKey, StaticSecret};

mod rp;

use {defmt_rtt as _, panic_probe as _};

static SPI_BUS: StaticCell<Mutex<ThreadModeRawMutex, RefCell<Spi<'static, SPI0, Blocking>>>> =
    StaticCell::new();

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    info!("Welcome to the Pico SD card example");

    let mut salt = [0u8; 16];
    RoscRng.fill_bytes(&mut salt);
    let pwd = b"test";

    info!("==== SHA256 CHECK ====");
    let mut hw_hash = rp::sha2::Sha2::new();
    hw_hash.update(pwd);
    let hash: [u8; 32] = hw_hash.finalize_reset().into();
    info!("HW_HASH (1): {}", hash);
    hw_hash.update(pwd);
    let hash: [u8; 32] = hw_hash.finalize_reset().into();
    info!("HW_HASH (2): {}", hash);

    let mut sw_hash = sha2::Sha256::new();
    sw_hash.update(pwd);
    let hash: [u8; 32] = sw_hash.finalize_reset().into();
    info!("SW_HASH (1): {:?}", hash);
    sw_hash.update(pwd);
    let hash: [u8; 32] = sw_hash.finalize_reset().into();
    info!("SW_HASH (2): {}", hash);

    info!("==== HMAC CHECK ====");

    let mut hmac = rp::hmac::Hmac::<rp::sha2::Sha2>::new_from_slice(pwd).unwrap();
    hmac.update(&salt);
    hmac.update(&1u32.to_be_bytes());
    let hash: [u8; 32] = hmac.finalize().into_bytes().as_slice().try_into().unwrap();
    info!("HW_HMAC_HASH (1): {:?}", hash);

    let mut hmac = SimpleHmac::<rp::sha2::Sha2>::new_from_slice(pwd).unwrap();
    hmac.update(&salt);
    hmac.update(&1u32.to_be_bytes());
    let hash: [u8; 32] = hmac.finalize().into_bytes().as_slice().try_into().unwrap();
    info!(
        "Should produce different hash because of hmac impl: {:?}",
        hash
    );

    let mut hmac = SimpleHmac::<sha2::Sha256>::new_from_slice(pwd).unwrap();
    hmac.update(&salt);
    hmac.update(&1u32.to_be_bytes());
    let hash: [u8; 32] = hmac.finalize().into_bytes().as_slice().try_into().unwrap();
    info!("SW_HMAC_HASH (1): {:?}", hash);

    info!("===== PBKDF2 =====");

    let hasher = AsyncPbkdf2::<rp::sha2::Sha2>::new(pwd, &salt, 100).unwrap();
    let hash = hasher.generate().await;
    info!("RPA_HASH: {}", hash);

    let hasher = AsyncPbkdf2::<sha2::Sha256>::new(pwd, &salt, 100).unwrap();
    let hash = hasher.generate().await;
    info!("SHA_HASH: {}", hash);

    info!("Generating Private-Public Key Pair");
    let device_private_key = StaticSecret::random_from_rng(RoscRng);
    let device_public_key = PublicKey::from(&device_private_key);

    let peripherals = embassy_rp::init(Default::default());

    let spi = embassy_rp::spi::Spi::new_blocking(
        peripherals.SPI0,
        peripherals.PIN_18,
        peripherals.PIN_19,
        peripherals.PIN_16,
        Default::default(),
    );
    let spi = Mutex::new(RefCell::new(spi));
    let spi = SPI_BUS.init(spi);
    let cs = Output::new(peripherals.PIN_17, embassy_rp::gpio::Level::High);
    let spi = SpiDevice::new(spi, cs);

    let sdcard = embedded_sdmmc::SdCard::new(spi, Delay);
    let volume_mgr = embedded_sdmmc::VolumeManager::new(sdcard, EmbassyTimeSource);

    info!("Opening Volume");

    match volume_mgr.open_volume(embedded_sdmmc::VolumeIdx(0)) {
        Ok(volume) => {
            let root_dir = volume.open_root_dir().unwrap();

            // EXAMPLE: Writing and reading a plaintext file.
            let file = root_dir
                .open_file_in_dir("01.txt", embedded_sdmmc::Mode::ReadWriteCreateOrTruncate)
                .unwrap();
            let mut file = EmbeddedV07IoAdapter(file);
            file.write(b"Hello World").unwrap();
            file.flush().unwrap();

            info!("[DONE]");

            // READ: Reset pointer and read back
            let mut buffer = [0u8; 32];
            file.seek(SeekFrom::Start(0)).unwrap();
            let bytes_read = file.read(&mut buffer).unwrap();

            // Use defmt to print the result
            info!(
                "Read from SD: {}",
                core::str::from_utf8(&buffer[..bytes_read]).unwrap()
            );

            // GCODE_ENCRYPT: Write and read some encrypted data.
            let gcode = "G1 X0 Y0\n G1 X1 Y0\n";
            let pwd = "test";

            // WRITE: Create or Open a file
            let file = root_dir
                .open_file_in_dir("01.egc", embedded_sdmmc::Mode::ReadWriteCreateOrTruncate)
                .unwrap();
            let mut file = EmbeddedV07IoAdapter(file);

            let e = Encrypt::new(gcode.as_bytes(), RoscRng);
            let written = e
                .with_password_and_device_key::<rp::sha2::Sha2, _>(
                    &mut file,
                    pwd.as_bytes(),
                    100,
                    device_public_key.as_bytes(),
                )
                .await
                .unwrap();

            info!("Bytes written to file ({})", written);
            file.seek(SeekFrom::Start(0)).unwrap();

            info!("[START] Decrypting");
            let start = Instant::now();
            let device_private_key: [u8; 32] = device_private_key.to_bytes();
            let d = DecryptBuilder::new(&mut file);
            info!("[FINISH] Decrypting ({}ms)", start.elapsed().as_millis());
            let mut line_decryptor = d
                .with_password_and_device_key::<rp::sha2::Sha2>(pwd.as_bytes(), device_private_key)
                .await
                .unwrap();
            let mut line = [0u8; 512];
            loop {
                match line_decryptor.read_line(&mut line.as_mut_slice()) {
                    Ok(Some(n)) => {
                        info!(
                            "Read from SD: {}",
                            core::str::from_utf8(&line[..n]).unwrap()
                        );
                    }
                    Ok(None) => {
                        warn!("EOF");
                        break;
                    }
                    Err(e) => {
                        match e {
                            Error::CipherError => error!("Cipher Error"),
                            Error::ReadError => error!("Read Error"),
                            Error::WriteError => error!("Write Error"),
                            Error::DecryptError => error!("Decrypt Error"),
                            _ => error!("Other Error"),
                        }
                        break;
                    }
                }
            }
        }
        Err(_e) => {
            error!("Failed to open volume.")
        }
    }
}

struct EmbassyTimeSource;

impl TimeSource for EmbassyTimeSource {
    fn get_timestamp(&self) -> embedded_sdmmc::Timestamp {
        // Dummy timestamp for demo purposes
        Timestamp {
            year_since_1970: 56,
            zero_indexed_month: 5,
            zero_indexed_day: 22,
            hours: 12,
            minutes: 0,
            seconds: 0,
        }
    }
}

struct EmbeddedV07IoAdapter<T>(pub T);

impl<D, T, const MAX_DIRS: usize, const MAX_FILES: usize, const MAX_VOLUMES: usize>
    embedded_io::ErrorType
    for EmbeddedV07IoAdapter<File<'_, D, T, MAX_DIRS, MAX_FILES, MAX_VOLUMES>>
where
    D: BlockDevice,
    T: TimeSource,
{
    type Error = embedded_io::ErrorKind; // Simplest mapping
}

impl<D, T, const MAX_DIRS: usize, const MAX_FILES: usize, const MAX_VOLUMES: usize>
    embedded_io::Write for EmbeddedV07IoAdapter<File<'_, D, T, MAX_DIRS, MAX_FILES, MAX_VOLUMES>>
where
    D: BlockDevice,
    T: TimeSource,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0
            .write(buf)
            .map_err(|_| embedded_io::ErrorKind::Other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush().map_err(|_| embedded_io::ErrorKind::Other)
    }
}

impl<D, T, const MAX_DIRS: usize, const MAX_FILES: usize, const MAX_VOLUMES: usize>
    embedded_io::Seek for EmbeddedV07IoAdapter<File<'_, D, T, MAX_DIRS, MAX_FILES, MAX_VOLUMES>>
where
    D: BlockDevice,
    T: TimeSource,
{
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        match pos {
            embedded_io::SeekFrom::Start(n) => self
                .0
                .seek_from_start(n as u32)
                .map_err(|_| embedded_io::ErrorKind::Other)?,
            embedded_io::SeekFrom::Current(n) => self
                .0
                .seek_from_current(n as i32)
                .map_err(|_| embedded_io::ErrorKind::Other)?,
            embedded_io::SeekFrom::End(n) => self
                .0
                .seek_from_end(n as u32)
                .map_err(|_| embedded_io::ErrorKind::Other)?,
        };
        // NOTE: incorrect value returned
        Ok(0)
    }
}
impl<D, T, const MAX_DIRS: usize, const MAX_FILES: usize, const MAX_VOLUMES: usize>
    embedded_io::Read for EmbeddedV07IoAdapter<File<'_, D, T, MAX_DIRS, MAX_FILES, MAX_VOLUMES>>
where
    D: BlockDevice,
    T: TimeSource,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf).map_err(|_| embedded_io::ErrorKind::Other)
    }
}
