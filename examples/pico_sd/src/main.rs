#![no_std]
#![no_main]

use core::cell::RefCell;

use defmt::info;
use embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice;
use embassy_executor::Spawner;
use embassy_rp::{
    gpio::Output,
    peripherals::SPI0,
    spi::{Blocking, Spi},
};
use embassy_sync::{blocking_mutex::Mutex, blocking_mutex::raw::ThreadModeRawMutex};
use embassy_time::Delay;
use embedded_sdmmc::{TimeSource, Timestamp};
use static_cell::StaticCell;

use {defmt_rtt as _, panic_probe as _};

mod rp_sha2;

static SPI_BUS: StaticCell<Mutex<ThreadModeRawMutex, RefCell<Spi<'static, SPI0, Blocking>>>> =
    StaticCell::new();

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    info!("Welcome to the Pico SD card example");

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

    match volume_mgr.open_volume(embedded_sdmmc::VolumeIdx(0)) {
        Ok(_volume) => {
            // TODO: Write and read some encrypted data.
            let _gcode = "G1 X0 Y0\n G1 X1 Y0\n";
            /*
            let mut root_dir = volume.open_root_dir().unwrap();

            // WRITE: Create or Open a file
            let mut file = root_dir
                .open_file_in_dir("HELLO.TXT", embedded_sdmmc::Mode::ReadWriteCreateOrTruncate)
                .unwrap();
            file.write(b"Hello from Embassy Rust!").unwrap();
            file.flush().unwrap();

            // READ: Reset pointer and read back
            let mut buffer = [0u8; 32];
            file.seek_from_start(0).unwrap();
            let bytes_read = file.read(&mut buffer).unwrap();

            // Use defmt to print the result
            defmt::info!(
                "Read from SD: {}",
                core::str::from_utf8(&buffer[..bytes_read]).unwrap()
            );
            */
        }
        Err(_e) => defmt::error!("Failed to open volume"),
    }

    /*
    info!("Gcode bytes: {}", gcode.as_bytes());

    let mut sha_hw = RpSha2::new();
    sha_hw.update(gcode.as_bytes());
    let hash = sha_hw.finalize();

    info!("[HW SHA] {:?}", hash.as_slice());

    info!("[HW SHA LENGTH] {:?}", hash.len());

    let mut sha_sw = Sha256::new();
    Digest::update(&mut sha_sw, gcode);
    let hash = sha_sw.finalize();
    info!("[SW SHA] {:?}", hash.as_slice());
    info!("[SW SHA LENGTH] {:?}", hash.len());

    info!("Generating Private-Public Key Pair");
    let device_private_key = StaticSecret::random_from_rng(RoscRng);
    let device_public_key = PublicKey::from(&device_private_key);

    encrypt_decrypt::<Sha256>(&device_private_key, &device_public_key, gcode.as_bytes()).await;
    encrypt_decrypt::<RpSha2>(&device_private_key, &device_public_key, gcode.as_bytes()).await;
    */
}

struct EmbassyTimeSource;

impl TimeSource for EmbassyTimeSource {
    fn get_timestamp(&self) -> embedded_sdmmc::Timestamp {
        // Dummy timestamp for demo purposes
        Timestamp {
            year_since_1970: 56,
            zero_indexed_month: 5,
            zero_indexed_day: 19,
            hours: 12,
            minutes: 0,
            seconds: 0,
        }
    }
}

/*

async fn encrypt_decrypt<D>(
    device_private_key: &StaticSecret,
    device_public_key: &PublicKey,
    gcode: &[u8],
) where
    D: Digest + BlockSizeUser + Clone + Unpin,
{
    let mut writer = [0u8; 1024];

    info!("[Start] Encrypting");

    let pwd = "test";
    let start = Instant::now();
    let e = Encrypt::new(gcode, RoscRng);
    let written = e
        .with_password_and_device_key::<D, _>(
            &mut writer.as_mut_slice(),
            pwd.as_bytes(),
            100,
            device_public_key.as_bytes(),
        )
        .await
        .unwrap();
    info!("[FINISH] Encrypting ({}ms)", start.elapsed().as_millis());
    info!("{} Bytes Written", written);
    info!("{}", writer[..written]);

    info!("[START] Decrypting");
    let start = Instant::now();
    let device_private_key: [u8; 32] = device_private_key.to_bytes();
    let d = DecryptBuilder::new(&writer[..written]);
    info!("[FINISH] Decrypting ({}ms)", start.elapsed().as_millis());
    let mut line_decryptor = d
        .with_password_and_device_key::<D>(pwd.as_bytes(), device_private_key)
        .await
        .unwrap();
    let mut line = [0u8; 1024];
    loop {
        match line_decryptor.read_line(&mut line.as_mut_slice()) {
            Ok(Some(n)) => {
                info!("GCODE LINE: {}", line[..n]);
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


*/
