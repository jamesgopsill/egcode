#![no_std]
#![no_main]

use defmt::{error, info, warn};
use digest::{Digest, common::BlockSizeUser};
use egcode::{
    decrypt::{DecryptBuilder, Error},
    encrypt::Encrypt,
};
use embassy_executor::Spawner;
use embassy_rp::clocks::RoscRng;

use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::rp_sha2::RpSha2;

use {defmt_rtt as _, panic_probe as _};

mod rp_sha2;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    info!("Welcome to the Pico egcode example");

    let gcode = "G1 X0 Y0\n G1 X1 Y0\n";
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
}

async fn encrypt_decrypt<D>(
    device_private_key: &StaticSecret,
    device_public_key: &PublicKey,
    gcode: &[u8],
) where
    D: Digest + BlockSizeUser + Clone + Unpin,
{
    let mut writer = [0u8; 1024];

    info!("Encrypting");
    let pwd = "test";
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

    info!("{} Bytes Written", written);
    info!("{}", writer[..written]);

    info!("Decrypting");
    let device_private_key: [u8; 32] = device_private_key.to_bytes();
    let d = DecryptBuilder::new(&writer[..written]);
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
