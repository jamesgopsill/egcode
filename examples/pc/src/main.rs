use std::{fs::File, io::BufReader};

use egcode::{decrypt::DecryptBuilder, encrypt::Encrypt};
use embedded_io_adapters::std::FromStd;
use futures::executor::block_on;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    let file = File::open("../../egcode/test_data/box.gcode").unwrap();
    let reader = BufReader::new(file);
    let reader = FromStd::new(reader);
    let mut writer = std::vec::Vec::new();
    let device_private_key = StaticSecret::random_from_rng(OsRng);
    let device_public_key = PublicKey::from(&device_private_key);
    let pwd = "test";
    let e = Encrypt::new(reader, OsRng);
    let written = block_on(e.with_password_and_device_key::<Sha256, _>(
        &mut writer,
        pwd.as_bytes(),
        100_000,
        device_public_key.as_bytes(),
    ))
    .unwrap();

    println!("Encrypted GCODE: ({})", written);

    let reader = FromStd::new(writer.as_slice());
    let device_private_key: [u8; 32] = device_private_key.to_bytes();

    let d = DecryptBuilder::new(reader);
    let mut line_decryptor =
        block_on(d.with_password_and_device_key::<Sha256>(pwd.as_bytes(), device_private_key))
            .unwrap();

    let mut line = std::vec::Vec::new();
    loop {
        match line_decryptor.read_line(&mut line) {
            Ok(Some(n)) => {
                let l = std::string::String::from_utf8(line[..n].to_vec()).unwrap();
                std::print!("[GCODE] ({n}) {l}");
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
