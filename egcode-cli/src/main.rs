use std::{fs::File, path::PathBuf};

use anyhow::anyhow;
use clap::{Parser, Subcommand};
use egcode::{decrypt::DecryptBuilder, encrypt::Encrypt};
use embedded_io_adapters::std::FromStd;
use futures::executor::block_on;
use rand_core::OsRng;
use sha2::Sha256;

const ROUNDS: u32 = 600_000;

#[derive(Debug, Parser)]
#[command(name = "egcode-cli")]
#[command(about = "", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        device_key: Option<String>,
    },
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        device_key: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Encrypt {
            input,
            output,
            password,
            device_key,
        } => match (password, device_key) {
            (Some(password), Some(device_key)) => {
                let key = hex::decode(device_key)?;
                let reader = File::open(input)?;
                let reader = FromStd::new(reader);
                let writer = File::create(output)?;
                let mut writer = FromStd::new(writer);
                let encrypt = Encrypt::new(reader, OsRng);
                let written = block_on(encrypt.with_password_and_device_key::<Sha256, _>(
                    &mut writer,
                    password.as_bytes(),
                    ROUNDS,
                    key.as_slice(),
                ))
                .map_err(|e| anyhow::anyhow!("Encryption Error: {:?}", e))?;
                println!("{written} bytes written.");
                Ok(())
            }
            (Some(password), None) => {
                let reader = File::open(input)?;
                let reader = FromStd::new(reader);
                let writer = File::create(output)?;
                let mut writer = FromStd::new(writer);
                let encrypt = Encrypt::new(reader, OsRng);
                let written = block_on(encrypt.with_password::<Sha256, _>(
                    &mut writer,
                    password.as_bytes(),
                    ROUNDS,
                ))
                .map_err(|e| anyhow::anyhow!("Encryption Error: {:?}", e))?;
                println!("{written} bytes written.");
                Ok(())
            }
            (None, Some(device_key)) => {
                let key = hex::decode(device_key)?;
                let reader = File::open(input)?;
                let reader = FromStd::new(reader);
                let writer = File::create(output)?;
                let mut writer = FromStd::new(writer);
                let encrypt = Encrypt::new(reader, OsRng);
                let written = block_on(encrypt.with_device_key::<Sha256, _>(&mut writer, &key))
                    .map_err(|e| anyhow::anyhow!("Encryption Error: {:?}", e))?;
                println!("{written} bytes written.");
                Ok(())
            }
            _ => Err(anyhow!("Password and/or device key required.")),
        },
        Commands::Decrypt {
            input,
            output,
            password,
            device_key,
        } => {
            let mut lines = match (password, device_key) {
                (Some(password), Some(device_key)) => {
                    let key = hex::decode(device_key)?;
                    let reader = File::open(input)?;
                    let reader = FromStd::new(reader);
                    let decryptor = DecryptBuilder::new(reader);
                    block_on(decryptor.with_password_and_device_key::<Sha256>(
                        password.as_bytes(),
                        key.as_slice().try_into()?,
                    ))
                    .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?
                }
                (Some(password), None) => {
                    let reader = File::open(input)?;
                    let reader = FromStd::new(reader);
                    let decryptor = DecryptBuilder::new(reader);
                    block_on(decryptor.with_password::<Sha256>(password.as_bytes()))
                        .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?
                }
                (None, Some(device_key)) => {
                    let key = hex::decode(device_key)?;
                    let reader = File::open(input)?;
                    let reader = FromStd::new(reader);
                    let decryptor = DecryptBuilder::new(reader);
                    block_on(decryptor.with_device_key::<Sha256>(key.as_slice().try_into()?))
                        .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?
                }
                _ => return Err(anyhow!("Password and/or device key required.")),
            };

            let mut written: usize = 0;
            let writer = File::create(output)?;
            let mut writer = FromStd::new(writer);
            loop {
                match lines.read_line(&mut writer) {
                    Ok(Some(n)) => {
                        written += n;
                    }
                    Ok(None) => {
                        println!("{written} bytes written");
                        break;
                    }
                    Err(e) => {
                        return Err(anyhow!("Decryption Error: {:?}", e));
                    }
                }
            }

            Ok(())
        }
    }
}
