# egcode

A `no_std` `async` `streaming` crate for encrypt/decrypt-ing [gcode (ISO 6983-1)](https://en.wikipedia.org/wiki/G-code) for Computer Numerical Controlled (CNC) devices.

⚠ This crate is under active development and has yet to be tested in production.

## Motivation

**TLDR;** Your Intellectual Property is at risk if you're using plaintext gcode.

`egcode` fills a gap in cryptographic tooling by provided end-to-end encryption for manufacturing code by ensuring assignment to specific CNC machines and the presence of a trusted individual to initiate the print job. Application areas include: makerspaces, in-house capability and manufacturing bureaus.

Our research has revealed a gap in cryptographic tooling to protect Engineering IP. For example, many makerspaces use SD cards and USB sticks to submit and stream gcode to CNC machines. The gcode is ASCII plaintext and/or compressed binary formats (shout out to bgcode) that can read and re-used by others on other devices or reversed engineer to extract the IP. Individuals picking up a USB stick in these facilities often see many gcode files left by other users. They could easily take a of these files and print as many of these as they like.

Some may choose to submit their gcode through CNC machine REST APIs however many CNC machine APIs are not TLS encrypted (`http` rather than `https`). The data could be listened into if malicous actors are on the network and the machine will typically save the code on local storage that could be accessed and where they are no guarantees that it the code is encrypted at rest.

Cloud services are also an unknown. Gcode submitted is typically transportated using `https` but it still remains plaintext and could be interrogated by the service provider in a variety of ways - from assisting a designer by commenting on their design through to them being able to simply take the design and use it. It also opens the opportunity for AI/ML training resulting in you IP being embedded within a model for others to use.

The objective of this project is to define the tooling (standards and methods) for end-to-end encryption of manufacturing code and provide assurances that the code can only be used for what it is intended for.

## Solution

`egcode` provides `no_std` `async` `streaming` encryption / decryption tooling enabling encryption and decryption on both desktop and CNC machine microcontrollers.

- `with_password` - An individual can encrypt their gcode using a password. The individual would then insert the gcode into a machine and enter their password which would enable the CNC machine to decrypt the manufacturing code. This provides protections that the individual needs to be present at the machine when the job is submitted.
- `with_device_key` - An individual encrypts their gcode against a specific device public key which could come from a devices API or offered from a trusted store (e.g., a makerspaces website listing their devices). The device key could also relate to a fleet of CNC machines or machines of the same make and model. The encrypted gcode can only be manufactured by the CNC machines that hold the private key. Machine manufacturers and service providers should ensure that the key is only held by valid machines. This ensures that the gcode can only be printed on the CNC machine(s) it is intended for.
- `with_password_and_device_key` - A double lock that prevents the gcode being decrypted on the wrong machine as well as needing the presence of a trusted individual who knows the password.

## There still needs to be trust

The solution offers a step-change in de-centralised security in manufacturing supply chains but there still needs to be trust in the machines you're working with and the firmware is using the manufacturing code for its intended purpose.

Future development is looking at adding further proofs to support approvals of jobs as well as firmware verification and validation on the machines to ensure they have not been tampered with and they are using the manufacturing code in the way it was intended for. There are also opportunities to explore time-bound techniques. The trust offered by `egcode` could be fed into billing/invoicing work.

`egcode` does not parse or provide any guarantees that the decrypted gcode is suitable for purpose or malicious. In fact, there are no checks that the data provided by a user is valid gcode at all. Please let us know if you feel this is in or out of scope of what you think the system boundary of this project should be.

## Example

```rust
use embedded_io_adapters::std::FromStd;
use futures::executor::block_on;
use rand_core::OsRng;
use egcode::encrypt::Encrypt;
use egcode::decrypt::DecryptBuilder;
use sha2::Sha256;

let file = std::fs::File::open("test_data/box.gcode").unwrap();
let reader = std::io::BufReader::new(file);
let reader = FromStd::new(reader);
let pwd = "shhh";
let mut writer = std::vec::Vec::new();
let e = Encrypt::new(reader, OsRng);

block_on(e.with_password::<Sha256, _>(&mut writer, pwd.as_bytes(), 10_000)).unwrap();
println!("Encrypted Gcode Length: {:?}", writer.len());

let reader = FromStd::new(writer.as_slice());
let d = DecryptBuilder::new(reader);
let mut line_reader = block_on(d.with_password::<Sha256>(pwd.as_bytes())).unwrap();

let mut line = std::vec::Vec::new();

loop {
  match line_reader.read_line(&mut line) {
    Ok(Some(n)) => {
      let l = String::from_utf8(line[..n].to_vec()).unwrap();
      print!("[LINE]{l}");
      line.clear();
    }
    Ok(None) => {
      println!("EOF");
      break;
    }
    Err(e) => {
      println!("[Error] {e:?}");
      panic!("Error");
    }
  }
}
```

## Auditing

This is planned and we're reaching out to colleagues who can assist us with this.

## Contributing

Absolutely, please reach out and add feature requests and discussion on GitHub.

## Sponsoring

Yes please, :D. Sponsoring the project will enable us to dedicate more resource to building, testing, validating and providing support for the standard.

## File Specification

The `.egcode` specification features three main blocks - header, encryption metadata and encrypted gcode.

### Header

The header features a magic check to confirm it is an egcode file and informs us which encryption method has been used.

| Description | Bytes | Type |
|--|--|--|
| Magic (`b"EGCO"`) | `[u8; 4]` | `[u8; 4]`
| Method | `[u8; 2]` | `u16` | 

### Encryption Metadata

The encryption metadata depends on the method specified in the header. There are three modes at this time.

#### With Password (1u16)

The `with_password` features three additional binary fields - rounds, salt, and nonce.

| Description | Bytes | Type |
|--|--|--|
| Rounds | `[u8; 4]` | `u32` (le_bytes) |
| Salt | `[u8; 16]` | `[u8; 16]` | 
| Nonce | `[u8; 12]` | `Nonce` | 

#### With Device Key (2u16)

The `with_device_key` features three additional binary fields - rounds, salt, and ephemeral public key.

| Description | Bytes | Type |
|--|--|--|
| Salt | `[u8; 16]` | `[u8; 16]` | 
| Nonce | `[u8; 12]` | `Nonce` |
| Ephemeral Public Key | `[u8; 32]`| `PublicKey` |


#### With Password and Device Key (3u16)

The `with_password_and_device_key` features three additional binary fields - rounds, salt, and nonce.

| Description | Bytes | Type |
|--|--|--|
| Rounds | `[u8; 4]` | `u32` (le_bytes) |
| Password Salt | `[u8; 16]` | `[u8; 16]` | 
| Password Nonce | `[u8; 12]` | `Nonce` |
| Gcode Salt | `[u8; 16]` | `[u8; 16]` | 
| Gcode Nonce | `[u8; 12]` | `Nonce` |
| Ephemeral Public Key | `[u8; 32]`| `PublicKey` |

### Encrypted Gcode

All three methods derive a key that is used to create a `ChaCha20Poly1305` cipher. The cipher then encrypts gcode in 1024 byte blocks with 16 byte tags. The tag precedes the block. The last gcode block may be shorter that 1024 as it is the remainder of the read bytes.
 
| Description | Bytes | Type |
|--|--|--|
| Tag | `[u8; 16]` | `[u8; 16]`
| Gcode | `[u8; 1024]` | `[u8; 1024]` | 

## Publications

- Using Web3.0 to build trust in agent-based additive manufacturing systems. J Gopsill, P Walker-Davies Procedia CIRP 134, 687-692
- Secure by design: exploring a minimal Web3.0 trust network to provide de-centralised secure, private, and provenance preserving design and manufacture workflows. J Gopsill, O. Schiffmann, C. Ranscombe and M. Goudswaard. Proceedings of DESIGN. 2026
