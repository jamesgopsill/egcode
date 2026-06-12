# egcode

A `no_std` streaming compliant encryption/decryption crate for manufacturing gcode.

## Motivation

`egcode` fills a gap in cryptographically secure methods of transferring manufacturing code to specific machines and ensuring the presence of a trusted individual. This could be the submission of code in makerspaces, within an organisation's own capability through to manufacturing bureaus.

Our research has revealed a distinct lack of cryptographically secure methods of protecting individual's design IP. Many makerspaces use SD cards and USB sticks to put gcode on the machines and all this is done using ASCII plaintext gcode. There are binary and compressed formats available but these can be easily be converted back. Another user picking up a USB stick in these facilities often see many gcode files left by other users. They could easily take a of these files and print as many of these as they like.

Some may choose to submit their gcode through a machines API however many machine APIs are not TLS encrypted (`http` rather than `https`). The data could therefore listened in on.

Cloud services are equally an unknown. Gcode is typically submitted to them as plaintext and while the transportation of the data is encrypted `https`, the data they receive is plaintext and could be interrogated by the service provider in a variety of ways - from assisting a designer by commenting on their design through to them being able to simply take the design and use it and AI/ML training.

In short, your Intellectual Property is at risk.

The objective of this project is to define the standards and methods of encrypting manufacturing code enabling assurances to be made at the manufacturing code level and supporting the variety of manufacturing contexts.


## Solution

`egcode` provides `no_std` streaming encryption / decryption methods enabling manufacturing microcontrollers to stream decrypt gcode from solid-state memory devices.

- `with_password` - An individual can encrypt their gcode using a password. The individual would then insert the gcode into a machine and enter their password which would enable the machine to decrypt the manufacturing code. This could be used on any machine.
- `with_device_key` - An individual encrypts their gcode against a specific device public key originating from a devices API or offered from a trusted store (e.g., a makerspaces website listing their devices). The encrypted gcode can only be manufactured by the device that holds the private key. Machine manufacturers and service providers should ensure that the key is only held by the machine.
- `with_password_and_device_key` - A double lock that prevents the gcode being decrypted on the wrong machine as well as needed to presence of a trusted individual who knows the password.

## There still needs to be trust

The solution offers a step-change in de-centralised security in manufacturing supply chains but there still needs to be trust in the machines you're working with and the firmware is using the manufacturing code for its intended purpose.

Future development is looking at adding further proofs to support approvals of jobs as well as firmware verification and validation on the machines to ensure they have not been tampered with and they are using the manufacturing code in the way it was intended for. The trust offered by `egcode` could be fed into billing/invoicing work.

## Auditing

## Contributing

Absolutely, please reach out and add feature requests and discussion on GitHub.

## Sponsoring

Yes please, :D.

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

#### With Derive Key (2u16)

#### With Password and Derive Key (3u16)

### Encrypted Gcode

All three methods result in deriving a key that is used to create a ChaCha20Poly1305 cipher. The cipher then encrypts 1024 byte gcode blocks with a 16 byte tag associated with each one. The last gcode block may be shorter that 1024 as it is the reminder of the read bytes.
 
| Description | Bytes | Type |
|--|--|--|
| Tag | `[u8; 16]` | `[u8; 16]`
| Gcode | `[u8; 1024]` | `[u8; 1024]` | 

## Publications


