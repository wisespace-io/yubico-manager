[![Build Status](https://travis-ci.org/wisespace-io/yubico-rs.png?branch=master)](https://travis-ci.org/wisespace-io/yubico-rs)
[![Crates.io](https://img.shields.io/crates/v/yubico.svg)](https://crates.io/crates/yubico)
[![MIT licensed](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE-MIT)
[![Apache-2.0 licensed](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)

# Yubico

Enables integration with the Yubico validation platform, so you can use Yubikey's one-time-password in your Rust application, allowing a user to authenticate via Yubikey.

## Current features

- [X] Yubikey client API library, [validation protocol version 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html).
- [X] Challenge-Response
- [ ] Configuration, not supported, you can use [Yubikey Personalization GUI](https://developers.yubico.com/yubikey-personalization-gui/)

## Usage

Add this to your Cargo.toml

```toml
[dependencies]
yubico = "0.3"
```

[Request your api key](https://upgrade.yubico.com/getapikey/).

### Example with Default Servers

```rust
extern crate yubico;

use yubico::Yubico;
use yubico::config::*;

fn main() {
   let yubi = Yubico::new("CLIENT_ID", "API_KEY");
   let result = yubi.verify("OTP", Config::default());
   match result {
      Ok(answer) => println!("{}", answer),
      Err(e) => println!("Error: {}", e),
   }
}
```

## Example with custom API servers

```rust
extern crate yubico;

use yubico::Yubico;
use yubico::config::*;

fn main() {
   let yubi = Yubico::new("CLIENT_ID", "API_KEY");

   let config = Config::default().set_api_hosts(vec!["https://api.example.com/verify".into()]);
   let result = yubi.verify("OTP", config);
   match result {
      Ok(answer) => println!("{}", answer),
      Err(e) => println!("Error: {}", e),
   }
}
```

### Example Challenge-Response (HMAC MODE)

```rust
extern crate yubico;
extern crate pretty_hex;

use pretty_hex::*;
use std::ops::Deref;
use yubico::{Yubico};
use yubico::config::{Config, Slot, Mode};

fn main() {
   let mut yubi = Yubico::new();

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

       let config = Config::default()
           .set_vendor_id(device.vendor_id)
           .set_product_id(device.product_id)
           .set_variable_size(true)
           .set_mode(Mode::Sha1)
           .set_slot(Slot::Slot2);

       // Challenge can not be greater than 64 bytes
       let challenge = String::from("mychallenge");
       let (hmac_result, _) = yubi.challenge_response(challenge.as_bytes(), config).unwrap();

       // Just for debug, lets check the hex
       let v: &[u8] = hmac_result.deref();
       println!("{:?}", v.hex_dump());

   } else {
       println!("Yubikey not found");
   }
}
```