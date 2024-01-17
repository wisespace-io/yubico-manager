extern crate hex;
extern crate yubico_manager;

use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::Yubico;

fn main() {
    let mut yubi = Yubico::new();

    if let Ok(device) = yubi.find_yubikey() {
        println!(
            "Vendor ID: {:?} Product ID {:?}",
            device.vendor_id, device.product_id
        );

        let config = Config::default_config()
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_mode(Mode::Otp)
            .set_slot(Slot::Slot2);

        // Challenge can not be greater than 64 bytes
        let challenge: &[u8] = b"my_challenge";
        // In OTP Mode, the result will always be different, even if the challenge is the same
        let otp_result = yubi.challenge_response_otp(challenge, config).unwrap();

        // Just for debug, lets check the hex
        let v: &[u8] = &otp_result.block;
        let hex_string = hex::encode(v);

        println!("{}", hex_string);
    } else {
        println!("Yubikey not found");
    }
}
