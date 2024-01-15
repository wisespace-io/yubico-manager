extern crate hex;
extern crate yubico_manager;

use std::ops::Deref;
use yubico_manager::{Yubico};
use yubico_manager::config::{Config, Slot, Mode};

fn main() {
   let mut yubi = Yubico::new();

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

       let config = Config::new_from(device)
           .set_variable_size(true)
           .set_mode(Mode::Sha1)
           .set_slot(Slot::Slot2);

       // Challenge can not be greater than 64 bytes
       let challenge = String::from("mychallenge");
       // In HMAC Mode, the result will always be the SAME for the SAME provided challenge
       let hmac_result= yubi.challenge_response_hmac(challenge.as_bytes(), config).unwrap();

       // Just for debug, lets check the hex
       let v: &[u8] = hmac_result.deref();
       let hex_string = hex::encode(v);

       println!("{}", hex_string);       
     
   } else {
       println!("Yubikey not found");
   }
}
