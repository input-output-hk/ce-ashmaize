use std::time::SystemTime;

use ashmaize::*;
use indicatif::{ProgressBar, ProgressStyle};

fn main() {
    const MB: usize = 1024 * 1024;
    const GB: usize = 1024 * MB;

    let args = std::env::args().collect::<Vec<_>>();

    let key = b"key";

    let rom = Rom::new(key, 16 * MB, 1 * GB);

    let pb = ProgressBar::new(u64::MAX);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} {pos}/{len} [{elapsed_precise}] {bar:40.cyan/blue} {msg}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );

    let mut salt = 0u128;

    let mut salt_bytes = [0; 16];

    let start_loop = SystemTime::now();

    let prefix_bits = 20;

    loop {
        salt_bytes.copy_from_slice(&salt.to_le_bytes());

        let h = hash(&salt_bytes, &rom, 8, 256);

        pb.set_position(salt as u64);

        if hash_structure_good(&h, prefix_bits) {
            println!("hash: {}", hex::encode(h));
            break;
        }

        if salt % 1000 == 0 {
            //println!("not hash: {} salt {}", hex::encode(h), salt);
            let elapsed = start_loop.elapsed().unwrap().as_secs_f64();
            let current_speed = (salt as f64) / elapsed;

            // Update the message with the current speed
            pb.set_message(format!("Speed: {:.2} hash/s", current_speed));
        }

        salt += 1;
    }

    let finished = SystemTime::now();
    let duration = finished.duration_since(start_loop).unwrap();

    println!(
        "found candidate for {} 0-bits prefix {:032x} in {}.{:06}",
        prefix_bits,
        salt,
        duration.as_secs(),
        duration.subsec_micros()
    )
}

fn hash_structure_good(hash: &[u8], zero_bits: usize) -> bool {
    let full_bytes = zero_bits / 8; // Number of full zero bytes
    let remaining_bits = zero_bits % 8; // Bits to check in the next byte

    // Check full zero bytes
    if hash.len() < full_bytes || hash[..full_bytes].iter().any(|&b| b != 0) {
        return false;
    }

    if remaining_bits == 0 {
        return true;
    }
    if hash.len() > full_bytes {
        // Mask for the most significant bits
        let mask = 0xFF << (8 - remaining_bits);
        hash[full_bytes] & mask == 0
    } else {
        false
    }
}
