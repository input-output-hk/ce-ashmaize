use std::sync::mpsc::{Sender, channel};
use std::{sync::Arc, thread, time::SystemTime};

use ashmaize::*;
use indicatif::{ProgressBar, ProgressStyle};

pub struct Thread {}

#[derive(Clone)]
pub struct GlobalParams {
    prefix: usize,
    rom: Arc<Rom>,
}

#[derive(Clone)]
pub enum Result {
    Progress(usize),
    Found(u128),
}

fn spin(params: GlobalParams, prefix: u128, sender: Sender<Result>) {
    let mut salt = 0u128;

    loop {
        let salt_bytes = (prefix | salt).to_le_bytes();

        let h = hash(&salt_bytes, &params.rom, 8, 256);

        //pb.set_position(salt as u64);

        if hash_structure_good(&h, params.prefix) {
            //println!("hash: {}", hex::encode(h));
            sender.send(Result::Found(prefix | salt)).unwrap();
        }

        if salt & 0xff == 0 {
            sender.send(Result::Progress(0xff)).unwrap();
            //println!("not hash: {} salt {}", hex::encode(h), salt);
            /*
            let elapsed = start_loop.elapsed().unwrap().as_secs_f64();
            let current_speed = (salt as f64) / elapsed;

            // Update the message with the current speed
            pb.set_message(format!("Speed: {:.2} hash/s", current_speed));
            */
        }

        salt += 1;
    }
}

fn main() {
    const MB: usize = 1024 * 1024;
    const GB: usize = 1024 * MB;

    let args = std::env::args().collect::<Vec<_>>();

    let key = b"key";

    thread::scope(|s| {
        let rom = Rom::new(key, 16 * MB, 1 * GB);

        let params = GlobalParams {
            prefix: 16,
            rom: Arc::new(rom),
        };

        let (sender, receiver) = channel();

        let nb_threads = 10;
        for thread_id in 0..nb_threads {
            let prefix = {
                let mut prefix_bytes = [0; 8];
                getrandom::fill(&mut prefix_bytes).unwrap();
                let n = u64::from_le_bytes(prefix_bytes);
                (n as u128) << 64
            };

            let params = params.clone();
            let sender = sender.clone();
            s.spawn(move || {
                println!("starting thread {} : {:x}", thread_id, prefix);
                spin(params, prefix, sender)
                //
            });
        }
        let start_loop = SystemTime::now();

        let mut pos = 0;
        let pb = ProgressBar::new(u64::MAX);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {pos}/{len} [{elapsed_precise}] {bar:40.cyan/blue} {msg}",
            )
            .unwrap()
            .progress_chars("#>-"),
        );

        let mut found = Vec::new();
        loop {
            let r = receiver.recv().unwrap();
            match r {
                Result::Progress(sz) => {
                    pos += sz as u64;
                    pb.set_position(pos);
                    let elapsed = start_loop.elapsed().unwrap().as_secs_f64();
                    let current_speed = (pos as f64) / elapsed;

                    // Update the message with the current speed
                    pb.set_message(format!(
                        "Speed: {:.2} hash/s found: {}",
                        current_speed,
                        found.len()
                    ));
                }
                Result::Found(salt) => {
                    //pb.set_message(format!("{}", found.len()));
                    found.push(salt)
                }
            }
        }
    });

    let finished = SystemTime::now();
    //let duration = finished.duration_since(start_loop).unwrap();

    /*
    println!(
        "found candidate for {} 0-bits prefix {:032x} in {}.{:06}",
        prefix_bits,
        salt,
        duration.as_secs(),
        duration.subsec_micros()
    )
    */
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
