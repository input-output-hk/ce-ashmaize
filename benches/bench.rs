use divan::{Bencher, counter::BytesCount};
use hashmaze::Rom;

fn main() {
    divan::main();
}

#[divan::bench(args = [1_024, 1_024 * 1_024, 10 * 1_024 * 1_024, 100 * 1_024 * 1_024 ])]
fn rom_new(bencher: Bencher, rom_size: usize) {
    bencher
        .counter(BytesCount::new(rom_size))
        .bench(|| Rom::new(b"password", rom_size));
}

#[divan::bench(args = [1, 1024, 1024 * 1024, 10 * 1024 * 1024])]
fn hash(bencher: Bencher, instruction_count: usize) {
    // 10MB
    let rom = Rom::new(b"password", 10 * 1_024 * 1_024);

    bencher
        .counter(instruction_count)
        .bench(|| hashmaze::hash(b"salt", &rom, instruction_count))
}
