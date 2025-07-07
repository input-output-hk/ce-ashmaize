#![cfg(target_arch = "wasm32")]

use ashmaize_web::{RomBuilder, RomBuilderError};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const B: usize = 1;
const KB: usize = 1_024 * B;
const MB: usize = 1_024 * KB;

const DEFAULT_KEY: [u8; 32] = [0; 32];

#[wasm_bindgen_test]
fn rom_builder_missing_key() {
    let mut builder = RomBuilder::new();
    builder.size(1 * MB);
    builder.gen_full_random();

    assert!(matches!(builder.build(), Err(RomBuilderError::MissingKey)));
}

#[wasm_bindgen_test]
fn rom_builder_missing_size() {
    let mut builder = RomBuilder::new();
    builder.key(&DEFAULT_KEY);
    builder.gen_full_random();

    assert!(matches!(builder.build(), Err(RomBuilderError::MissingSize)));
}

#[wasm_bindgen_test]
fn rom_builder_missing_gen_type() {
    let mut builder = RomBuilder::new();
    builder.size(1 * MB);
    builder.key(&DEFAULT_KEY);

    assert!(matches!(
        builder.build(),
        Err(RomBuilderError::MissingGenType)
    ));
}

#[wasm_bindgen_test]
fn rom_builder_pre_size_not_power_of_two() {
    let mut builder = RomBuilder::new();
    builder.size(1 * MB);
    builder.key(&DEFAULT_KEY);
    builder.gen_two_steps(17, 8);

    assert!(matches!(
        builder.build(),
        Err(RomBuilderError::PreSizeNotPowerOfTwo)
    ));
}

#[wasm_bindgen_test]
fn rom_build_size_0() {
    let mut builder = RomBuilder::new();
    builder.size(0 * MB);
    builder.key(&DEFAULT_KEY);
    builder.gen_full_random();

    assert!(matches!(builder.build(), Err(RomBuilderError::SizeIsZero)));
}

#[wasm_bindgen_test]
fn rom_build_full_random() {
    let mut builder = RomBuilder::new();
    builder.size(1 * MB);
    builder.key(&DEFAULT_KEY);
    builder.gen_full_random();

    assert!(matches!(builder.build(), Ok(..)));
}

#[wasm_bindgen_test]
fn rom_build_two_steps() {
    let mut builder = RomBuilder::new();
    builder.size(1 * MB);
    builder.key(&DEFAULT_KEY);
    builder.gen_two_steps(256, 8);

    assert!(matches!(builder.build(), Ok(..)));
}

#[wasm_bindgen_test]
fn rom_hash() {
    const PRE_SIZE: usize = 16 * 1024;
    const SIZE: usize = 10 * 1024 * 1024;
    const NB_INSTR: u32 = 256;
    const EXPECTED: [u8; 64] = [
        165, 176, 206, 3, 53, 6, 210, 199, 204, 8, 95, 178, 189, 0, 216, 41, 59, 186, 178, 244,
        224, 2, 136, 33, 85, 149, 238, 107, 30, 85, 172, 145, 242, 237, 234, 198, 122, 121, 110,
        95, 227, 208, 118, 57, 243, 216, 38, 146, 132, 58, 44, 203, 183, 194, 111, 13, 37, 82, 123,
        46, 226, 55, 75, 202,
    ];

    let mut builder = RomBuilder::new();
    builder.size(SIZE);
    builder.key(b"123");
    builder.gen_two_steps(PRE_SIZE, 4);

    let rom = builder.build().unwrap();
    let hash = rom.hash(b"hello", 8, NB_INSTR);

    assert_eq!(hash, EXPECTED);
}
