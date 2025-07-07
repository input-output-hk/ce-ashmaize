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
        0x79, 0x6f, 0x15, 0x4a, 0x30, 0x30, 0x6b, 0x4a, 0x8d, 0x51, 0x69, 0x49, 0x85, 0x77, 0xc9,
        0x1d, 0xd4, 0x61, 0x3b, 0x44, 0xd9, 0x72, 0xb3, 0x38, 0x2c, 0x37, 0x36, 0xd2, 0x80, 0x0e,
        0xde, 0x16, 0xda, 0x7c, 0x60, 0xb0, 0x60, 0x26, 0x12, 0xb5, 0xb4, 0x3a, 0xa2, 0x0f, 0x17,
        0xdd, 0xe3, 0xc0, 0xa1, 0x82, 0xd5, 0xbf, 0x80, 0xcf, 0xec, 0xa2, 0xcb, 0x29, 0x5d, 0x09,
        0x47, 0xd8, 0x01, 0x3b,
    ];

    let mut builder = RomBuilder::new();
    builder.size(SIZE);
    builder.key(b"123");
    builder.gen_two_steps(PRE_SIZE, 4);

    let rom = builder.build().unwrap();
    let hash = rom.hash(b"hello", 8, NB_INSTR);

    assert_eq!(hash, EXPECTED);
}
