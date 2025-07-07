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
        97, 69, 158, 30, 244, 24, 218, 189, 3, 54, 151, 98, 200, 4, 62, 231, 184, 194, 171, 216,
        239, 111, 203, 126, 147, 122, 208, 115, 233, 235, 21, 186, 41, 111, 126, 98, 151, 26, 55,
        151, 8, 154, 0, 139, 126, 125, 130, 54, 168, 228, 194, 194, 207, 57, 176, 213, 167, 178,
        155, 70, 21, 200, 18, 168,
    ];

    let mut builder = RomBuilder::new();
    builder.size(SIZE);
    builder.key(b"123");
    builder.gen_two_steps(PRE_SIZE, 4);

    let rom = builder.build().unwrap();
    let hash = rom.hash(b"hello", 8, NB_INSTR);

    assert_eq!(hash, EXPECTED);
}
