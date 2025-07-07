mod utils;

use wasm_bindgen::prelude::*;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// The Read Only Memory [`Rom`].
///
#[wasm_bindgen]
pub struct Rom(ashmaize::Rom);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
#[wasm_bindgen]
pub enum RomBuilderError {
    /// Missing the seed key parameter.
    /// Call [`RomBuilder::key`] function to set it.
    MissingKey = 1,
    /// Missing the total ROM size.
    /// Call [`RomBuilder::size`] function to set it.
    MissingSize = 2,
    /// Missing the ROM Generatiom Type. Call either
    /// [`RomBuilder::gen_full_random`] or [`RomBuilder::gen_two_steps`]
    /// to set a Generation Type.
    MissingGenType = 3,
    /// The [`RomBuilder::size`] cannot be null.
    SizeIsZero = 4,
    /// error shown if the `pre_size` parameter in [`RomBuilder::gen_two_steps`]
    /// is not a power of two.
    PreSizeNotPowerOfTwo = 5,
}

/// Helper object to build a [`Rom`].
#[wasm_bindgen]
#[derive(Default)]
pub struct RomBuilder {
    key: Option<Box<[u8]>>,
    gen_type: Option<ashmaize::RomGenerationType>,
    size: Option<usize>,
}

#[wasm_bindgen]
impl Rom {
    /// We need some parameters to be set to properly generate the [`Rom`].
    /// This function returns a helper to construct a [`Rom`]. See [`RomBuilder`]
    /// for the necessary parameters.
    ///
    #[wasm_bindgen]
    pub fn builder() -> RomBuilder {
        RomBuilder::new()
    }

    /// Compute the digest
    #[wasm_bindgen]
    pub fn hash(&self, salt: &[u8], nb_loops: u32, nb_instrs: u32) -> Vec<u8> {
        ashmaize::hash(salt, &self.0, nb_loops, nb_instrs).to_vec()
    }
}

#[wasm_bindgen]
impl RomBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // set the panic hook. This function is going to be used/called only
        // once. Subsequent calls will do nothing.
        utils::set_panic_hook();

        Self::default()
    }

    /// Set the _Seed_ key that is going to be used to initialise the
    /// Pseudo Random Number Generator (PRNG) that will be used to
    /// populate the random bytes in the [`Rom`].
    ///
    #[wasm_bindgen]
    pub fn key(&mut self, key: &[u8]) {
        self.key = Some(<Box<[u8]> as From<&[u8]>>::from(key));
    }

    /// Set the _Size_ of the [`Rom`] to generate.
    #[wasm_bindgen]
    pub fn size(&mut self, size: usize) {
        self.size = Some(size);
    }

    /// Set the Generation Type to use a full random.
    ///
    /// The PRNG initialised with the [`Self::key`] will be used to
    /// generate each of the bytes of the [`Rom`]. This function is a
    /// bit slower than [`Self::gen_two_steps`].
    #[wasm_bindgen]
    pub fn gen_full_random(&mut self) {
        self.gen_type = Some(ashmaize::RomGenerationType::FullRandom);
    }

    /// Set the Generation Type to use a two steps random generation.
    ///
    /// This method will generate a full random mixing buffer of size `pre_size`.
    /// This buffer will be used as source to randomly generate the [`Self::size`]
    /// of the [`Rom`]. This method is faster than [`Self::gen_full_random`].
    ///
    #[wasm_bindgen]
    pub fn gen_two_steps(&mut self, pre_size: usize, mixing_numbers: usize) {
        self.gen_type = Some(ashmaize::RomGenerationType::TwoStep {
            pre_size,
            mixing_numbers,
        });
    }

    /// Finalise building the [`Rom`].
    ///
    #[wasm_bindgen]
    pub fn build(&self) -> Result<Rom, RomBuilderError> {
        let key = self.key.as_deref().ok_or(RomBuilderError::MissingKey)?;
        let size = self.size.ok_or(RomBuilderError::MissingSize)?;
        let gen_type = self.gen_type.ok_or(RomBuilderError::MissingGenType)?;

        if size == 0 {
            return Err(RomBuilderError::SizeIsZero);
        }

        if let ashmaize::RomGenerationType::TwoStep { pre_size, .. } = gen_type
            && !pre_size.is_power_of_two()
        {
            return Err(RomBuilderError::PreSizeNotPowerOfTwo);
        }

        let rom = ashmaize::Rom::new(key, gen_type, size);
        Ok(Rom(rom))
    }
}
