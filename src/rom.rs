use cryptoxide::{
    hashing::blake2b::{self, Blake2b},
    kdf::argon2,
};

pub const DATASET_ACCESS_SIZE: usize = 64;

pub(crate) struct RomDigest(pub(crate) [u8; 64]);

/// The **R**ead **O**only **M**emory used to generate the proram.
///
/// The **ROM** is a read-only memory that contains a random program.
/// The program is generated using a random seed and a random generation type.
/// The random generation type can be either [`RomGenerationType::FullRandom`] or [`RomGenerationType::TwoStep`].
///
/// [`hash`]: crate::hash
pub struct Rom {
    pub(crate) digest: RomDigest,
    data: Vec<u8>,
}

/// The generation type of the **ROM**.
///
/// This is used to drive the generation of the **ROM**. It can be
/// either fully random or use a two step approach.
///
#[derive(Clone, Copy, Debug)]
pub enum RomGenerationType {
    /// this is the simplest approach and it uses a blake2b to
    /// generate the whole ROM. However it is slower than the
    /// [`TwoSetp`] option
    FullRandom,
    /// This option is faster to execute and not necessarily
    /// weaker than [`FullRandom`].
    TwoStep {
        /// the pre-memory size
        ///
        /// This must be a power of `2` otherwise it will triger
        /// a panic during execution
        pre_size: usize,
        /// number of chunks to randomly combine (e.g. 4)
        mixing_numbers: usize,
    },
}

impl Rom {
    /// create a new [`Rom`] using the given data as `key` to initilise
    /// the _seed_ that will be used for the [`Rom`] generation
    ///
    /// This function is deterministic and will produce the same outputs
    /// for the same given inputs.
    ///
    /// # Panic
    ///
    /// this function may panic if the `pre_size` field in [`RomGenerationType::TwoStep`]
    /// is not a power of `2`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ashmaize::{Rom, RomGenerationType};
    /// # const KB: usize = 1_024;
    /// let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 256 * KB);
    /// ```
    ///
    /// ```
    /// # use ashmaize::{Rom, RomGenerationType};
    /// # const KB: usize = 1_024;
    /// let gen_type = RomGenerationType::TwoStep {
    ///     pre_size: 16 * KB,
    ///     mixing_numbers: 4,
    /// };
    /// let rom = Rom::new(b"seed", gen_type, 256 * KB);
    /// ```
    ///
    pub fn new(key: &[u8], gen_type: RomGenerationType, size: usize) -> Self {
        let mut data = vec![0; size];

        let seed = blake2b::Context::<256>::new()
            .update(&(data.len() as u32).to_le_bytes())
            .update(key)
            .finalize();
        let digest = random_gen(gen_type, seed, &mut data);

        Self { digest, data }
    }

    pub(crate) fn at(&self, i: u32) -> &[u8; DATASET_ACCESS_SIZE] {
        let start = i as usize % (self.data.len() / DATASET_ACCESS_SIZE);
        <&[u8; DATASET_ACCESS_SIZE]>::try_from(&self.data[start..start + DATASET_ACCESS_SIZE])
            .unwrap()
    }
}

fn random_gen(gen_type: RomGenerationType, seed: [u8; 32], output: &mut [u8]) -> RomDigest {
    if let RomGenerationType::TwoStep {
        pre_size,
        mixing_numbers,
    } = gen_type
    {
        assert!(pre_size.is_power_of_two());
        let mut mixing_buffer = vec![0; pre_size];

        argon2::hprime(&mut mixing_buffer, &seed);

        const OFFSET_LOOPS: u32 = 4;

        // generate a 32 u16s iterator from a digest
        fn digest_to_u16s(digest: &[u8; 64]) -> impl Iterator<Item = u16> {
            digest
                .chunks(2)
                .map(|c| u16::from_le_bytes(*<&[u8; 2]>::try_from(c).unwrap()))
        }

        let mut offsets_diff = vec![];
        for i in 0u32..OFFSET_LOOPS {
            let command = Blake2b::<512>::new()
                .update(&seed)
                .update(b"generation offset")
                .update(&i.to_le_bytes())
                .finalize();
            offsets_diff.extend(digest_to_u16s(&command))
        }
        assert_eq!(offsets_diff.len(), 32 * OFFSET_LOOPS as usize);

        let nb_chunks_bytes = output.len() / 64;
        let mut offsets_bytes = vec![0; nb_chunks_bytes];

        let offset_bytes_input = Blake2b::<512>::new()
            .update(&seed)
            .update(b"generation offset base")
            .finalize();
        argon2::hprime(&mut offsets_bytes, &offset_bytes_input);

        let offsets = offsets_bytes;

        let mut digest = Blake2b::<512>::new();
        let nb_source_chunks = (pre_size / 64) as u32;
        for (i, chunk) in output.chunks_mut(64).enumerate() {
            let start_idx = offsets[i % offsets.len()] as u32 % nb_source_chunks;

            let idx0 = (i as u32) % nb_source_chunks;
            let offset = (idx0 as usize).wrapping_mul(64);
            let input = &mixing_buffer[offset..offset + 64];
            chunk.copy_from_slice(input);

            for d in 1..mixing_numbers {
                let idx = start_idx.wrapping_add(offsets_diff[(d - 1) % offsets_diff.len()] as u32)
                    % nb_source_chunks;
                let offset = (idx as usize).wrapping_mul(64);
                let input = &mixing_buffer[offset..offset + 64];
                xorbuf(chunk, input);
            }

            digest.update_mut(chunk);
        }
        RomDigest(digest.finalize())
    } else {
        argon2::hprime(output, &seed);
        RomDigest(Blake2b::<512>::new().update(output).finalize())
    }
}

fn xorbuf(out: &mut [u8], input: &[u8]) {
    assert_eq!(out.len(), input.len());
    assert_eq!(out.len(), 64);
    /* implement xoring of all the bytes:
    for (o, i) in out.iter_mut().zip(input.iter()) {
        *o ^= i;
    }
    */
    let input = input.as_ptr() as *const u64;
    let out = out.as_mut_ptr() as *mut u64;
    unsafe {
        *out.offset(0) ^= *input.offset(0);
        *out.offset(1) ^= *input.offset(1);
        *out.offset(2) ^= *input.offset(2);
        *out.offset(3) ^= *input.offset(3);
        *out.offset(4) ^= *input.offset(4);
        *out.offset(5) ^= *input.offset(5);
        *out.offset(6) ^= *input.offset(6);
        *out.offset(7) ^= *input.offset(7);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rom_random_distribution() {
        let mut distribution = [0; 256];

        const SIZE: usize = 10 * 1_024 * 1_024;

        let rom = Rom::new(
            b"password",
            RomGenerationType::TwoStep {
                pre_size: 256 * 1024,
                mixing_numbers: 4,
            },
            SIZE,
        );

        for byte in rom.data {
            let index = byte as usize;
            distribution[index] += 1;
        }

        const R: usize = 3; // expect 3% range difference with the perfect average
        const AVG: usize = SIZE / 256;
        const MIN: usize = AVG * (100 - R) / 100;
        const MAX: usize = AVG * (100 + R) / 100;

        dbg!(&distribution);
        dbg!(MIN);
        dbg!(AVG);
        dbg!(MAX);

        assert!(
            distribution
                .iter()
                .take(u8::MAX as usize)
                .all(|&count| count > MIN && count < MAX)
        );
    }
}
