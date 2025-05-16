use cryptoxide::{
    hashing::blake2b::{self, Blake2b},
    kdf::argon2,
};

pub const DATASET_ACCESS_SIZE: usize = 64;

pub struct RomDigest(pub(crate) [u8; 64]);

pub struct Rom {
    pub digest: RomDigest,
    data: Vec<u8>,
}

impl Rom {
    pub fn new(key: &[u8], pre_size: usize, size: usize) -> Self {
        let mut data = vec![0; size];

        let seed = blake2b::Context::<256>::new()
            .update(&(data.len() as u32).to_le_bytes())
            .update(key)
            .finalize();
        let digest = random_gen(pre_size, 4, seed, &mut data);

        Self { digest, data }
    }

    pub fn at<'a>(&'a self, i: u32) -> &'a [u8; DATASET_ACCESS_SIZE] {
        let start = (i as usize).wrapping_mul(DATASET_ACCESS_SIZE) % self.data.len();
        <&[u8; DATASET_ACCESS_SIZE]>::try_from(&self.data[start..start + DATASET_ACCESS_SIZE])
            .unwrap()
    }
}

fn random_gen(
    pre_size: usize,
    mixing_numbers: usize,
    seed: [u8; 32],
    output: &mut [u8],
) -> RomDigest {
    if true {
        assert!(pre_size.is_power_of_two());
        let mut mixing_buffer = vec![0; pre_size];

        argon2::hprime(&mut mixing_buffer, &seed);

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

        let mut digest = Blake2b::<512>::new();

        let mut offsets_diff = vec![];
        const OFFSET_LOOPS: u32 = 4;
        for i in 0u32..OFFSET_LOOPS {
            let command = Blake2b::<512>::new()
                .update(&seed)
                .update(b"generation offset")
                .update(&i.to_le_bytes())
                .finalize();
            let iter = command
                .chunks(2)
                .map(|c| u16::from_le_bytes(*<&[u8; 2]>::try_from(c).unwrap()));
            offsets_diff.extend(iter)
        }
        assert_eq!(offsets_diff.len(), 32 * OFFSET_LOOPS as usize);

        let nb_chunks_bytes = output.len() / 64;
        let mut offsets_bytes = vec![0; nb_chunks_bytes];
        argon2::hprime(&mut offsets_bytes, &seed);

        let offsets = offsets_bytes;

        let nb_source_chunks = (pre_size / 64) as u32;
        for (i, chunk) in output.chunks_mut(64).enumerate() {
            let start_idx = offsets[i % offsets.len()] as u32 % nb_source_chunks;

            // mixing_buffer % pre_size
            for d in 0..mixing_numbers {
                let idx = if d > 0 {
                    start_idx.wrapping_add(offsets_diff[(d - 1) % offsets_diff.len()] as u32)
                        % nb_source_chunks
                } else {
                    (i as u32) % nb_source_chunks
                };
                let offset = (idx as usize).wrapping_mul(64);
                let input = &mixing_buffer[offset..offset + 64];
                xorbuf(chunk, input);
            }

            digest.update_mut(chunk);
        }
        RomDigest(digest.finalize())
    } else {
        argon2::hprime(output, &seed);
        let digest = RomDigest(Blake2b::<512>::new().update(&output).finalize());
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rom_random_distribution() {
        let mut distribution = [0; 256];

        const SIZE: usize = 10 * 1_024 * 1_024;

        let rom = Rom::new(b"password", 256 * 1024, SIZE);

        for byte in rom.data {
            let index = byte as usize;
            distribution[index] += 1;
        }

        const R: usize = 2; // expect 2% range difference with the perfect average
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
