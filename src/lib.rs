use cryptoxide::{
    hashing::blake2b::{self, Blake2b},
    kdf::argon2,
};

// 1 byte operator
// 3 bytes operands (src1, src2, dst)
// 28 bytes data
const INSTR_SIZE: usize = 32;
const NB_REGS: usize = 32; // need to be a power of two
const REGS_INDEX_MASK: u8 = NB_REGS as u8 - 1;

pub struct VM {
    program: Program,
    regs: [u64; NB_REGS],
    ip: u32,
    prog_digest: blake2b::Context<512>,
    mem_digest: blake2b::Context<512>,
    counter: u32,
    memory_counter: u32,
    loop_counter: u32,
}

#[derive(Clone, Copy)]
pub enum Instr {
    Op3(Op3),
    Op2(Op2),
}

#[derive(Clone, Copy)]
pub enum Op3 {
    Add,
    Mul,
    MulH,
    Xor,
    Div,
    Mod,
}

#[derive(Clone, Copy)]
pub enum Op2 {
    ISqrt,
    Neg,
    BitRev,
    RotL,
    RotR,
}

// special encoding

impl From<u8> for Instr {
    fn from(value: u8) -> Self {
        match value {
            0..32 => Instr::Op3(Op3::Add),
            32..64 => Instr::Op3(Op3::Mul),
            64..72 => Instr::Op3(Op3::MulH),
            72..80 => Instr::Op2(Op2::ISqrt),
            80..90 => Instr::Op3(Op3::Div),
            90..100 => Instr::Op3(Op3::Mod),
            200..208 => Instr::Op3(Op3::Xor),
            208..216 => Instr::Op2(Op2::RotL),
            216..232 => Instr::Op2(Op2::RotR),
            232..240 => Instr::Op2(Op2::Neg),
            240..250 => Instr::Op2(Op2::Neg),
            _ => Instr::Op3(Op3::Add),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Operand {
    Reg,
    Memory,
    Ip,
    Literal,
    Special1,
    Special2,
}

impl From<u8> for Operand {
    fn from(value: u8) -> Self {
        match value {
            0..100 => Self::Reg,
            100..200 => Self::Memory,
            200..240 => Self::Literal,
            240..250 => Self::Ip,
            250..253 => Self::Special1,
            253..=255 => Self::Special2,
        }
    }
}

impl VM {
    pub fn new(seed_regs: &RomDigest, nb_instrs: u32, salt: &[u8]) -> Self {
        let seed = Blake2b::<512>::new()
            .update(&seed_regs.0)
            .update(salt)
            .finalize();
        let mut regs = [0; NB_REGS];
        for (i, regs) in regs.chunks_mut(8).enumerate() {
            let reg_out = Blake2b::<512>::new()
                .update(&seed)
                .update(&(i as u32).to_le_bytes())
                .finalize();
            for (reg_bytes, reg) in reg_out.chunks(8).zip(regs.iter_mut()) {
                *reg = u64::from_le_bytes(*<&[u8; 8]>::try_from(reg_bytes).unwrap())
            }
        }

        let reg_digest = {
            let mut context = Blake2b::<512>::new().update(&seed);
            for reg in regs {
                context.update_mut(&reg.to_le_bytes())
            }
            context.finalize()
        };
        //let ip = u32::from_le_bytes(*<&[u8; 4]>::try_from(&reg_digest[0..4]).unwrap());

        let program = Program::new(&seed, nb_instrs);

        let prog_digest = Blake2b::<512>::new().update(&reg_digest).update(b"program");
        let mem_digest = Blake2b::<512>::new().update(&reg_digest).update(b"memory");

        Self {
            program,
            regs,
            ip: 0,
            prog_digest,
            mem_digest,
            counter: 0,
            loop_counter: 0,
            memory_counter: 0,
        }
    }

    #[inline]
    fn post_step(&mut self) {
        /*
        let mut context = Blake2b::<512>::new();
        context.update_mut(&self.counter.to_le_bytes());
        for r in self.regs {
            context.update_mut(&r.to_le_bytes());
        }
        let r = context.finalize();
        */
        //let ip = u32::from_le_bytes(*<&[u8; 4]>::try_from(&r[0..4]).unwrap());
        self.ip = self.ip.wrapping_add(1);
        self.counter = self.counter.wrapping_add(1);
    }

    pub fn step(&mut self, rom: &Rom) {
        execute_one_instruction(self, rom);
        self.post_step();
    }

    pub fn pre_instructions(&mut self) {
        // todo
    }

    pub fn post_instructions(&mut self) {
        let mem_digest = self.mem_digest.clone().finalize();
        let mixing_value = Blake2b::<512>::new()
            .update(&mem_digest)
            .update(&self.loop_counter.to_le_bytes())
            .finalize();
        let mut mixing_out = vec![0; NB_REGS * 1024];
        argon2::hprime(&mut mixing_out, &mixing_value);

        for mem_chunks in mixing_out.chunks(NB_REGS * 8) {
            for (reg, reg_chunk) in self.regs.iter_mut().zip(mem_chunks.chunks(8)) {
                *reg ^= u64::from_le_bytes(*<&[u8; 8]>::try_from(reg_chunk).unwrap())
            }
        }

        /*
        for (i, regs) in self.regs.chunks_mut(8).enumerate() {
            let reg_out = Blake2b::<512>::new()
                .update(&mixing_value)
                .update(&(i as u32).to_le_bytes())
                .finalize();
            for (reg_bytes, reg) in reg_out.chunks(8).zip(regs.iter_mut()) {
                *reg ^= u64::from_le_bytes(*<&[u8; 8]>::try_from(reg_bytes).unwrap())
            }
        }
        */

        self.loop_counter = self.loop_counter.wrapping_add(1)
    }

    pub fn execute(&mut self, rom: &Rom, instr: u32) {
        self.pre_instructions();
        for _ in 0..instr {
            self.step(rom)
        }
        self.post_instructions()
    }

    pub fn finalize(self) -> [u8; 64] {
        let data_digest = self.prog_digest.finalize();
        let mut context = Blake2b::<512>::new().update(&data_digest);
        context.update_mut(&self.counter.to_le_bytes());
        for r in self.regs {
            context.update_mut(&r.to_le_bytes());
        }
        context.update_mut(&self.ip.to_le_bytes());
        context.finalize()
    }

    pub fn special_value64(&self) -> u64 {
        let r = self.prog_digest.clone().finalize();
        u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
    }

    #[allow(dead_code)]
    pub(crate) fn debug(&self) -> String {
        let mut out = String::new();
        for (i, r) in self.regs.iter().enumerate() {
            out.push_str(&format!("[{:02x}] {:016x} ", i, r));
            if (i % 4) == 3 {
                out.push_str("\n");
            }
        }
        out.push_str(&format!(
            "ip {:08x} counter {:08x}\n",
            self.ip, self.counter
        ));
        out
    }
}

pub struct RomDigest([u8; 64]);

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

    pub fn at<'a>(&'a self, i: u32) -> &'a [u8; INSTR_SIZE] {
        let start = (i as usize).wrapping_mul(INSTR_SIZE) % self.data.len();
        <&[u8; INSTR_SIZE]>::try_from(&self.data[start..start + INSTR_SIZE]).unwrap()
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
            /*
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
        /*
        let offsets = offsets_bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes(*<&[u8; 2]>::try_from(c).unwrap()))
            .collect::<Vec<_>>();
            */

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
    /*
    use cryptoxide::drg;
    let mut drg = drg::chacha::trg::<8>::new(&seed);
    drg.fill_slice(output);
    */
}

pub struct Program {
    instructions: Vec<u8>,
}

impl Program {
    pub fn new(seed: &[u8], nb_instrs: u32) -> Self {
        let mut instructions = vec![0; nb_instrs as usize * INSTR_SIZE];
        argon2::hprime(&mut instructions, &seed);
        Self { instructions }
    }

    pub fn at<'a>(&'a self, i: u32) -> &'a [u8; INSTR_SIZE] {
        let start = (i as usize).wrapping_mul(INSTR_SIZE) % self.instructions.len();
        <&[u8; INSTR_SIZE]>::try_from(&self.instructions[start..start + INSTR_SIZE]).unwrap()
    }
}

fn execute_one_instruction(vm: &mut VM, rom: &Rom) {
    let prog_chunk = *vm.program.at(vm.ip);
    let opcode = Instr::from(prog_chunk[0]);

    macro_rules! mem_access64 {
        ($vm:ident, $rom:ident, $addr:ident) => {{
            let mem = rom.at($addr as u32);
            $vm.mem_digest.update_mut(mem);
            $vm.memory_counter = $vm.memory_counter.wrapping_add(1);

            let idx = ($vm.memory_counter % (64 / 8)) as usize;
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&mem[idx..idx + 8]).unwrap())
        }};
    }

    macro_rules! special1_value64 {
        ($vm:ident) => {{
            let r = vm.prog_digest.clone().finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
        }};
    }

    macro_rules! special2_value64 {
        ($vm:ident) => {{
            let r = vm.mem_digest.clone().finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
        }};
    }

    match opcode {
        Instr::Op3(operator) => {
            let op1 = Operand::from(prog_chunk[1]);
            let op2 = Operand::from(prog_chunk[2]);

            let lit1 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&prog_chunk[4..12]).unwrap());
            let lit2 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&prog_chunk[12..20]).unwrap());

            let src1 = match op1 {
                Operand::Reg => vm.regs[(prog_chunk[4] & REGS_INDEX_MASK) as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Ip => vm.ip as u64,
                Operand::Literal => lit1,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };
            let src2 = match op2 {
                Operand::Reg => vm.regs[(prog_chunk[12] & REGS_INDEX_MASK) as usize],
                Operand::Memory => mem_access64!(vm, rom, lit2),
                Operand::Ip => vm.ip as u64,
                Operand::Literal => lit2,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op3::Add => src1.wrapping_add(src2),
                Op3::Mul => src1.wrapping_mul(src2),
                Op3::Xor => src1 ^ src2,
                Op3::MulH => ((src1 as u128 * src2 as u128) >> 64) as u64,
                Op3::Div => {
                    if src2 == 0 {
                        special1_value64!(vm)
                    } else {
                        src1 / src2
                    }
                }
                Op3::Mod => {
                    if src2 == 0 {
                        special1_value64!(vm)
                    } else {
                        src1 / src2
                    }
                }
            };

            vm.regs[(prog_chunk[12] & REGS_INDEX_MASK) as usize] = result;
        }
        Instr::Op2(operator) => {
            let op1 = Operand::from(prog_chunk[1]);

            let lit1 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&prog_chunk[4..12]).unwrap());

            let src = match op1 {
                Operand::Reg => vm.regs[(prog_chunk[4] & REGS_INDEX_MASK) as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Ip => vm.ip as u64,
                Operand::Literal => {
                    u64::from_le_bytes(*<&[u8; 8]>::try_from(&prog_chunk[4..12]).unwrap())
                }
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op2::Neg => !src,
                Op2::RotL => src.rotate_left(1),
                Op2::RotR => src.rotate_right(1),
                Op2::ISqrt => src.isqrt(),
                Op2::BitRev => src.reverse_bits(),
            };

            vm.regs[(prog_chunk[12] & REGS_INDEX_MASK) as usize] = result;
        }
    }
    vm.prog_digest.update_mut(&prog_chunk);
}

pub fn hash(salt: &[u8], rom: &Rom, nb_loops: u32, nb_instrs: u32) -> [u8; 64] {
    let mut vm = VM::new(&rom.digest, nb_instrs, salt);
    for _ in 0..nb_loops {
        vm.execute(&rom, nb_instrs);
    }
    vm.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_count_diff() {
        let rom = Rom::new(b"password1", 1024, 10_240);

        let h1 = hash(&0u128.to_be_bytes(), &rom, 8, 128);
        let h2 = hash(&0u128.to_be_bytes(), &rom, 8, 129);

        assert_ne!(h1, h2);
    }

    /*
    #[test]
    fn check_ip_stale() {
        let rom = Rom::new(b"password1", 1024, 10_240);

        let salt = &0u128.to_be_bytes();
        let nb_instrs = 100_000;
        let mut vm = VM::new(&rom.digest, nb_instrs, salt);
        for i in 0..nb_instrs {
            let prev = vm.debug();
            vm.step(&rom);
        }
    }
    */

    #[test]
    fn test() {
        const SIZE: usize = 10 * 1024 * 1024;
        const NB_INSTR: u32 = 256;

        let rom = Rom::new(b"123", 1024, SIZE);

        let h = hash(b"hello", &rom, 8, NB_INSTR);
        println!("{:?}", h);
    }

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
