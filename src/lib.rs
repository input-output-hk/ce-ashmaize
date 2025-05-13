use cryptoxide::{
    hashing::blake2b::{self, Blake2b}, //kdf::argon2,
};

// 1 byte operator
// 3 bytes operands (src1, src2, dst)
// 28 bytes data
const INSTR_SIZE: usize = 32;
const NB_REGS: usize = 32; // need to be a power of two
const REGS_INDEX_MASK: u8 = NB_REGS as u8 - 1;

pub struct VM {
    regs: [u64; NB_REGS],
    ip: u32,
    data_digest: blake2b::Context<512>,
    counter: u32,
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
}

#[derive(Clone, Copy)]
pub enum Op2 {
    Neg,
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
            200..208 => Instr::Op3(Op3::Xor),
            208..216 => Instr::Op2(Op2::RotL),
            216..232 => Instr::Op2(Op2::RotR),
            232..240 => Instr::Op2(Op2::Neg),
            _ => Instr::Op3(Op3::Add),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Operand {
    Reg,
    Ip,
    Literal,
    Special,
}

impl From<u8> for Operand {
    fn from(value: u8) -> Self {
        match value {
            0..200 => Self::Reg,
            200..240 => Self::Literal,
            240..250 => Self::Ip,
            _ => Self::Special,
        }
    }
}

impl VM {
    pub fn new(seed_regs: &RomDigest, salt: &[u8]) -> Self {
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
        let ip = u32::from_le_bytes(*<&[u8; 4]>::try_from(&reg_digest[0..4]).unwrap());

        let data_digest = Blake2b::<512>::new().update(&reg_digest[4..]);

        Self {
            regs,
            ip,
            data_digest,
            counter: 0,
        }
    }

    fn step_finalize(&mut self, rom_chunk: &[u8]) {
        let mut context = Blake2b::<512>::new();
        context.update_mut(&self.counter.to_le_bytes());
        for r in self.regs {
            context.update_mut(&r.to_le_bytes());
        }
        let r = context.finalize();
        let ip = u32::from_le_bytes(*<&[u8; 4]>::try_from(&r[0..4]).unwrap());
        self.ip = self.ip.wrapping_add(ip);
        self.counter += 1;
        self.data_digest.update_mut(rom_chunk);
    }

    pub fn execute_one(&mut self, rom: &Rom) {
        let rom_chunk = rom.at(self.ip);
        execute_one_instruction(self, rom_chunk);
        self.step_finalize(rom_chunk);
    }

    pub fn execute(&mut self, rom: &Rom, instr: u32) {
        for _ in 0..instr {
            self.execute_one(rom)
        }
    }

    pub fn finalize(self) -> [u8; 64] {
        let data_digest = self.data_digest.finalize();
        let mut context = Blake2b::<512>::new().update(&data_digest);
        context.update_mut(&self.counter.to_le_bytes());
        for r in self.regs {
            context.update_mut(&r.to_le_bytes());
        }
        context.update_mut(&self.ip.to_le_bytes());
        context.finalize()
    }

    pub fn special_value64(&self) -> u64 {
        let r = self.data_digest.clone().finalize();
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
    pub fn new(key: &[u8], size: usize) -> Self {
        let mut data = vec![0; size];

        let seed = blake2b::Context::<256>::new()
            .update(&(data.len() as u32).to_le_bytes())
            .update(key)
            .finalize();
        let digest = random_gen(seed, &mut data);

        Self { digest, data }
    }

    pub fn at<'a>(&'a self, i: u32) -> &'a [u8; INSTR_SIZE] {
        let start = (i as usize).wrapping_mul(INSTR_SIZE) % self.data.len();
        <&[u8; INSTR_SIZE]>::try_from(&self.data[start..start + INSTR_SIZE]).unwrap()
    }
}

fn random_gen(seed: [u8; 32], output: &mut [u8]) -> RomDigest {
    use cryptoxide::kdf::argon2;

    argon2::hprime(output, &seed);
    /*
    use cryptoxide::drg;

    let mut drg = drg::chacha::Drg::<8>::new(&seed);
    drg.fill_slice(output);
    */
    let digest = RomDigest(Blake2b::<512>::new().update(&output).finalize());
    digest
}

fn execute_one_instruction(vm: &mut VM, rom_chunk: &[u8]) {
    let opcode = Instr::from(rom_chunk[0]);

    match opcode {
        Instr::Op3(operator) => {
            let op1 = Operand::from(rom_chunk[1]);
            let op2 = Operand::from(rom_chunk[2]);
            let op3 = Operand::from(rom_chunk[3]);

            let src1 = match op1 {
                Operand::Reg => vm.regs[(rom_chunk[4] & REGS_INDEX_MASK) as usize],
                Operand::Ip => vm.ip as u64,
                Operand::Literal => {
                    u64::from_le_bytes(*<&[u8; 8]>::try_from(&rom_chunk[4..12]).unwrap())
                }
                Operand::Special => vm.special_value64(),
            };
            let src2 = match op2 {
                Operand::Reg => vm.regs[(rom_chunk[12] & REGS_INDEX_MASK) as usize],
                Operand::Ip => vm.ip as u64,
                Operand::Literal => {
                    u64::from_le_bytes(*<&[u8; 8]>::try_from(&rom_chunk[12..20]).unwrap())
                }
                Operand::Special => vm.special_value64(),
            };

            let result = match operator {
                Op3::Add => src1.wrapping_add(src2),
                Op3::Mul => src1.wrapping_mul(src2),
                Op3::Xor => src1 ^ src2,
                Op3::MulH => ((src1 as u128 * src2 as u128) >> 64) as u64,
            };

            match op3 {
                Operand::Literal | Operand::Special | Operand::Reg => {
                    vm.regs[(rom_chunk[12] & REGS_INDEX_MASK) as usize] = result;
                }
                Operand::Ip => vm.ip = result as u32,
            }
        }
        Instr::Op2(operator) => {
            let op1 = Operand::from(rom_chunk[1]);
            let op2 = Operand::from(rom_chunk[2]);

            let src = match op1 {
                Operand::Reg => vm.regs[(rom_chunk[4] & REGS_INDEX_MASK) as usize],
                Operand::Ip => vm.ip as u64,
                Operand::Literal => {
                    u64::from_le_bytes(*<&[u8; 8]>::try_from(&rom_chunk[4..12]).unwrap())
                }
                Operand::Special => vm.special_value64(),
            };

            let result = match operator {
                Op2::Neg => !src,
                Op2::RotL => src.rotate_left(1),
                Op2::RotR => src.rotate_right(1),
            };

            match op2 {
                Operand::Literal | Operand::Special | Operand::Reg => {
                    vm.regs[(rom_chunk[12] & REGS_INDEX_MASK) as usize] = result;
                }
                Operand::Ip => vm.ip = result as u32,
            }
        }
    }
}

pub fn hash(salt: &[u8], rom: &Rom, nb_instrs: u32) -> [u8; 64] {
    let mut vm = VM::new(&rom.digest, salt);
    vm.execute(&rom, nb_instrs);
    vm.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_count_diff() {
        let rom = Rom::new(b"password1", 10_240);

        let h1 = hash(&0u128.to_be_bytes(), &rom, 10_000);
        let h2 = hash(&0u128.to_be_bytes(), &rom, 10_001);

        assert_ne!(h1, h2);
    }

    #[test]
    fn check_ip_stale() {
        let rom = Rom::new(b"password1", 10_240);

        let salt = &0u128.to_be_bytes();
        let nb_instrs = 100_000;
        let mut vm = VM::new(&rom.digest, salt);
        let mut prev_ip = 0;
        for i in 0..nb_instrs {
            let prev = vm.debug();
            vm.execute_one(&rom);
            assert_ne!(prev_ip, vm.ip, "instruction {}\n{}{}", i, prev, vm.debug());
            prev_ip = vm.ip;
        }
    }

    #[test]
    fn test() {
        const SIZE: usize = 10 * 1024 * 1024;
        const NB_INSTR: u32 = 256;

        let rom = Rom::new(b"123", SIZE);

        let h = hash(b"hello", &rom, NB_INSTR);
        println!("{:?}", h);
    }

    #[test]
    fn rom_random_distribution() {
        let mut distribution = [0; 256];

        const SIZE: usize = 1_024 * 1_024;

        let rom = Rom::new(b"password", SIZE);

        for byte in rom.data {
            let index = byte as usize;
            distribution[index] += 1;
        }

        const MIN: usize = SIZE / (u8::MAX as usize) - u8::MAX as usize;

        dbg!(&distribution);
        dbg!(MIN);

        assert!(
            distribution
                .iter()
                .take(u8::MAX as usize)
                .all(|&count| count > MIN)
        );
    }
}
