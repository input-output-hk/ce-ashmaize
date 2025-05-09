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
    regs: [u64; NB_REGS],
    ip: u32,
    data_digest: blake2b::Context<512>,
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
    pub fn new(seed_regs: &[u8; 64], salt: &[u8]) -> Self {
        let seed = Blake2b::<512>::new()
            .update(seed_regs)
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
        }
    }

    fn step_finalize(&mut self, rom_chunk: &[u8]) {
        let mut context = Blake2b::<512>::new();
        for r in self.regs {
            context = context.update(&r.to_le_bytes());
        }
        let r = context.finalize();
        let ip = u32::from_le_bytes(*<&[u8; 4]>::try_from(&r[0..4]).unwrap());
        self.ip = self.ip.wrapping_add(ip);
        self.data_digest.update_mut(rom_chunk);
    }

    pub fn execute_one(&mut self, rom: &Rom) {
        let rom_chunk = rom.at(self.ip);
        execute_one_instruction(self, rom_chunk);
        self.step_finalize(rom_chunk);
    }

    pub fn special_value64(&self) -> u64 {
        let r = self.data_digest.clone().finalize();
        u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
    }

    pub fn execute(&mut self, rom: &Rom, instr: usize) {
        for _ in 0..instr {
            self.execute_one(rom)
        }
    }

    pub fn finalize(self) -> [u8; 64] {
        let data_digest = self.data_digest.finalize();
        let mut context = Blake2b::<512>::new().update(&data_digest);
        for r in self.regs {
            context.update_mut(&r.to_le_bytes());
        }
        context.update_mut(&self.ip.to_le_bytes());
        context.finalize()
    }
}

pub struct Rom {
    data_hash: [u8; 64],
    data: Vec<u8>,
}

impl Rom {
    pub fn new(password: &[u8], size: usize) -> Self {
        let mut data = vec![0; size];
        argon2::hprime(&mut data, password);
        let data_hash = Blake2b::<512>::new().update(&data).finalize();
        Self { data_hash, data }
    }

    pub fn at<'a>(&'a self, i: u32) -> &'a [u8; INSTR_SIZE] {
        let start = (i as usize).wrapping_mul(INSTR_SIZE) % self.data.len();
        <&[u8; INSTR_SIZE]>::try_from(&self.data[start..start + INSTR_SIZE]).unwrap()
    }
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

pub fn hash(salt: &[u8], rom: &Rom, nb_instrs: usize) -> [u8; 64] {
    // initialize the VM with the seed
    let mut vm = VM::new(&rom.data_hash, salt);

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

        //let h1 = hash(&0u128.to_be_bytes(), &rom, 75);
        //let h2 = hash(&0u128.to_be_bytes(), &rom, 76);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test() {
        const SIZE: usize = 10 * 1024 * 1024;
        const NB_INSTR: usize = 256;

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
