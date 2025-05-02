use cryptoxide::{hashing::blake2b::Blake2b, kdf::argon2};

// 1 byte operator
// 3 bytes operands (src1, src2, dst)
// 28 bytes data
const INSTR_SIZE: usize = 32;
const NB_REGS: usize = 32; // need to be a power of two
const REGS_INDEX_MASK: u8 = NB_REGS as u8 - 1;

pub struct VM {
    regs: [u64; NB_REGS],
    checksum: u64,
    ip: u32,
    instr_sum: u32,
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
}

// special encoding

impl From<u8> for Instr {
    fn from(value: u8) -> Self {
        match value {
            0..8 => Instr::Op3(Op3::Add),
            8..16 => Instr::Op3(Op3::Mul),
            0xfe => Instr::Op3(Op3::Xor),
            0xff => Instr::Op2(Op2::Neg),
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
        match value & 0b11 {
            0 => Self::Reg,
            1 => Self::Ip,
            2 => Self::Literal,
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
        for (i, reg) in regs.iter_mut().enumerate() {
            let mut reg_out = [0; 8];
            Blake2b::<64>::new()
                .update(&seed)
                .update(&(i as u32).to_le_bytes())
                .finalize_at(&mut reg_out);
            *reg = u64::from_le_bytes(reg_out)
        }

        let ip = regs
            .iter()
            .copied()
            .fold(0xffff_ffffu32, |acc, r| acc.wrapping_add(r as u32));

        let checksum = regs
            .iter()
            .copied()
            .fold(ip as u64, |acc, r| acc.wrapping_mul(r).wrapping_add(r >> 1));

        Self {
            regs,
            ip,
            checksum,
            instr_sum: 0,
        }
    }

    fn step_finalize(&mut self, instr: u32) {
        for r in self.regs {
            self.checksum = self.checksum.wrapping_mul(r).wrapping_add(r & 0xEDCB);
        }

        self.instr_sum = self.instr_sum.wrapping_add(instr);
        self.ip = self
            .ip
            .wrapping_mul((self.checksum >> 32) as u32)
            .wrapping_add(self.checksum as u32);
    }

    pub fn execute(&mut self, rom: &Rom, instr: usize) {
        //assert_eq!(rom.data.len(), SIZE);

        for _ in 0..instr {
            let instr_val = execute_one(self, rom);
            self.step_finalize(instr_val);
        }
    }

    pub fn finalize(&self) -> [u8; 64] {
        let mut out = [0u8; 64];

        let mut checksum = self.checksum;
        for r in self.regs {
            checksum = checksum.wrapping_mul(r);
        }
        let mut context = Blake2b::<512>::new().update(&checksum.to_le_bytes());
        for r in self.regs {
            context.update_mut(&r.to_le_bytes())
        }

        context.finalize_at(&mut out);
        out
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

fn execute_one(vm: &mut VM, rom: &Rom) -> u32 {
    let rom_chunk = rom.at(vm.ip);
    let instr_val = u32::from_le_bytes(*<&[u8; 4]>::try_from(&rom_chunk[0..4]).unwrap());

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
                Operand::Special => vm.checksum,
            };
            let src2 = match op2 {
                Operand::Reg => vm.regs[(rom_chunk[12] & REGS_INDEX_MASK) as usize],
                Operand::Ip => vm.ip as u64,
                Operand::Literal => {
                    u64::from_le_bytes(*<&[u8; 8]>::try_from(&rom_chunk[12..20]).unwrap())
                }
                Operand::Special => vm.checksum,
            };

            let result = match operator {
                Op3::Add => src1.wrapping_add(src2),
                Op3::Mul => src1.wrapping_mul(src2),
                Op3::Xor => src1.wrapping_mul(src2),
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
                Operand::Special => vm.checksum,
            };

            let result = match operator {
                Op2::Neg => !src,
            };

            match op2 {
                Operand::Literal | Operand::Special | Operand::Reg => {
                    vm.regs[(rom_chunk[12] & REGS_INDEX_MASK) as usize] = result;
                }
                Operand::Ip => vm.ip = result as u32,
            }
        }
    }

    instr_val
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
