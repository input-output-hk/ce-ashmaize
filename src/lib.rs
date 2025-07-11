/*!
# Ashmaize: a widely portable ASIC resistant hash algorithm

AshMaize is a simple PoW that is somewhat ASIC resistant, yet relative simple to implement

# How to use

## The [`Rom`]

First you need to initialise the [`Rom`]. It is the _Read Only Memory_
and it is generated once and can be reused for different hash program.

```
use ashmaize::{Rom, RomGenerationType};

let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 16 * 1_024);
```

## [`hash`]

Now you can use the [`hash`] function to execute a random program against
the [`Rom`] that will generate a Digest.

```
use ashmaize::hash;
# use ashmaize::{Rom, RomGenerationType};
# let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 16 * 1_024);

let digest = hash(b"salt", &rom, 8, 256);
# assert_eq!(
#      digest,
#      [235, 220, 158, 74, 62, 237, 133, 94, 124, 169, 203, 136, 92, 215, 155, 192, 184, 92, 38, 178, 239, 136, 86, 107, 217, 67, 55, 139, 213, 54, 119, 250, 74, 22, 206, 130, 122, 243, 166, 213, 50, 12, 223, 87, 1, 155, 16, 126, 25, 7, 132, 26, 59, 31, 252, 67, 70, 45, 224, 220, 152, 104, 108, 56]
# );```

*/

mod rom;

use cryptoxide::{
    hashing::blake2b::{self, Blake2b},
    kdf::argon2,
};

use self::rom::RomDigest;
pub use self::rom::{Rom, RomGenerationType};

// 1 byte operator
// 3 bytes operands (src1, src2, dst)
// 28 bytes data
const INSTR_SIZE: usize = 20;
const NB_REGS: usize = 1 << REGS_BITS;
const REGS_BITS: usize = 5;
const REGS_INDEX_MASK: u8 = NB_REGS as u8 - 1;

/// The `Ashmaize`'s virtual machine
struct VM {
    program: Program,
    regs: [u64; NB_REGS],
    ip: u32,
    prog_digest: blake2b::Context<512>,
    mem_digest: blake2b::Context<512>,
    memory_counter: u32,
    loop_counter: u32,
}

#[derive(Clone, Copy)]
enum Instr {
    Op3(Op3),
    Op2(Op2),
}

#[derive(Clone, Copy)]
enum Op3 {
    Add,
    Mul,
    MulH,
    Xor,
    Div,
    Mod,
}

#[derive(Clone, Copy)]
enum Op2 {
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
            64..96 => Instr::Op3(Op3::MulH),
            96..112 => Instr::Op2(Op2::ISqrt),
            112..134 => Instr::Op3(Op3::Div),
            134..152 => Instr::Op3(Op3::Mod),
            152..192 => Instr::Op2(Op2::BitRev),
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
enum Operand {
    Reg,
    Memory,
    Literal,
    Special1,
    Special2,
}

impl From<u8> for Operand {
    fn from(value: u8) -> Self {
        assert!(value <= 0x0f);
        match value {
            0..5 => Self::Reg,
            5..9 => Self::Memory,
            9..13 => Self::Literal,
            13..14 => Self::Special1,
            14.. => Self::Special2,
        }
    }
}

impl VM {
    /// Create a new VM which is specific to the ROM by using the RomDigest,
    /// but mainly dependent on the salt which is an arbitrary byte content
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

        let program = Program::new(&seed, nb_instrs);

        let prog_digest = Blake2b::<512>::new().update(&reg_digest).update(b"program");
        let mem_digest = Blake2b::<512>::new().update(&reg_digest).update(b"memory");

        Self {
            program,
            regs,
            ip: 0,
            prog_digest,
            mem_digest,
            loop_counter: 0,
            memory_counter: 0,
        }
    }

    pub fn step(&mut self, rom: &Rom) {
        execute_one_instruction(self, rom);
        self.ip = self.ip.wrapping_add(1);
    }

    pub fn post_instructions(&mut self, is_final: bool) {
        let prog_digest = self.prog_digest.clone().finalize();
        let mem_digest = self.mem_digest.clone().finalize();
        let mixing_value = Blake2b::<512>::new()
            .update(&prog_digest)
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

        if !is_final {
            self.program.shuffle(&prog_digest)
        }

        self.loop_counter = self.loop_counter.wrapping_add(1)
    }

    pub fn execute(&mut self, rom: &Rom, instr: u32, final_loop: bool) {
        for _ in 0..instr {
            self.step(rom)
        }
        self.post_instructions(final_loop)
    }

    pub fn finalize(self) -> [u8; 64] {
        let prog_digest = self.prog_digest.finalize();
        let mem_digest = self.mem_digest.finalize();
        let mut context = Blake2b::<512>::new()
            .update(&prog_digest)
            .update(&mem_digest);
        for r in self.regs {
            context.update_mut(&r.to_le_bytes());
        }
        context.finalize()
    }

    #[allow(dead_code)]
    pub(crate) fn debug(&self) -> String {
        let mut out = String::new();
        for (i, r) in self.regs.iter().enumerate() {
            out.push_str(&format!("[{i:02x}] {r:016x} "));
            if (i % 4) == 3 {
                out.push('\n');
            }
        }
        out.push_str(&format!("ip {:08x}\n", self.ip,));
        out
    }
}

struct Program {
    instructions: Vec<u8>,
}

impl Program {
    pub fn new(seed: &[u8], nb_instrs: u32) -> Self {
        let size = nb_instrs as usize * INSTR_SIZE;
        let mut instructions = vec![0; size];
        argon2::hprime(&mut instructions, seed);
        Self { instructions }
    }

    pub fn at(&self, i: u32) -> &[u8; INSTR_SIZE] {
        let start = (i as usize).wrapping_mul(INSTR_SIZE) % self.instructions.len();
        <&[u8; INSTR_SIZE]>::try_from(&self.instructions[start..start + INSTR_SIZE]).unwrap()
    }

    pub fn shuffle(&mut self, seed: &[u8]) {
        argon2::hprime(&mut self.instructions, seed)
    }
}

fn execute_one_instruction(vm: &mut VM, rom: &Rom) {
    let prog_chunk = *vm.program.at(vm.ip);

    macro_rules! mem_access64 {
        ($vm:ident, $rom:ident, $addr:ident) => {{
            let mem = rom.at($addr as u32);
            $vm.mem_digest.update_mut(mem);
            $vm.memory_counter = $vm.memory_counter.wrapping_add(1);

            // divide memory access into 8 chunks of 8 bytes
            let idx = (($vm.memory_counter % (64 / 8)) as usize) * 8;
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&mem[idx..idx + 8]).unwrap())
        }};
    }

    macro_rules! special1_value64 {
        ($vm:ident) => {{
            let r = $vm.prog_digest.clone().finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
        }};
    }

    macro_rules! special2_value64 {
        ($vm:ident) => {{
            let r = $vm.mem_digest.clone().finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&r[0..8]).unwrap())
        }};
    }

    let opcode = Instr::from(prog_chunk[0]);
    let op1 = Operand::from(prog_chunk[1] >> 4);
    let op2 = Operand::from(prog_chunk[1] & 0x0f);

    let rs = ((prog_chunk[2] as u16) << 8) | (prog_chunk[3] as u16);
    let r1 = ((rs >> (2 * REGS_BITS)) as u8) & REGS_INDEX_MASK;
    let r2 = ((rs >> REGS_BITS) as u8) & REGS_INDEX_MASK;
    let r3 = (rs as u8) & REGS_INDEX_MASK;

    let lit1 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&prog_chunk[4..12]).unwrap());
    let lit2 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&prog_chunk[12..20]).unwrap());

    match opcode {
        Instr::Op3(operator) => {
            let src1 = match op1 {
                Operand::Reg => vm.regs[r1 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Literal => lit1,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };
            let src2 = match op2 {
                Operand::Reg => vm.regs[r2 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit2),
                Operand::Literal => lit2,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op3::Add => src1.wrapping_add(src2),
                Op3::Mul => src1.wrapping_mul(src2),
                Op3::MulH => ((src1 as u128 * src2 as u128) >> 64) as u64,
                Op3::Xor => src1 ^ src2,
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

            vm.regs[r3 as usize] = result;
        }
        Instr::Op2(operator) => {
            let src1 = match op1 {
                Operand::Reg => vm.regs[r1 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Literal => lit1,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op2::Neg => !src1,
                Op2::RotL => src1.rotate_left(r1 as u32),
                Op2::RotR => src1.rotate_right(r1 as u32),
                Op2::ISqrt => src1.isqrt(),
                Op2::BitRev => src1.reverse_bits(),
            };
            vm.regs[r3 as usize] = result;
        }
    }
    vm.prog_digest.update_mut(&prog_chunk);
}

/// For the given [`Rom`] and parameter, compute the digest of the given `salt`
///
/// # Example
///
/// ```
/// # use ashmaize::{Rom, RomGenerationType, hash};
/// # const KB: usize = 1_024;
/// # let rom = Rom::new(b"seed", RomGenerationType::FullRandom, 16 * KB);
/// const NB_LOOPS: u32 = 8;
/// const NB_INSTRS: u32 = 256;
/// let digest = hash(b"salt", &rom, NB_LOOPS, NB_INSTRS);
/// # assert_eq!(
/// #      digest,
/// #      [235, 220, 158, 74, 62, 237, 133, 94, 124, 169, 203, 136, 92, 215, 155, 192, 184, 92, 38, 178, 239, 136, 86, 107, 217, 67, 55, 139, 213, 54, 119, 250, 74, 22, 206, 130, 122, 243, 166, 213, 50, 12, 223, 87, 1, 155, 16, 126, 25, 7, 132, 26, 59, 31, 252, 67, 70, 45, 224, 220, 152, 104, 108, 56]
/// # );
/// ```
///
pub fn hash(salt: &[u8], rom: &Rom, nb_loops: u32, nb_instrs: u32) -> [u8; 64] {
    let mut vm = VM::new(&rom.digest, nb_instrs, salt);
    for i in 0..nb_loops {
        let final_loop = i == nb_loops - 1;
        vm.execute(rom, nb_instrs, final_loop);
    }
    vm.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_count_diff() {
        let rom = Rom::new(
            b"password1",
            RomGenerationType::TwoStep {
                pre_size: 1024,
                mixing_numbers: 4,
            },
            10_240,
        );

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
        const PRE_SIZE: usize = 16 * 1024;
        const SIZE: usize = 10 * 1024 * 1024;
        const NB_INSTR: u32 = 256;

        let rom = Rom::new(
            b"123",
            RomGenerationType::TwoStep {
                pre_size: PRE_SIZE,
                mixing_numbers: 4,
            },
            SIZE,
        );

        let h = hash(b"hello", &rom, 8, NB_INSTR);
        println!("{:?}", h);
    }

    #[test]
    fn test_eq() {
        const PRE_SIZE: usize = 16 * 1024;
        const SIZE: usize = 10 * 1024 * 1024;
        const NB_INSTR: u32 = 256;

        const EXPECTED: [u8; 64] = [
            165, 176, 206, 3, 53, 6, 210, 199, 204, 8, 95, 178, 189, 0, 216, 41, 59, 186, 178, 244,
            224, 2, 136, 33, 85, 149, 238, 107, 30, 85, 172, 145, 242, 237, 234, 198, 122, 121,
            110, 95, 227, 208, 118, 57, 243, 216, 38, 146, 132, 58, 44, 203, 183, 194, 111, 13, 37,
            82, 123, 46, 226, 55, 75, 202,
        ];

        let rom = Rom::new(
            b"123",
            RomGenerationType::TwoStep {
                pre_size: PRE_SIZE,
                mixing_numbers: 4,
            },
            SIZE,
        );

        let h = hash(b"hello", &rom, 8, NB_INSTR);
        assert_eq!(h, EXPECTED);
    }
}
