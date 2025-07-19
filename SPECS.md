# AshMaize

AshMaize is a proof of work (PoW) algorithm which was designed as a lightweight
ASIC-resistant algorithm that try to minizize the GAP between wasm and native
implementation. At an High level it is designed to be similar to RandomX.

```
Function AshMaize(key, value, preRomSize, romSize, nbInstructions, nbLoops)
    # Inputs:
    #   key:             Bytes
    #   value_to_hash:   Bytes
    #   preRomSize:      Integer (32..2^32-1)
    #   romSize:         Integer (32..2^32-1)
    #   nbInstructions:  Integer (128..2^32-1)
    #   nbLoops:         Integer (2..)
    # Output:
    #   digest:          Bytes (64 bytes)

    rom = Rom(key, preRomSize, romSize)
    rom-digest = Digest(rom)

    vm = VmInitialize(Mixing(rom-digest, value_to_hash))
    vmExecute(nbLoops, nbInstructions, vm, rom)
    return VmFinalize(vm)
```

## ROM generation

The ROM is randomly generated using the key at startup. The ROM needs to be large
with the benefits of increasing exponentially the difficulty to implement the algorithm
in an ASIC, where RAM latency and RAM cost will incur implementation and running cost.

The ROM is randomly accessed when running the program in 64 bytes chunk "cacheline"

From an utility point of view, the ROM is a deterministically byte string of random content
of specific size: `ROM = DRGB(key, size)`

The main design is to:

- random data that cannot be guessed or hardcoded
- depends on the key
- cannot be easily replaced by an algorithm
- the size of data needs to be retained is largely equivalent to the output size
  if wanting to make shortcuts by replacing by dynamic generation

Consequently we chose Argon2Hprime as a primitive, that works like a Hash based
DRG, and recursively generate random bytes by hashing hashes. This provides
absolute sequentiality and at any given sequence the ROM doesn't contains enough
information to generate the next sequence.

There is 2 ways to generate the ROM: a 1-step or a 2-steps approach

The 1-step using the highly sequential Argon2Hprime to instanciate the whole area.

The 2-steps approach, which is designed to reduce generation time, by creating a
pre-area of smaller size, that is randomly XOR'ed to produce the larger area.

It's recommended to use the 1-step approach, which is also the simplest
approach, when creating the ROM for a long time (1 hour or more) and that the
cost to create this ROM is amortized.

The 2-steps approach is more useful for testing and benchmarking, but also
reduce the ASIC resistance by reducing the amount of memory needed. Each final
chunks are re-combined with variable number of XORs from the pre area, so would
not reduce the need for fast prefetching from RAM.

```
Function Rom1Step(key, romSize)
  return argon2Hprime(LE32(romSize) | seed, romSize)

Function Rom2Steps(key, preRomSize, romSize)
    seed = Digest(LE32(romSize) | key)
    pre-rom = argon2Hprime(seed, preRomSize)

    for i in 0..4
        offset-diff[i] = u16s(Digest(seed | "generation offset" | LE32(i))

    offset-base = argon2Hprime(Digest(seed | "generation base"), romSize)

    rom = allocate(romSize)
    for i, chunk in chunks(64, rom)
        chunk = pre-rom[i]

        for d in 1..mixingNumbers
            chunk ^= pre-rom[i + offset-base[i] + offset-diff[i]]
    return rom
```

The ROM digest is the hash of all the bytes in the ROM:

```
Rom-Digest = Digest(ROM)
```

## Virtual Machine

The virtual machine execute an instruction set in a mutable context. It is
similar to a simplistic CPU. It is composed of:

* 32 64-bits registers
* Program counter (PC)
* 2 special hash digest accumulators: one for program (PROG_DIGEST used for special1) and one for memory (MEM_DIGST used for special2)
* a memory access counter (MC)
* a loop counter (LC)

### Initialization

The virtual machine state is deterministically generated from the rom digest and the salt
on first executing the VM. PC, MC and LC are all initialized to 0.

```
init_buffer = Argon2Hprime(32 * 8 + 3 * 64, rom_digest || salt)
```

where the init_buffer is mapped to the pattern:

```
REG[0] || REG[1] || ... || REGS[31] || DIGEST_INIT[0] || DIGEST_INIT[1] || PROG_SEED
where
  REG[N] is the little endian 64 bits value of a 8 bytes slice
  DIGEST_INIT[N] is a 64 bytes slice
  PROG_SEED is a 64 bytes slice
```

Finally we initialize each Digest context, with DIGEST_INIT[0] and DIGEST_INIT[1]
for PROG_DIGEST and MEM_DIGEST respectively.

```
PROG_DIGEST = DigestContext(DIGEST_INIT[0])
MEM_DIGEST = DigestContext(DIGEST_INIT[1])
```

### Execution

The main execution is composed of *nb_loops* loops that

1. generate a new program `ProgramGenerate`
2. execute all the instructions of the program `ProgramExecute`
3. mix the VM state `PostInstructions`

It follow the pseudo code:

```
Function vmExecute(nbLoops, nbInstructions, vm, rom)
  REPEAT nbLoops
    program = ProgramGenerate(PROG_SEED, nbInstructions)
    ProgramExecute(program)
    PostInstructions()

Function ProgramExecute(program)
  REPEAT nb_instructions
    instruction = InstructionDecode(program[PC])
    executeInstruction(instruction)

Function ProgramGenerate(PROG_SEED, nbInstructions)
  return Argon2Hprime(nbInstructions * INSTRUCTION_SIZE, PROG_SEED)

Function PostInstructions()
  sum_regs = REG[0] + REGS[1] + ... + REGS[NB_REGS-1]

  prog_value = DigestFinalize(DigestUpdate(PROG_DIGEST, LE(sum_regs))
  mem_value = DigestFinalize(DigestUpdate(MEM_DIGEST, LE(sum_regs))

  NB_MIXING = 32
  mixing = Argon2Hprime(NB_MIXING * NB_REGS * REGISTER_SIZE, Digest(prog_value || mem_value || LC))
  repeat NB_MIXING
    repeat all_registers
      REG[i] ^= LE(mixing[0..8])
      mixing += 8

  PROG_SEED = prog_digest
  LC += 1
```

### Finalization

Finalization produce a final hash value using a digest from multiple values from the VM state.

It uses the following pseudo code:

```
Function VmFinalize()
  return Digest(DigestFinalize(PROG_DIGEST) ||
                DigestFinalize(MEM_DIGEST) ||
                MC ||
                REG[0] || REG[1] || ... || REG[NB_REGS-1])
```

### Instructions

Instructions supported by the Virtual machines:

* *Add*: 64 bit integer addition between 3 operands `dst := src1 + src2`
* *Mul*: 64 bit integer multiplication, all overflow ignored `dst := (src1 * src2) % 2^64`
* *MulH*: 128 bit integer multiplication keeping only the highest 64 bits of a 128 bits: `dst := (src1 * src2) >> 64`
* *Div*: 64 bit integer division. if the divisor is 0, then the divisor is replaced by special-value1. `dst := src1 / src2`
* *Mod*: 64 bit integer modulus. if the divisor is 0, then the divisor is replaced by special-value1. `dst := src1 % src2`
* *Xor*: 64 bit bitwise xor. `dst = src1 ^ src2`
* *RotL*: 64 bit rotate left. `dst = src1 <<< src2`
* *RotR*: 64 bit rotate right. `dst = src1 >>> src2`
* *Sqrt*: 64 bit integer square root. `dst = sqrt(src1)`
* *Neg*: 64 bit bitwise negation. `dst = ~src1`
* *BitRev*: 64 bit bit-reversal. `dst = bitrev(src1)`
* *And*: 64 bit bitwise and. `dst = src1 & src2`
* *Hash[N]*: Nth 64 bit subslice of a 512 bit hash of sources, where N (0 <= N <= 7). `dst = blake2b(LE(src1) || LE(src2))[Nth 8 bytes chunk]`

| Instruction | Opcode Value         | Probabilities |
|-------------|----------------------|---------------|
| Add         | [0-40[               | ~15.6%        |
| Mul         | [40-80[              | ~15.6%        |
| MulH        | [80-96[              | 6.25%         |
| Div         | [96-112[             | 6.25%         |
| Mod         | [112-128[            | 6.25%         |
| ISqrt       | [128-138[            | ~3.9%         |
| BitRev      | [138-148[            | ~3.9%         |
| Xor         | [148-188[            | ~15.6%        |
| RotL        | [188-204[            | 6.25%         |
| RotR        | [204-220[            | 6.25%         |
| Neg         | [220-240[            | ~7.8%         |
| And         | [240-248[            | ~3.9%         |
| Hash[N]     | [248-256[            | ~3.9%         |

Note that the probabilities for each instructions are not uniform, since some
instructions are cheaper than some other. However it is also preferable that each
program contains at least 1 instruction of each type, which is why we don't lower
individual probability more than ~4%.

Also an attacker cannot benefits from choosing simpler instruction sets when
first generating, since the program is re-generated randomly at each instance of
the loop in an unpredictable way without executing all the instructions.

### Programs

Each instructions in a program is 20 bytes with the following meaning:

* *OpCode* (8 bits): the type of instruction to run
* *Source Operand1* (4 bits): the source type for the first operand of this instruction
* *Source Operand2* (4 bits): the source type for the second operand (if used) of this instruction
* 1 unused bit
* 3 Register Index of 5 bits each (15 bits):
  * *r1* : source 1 register used only if source operand1 is of register type
  * *r2* : source 2 register used only if source operand2 is of register type
  * *r3* : destination register
* *Source Lit1* (64 bits): use either as literal value or as a memory address for operand1
* *Source Lit2* (64 bits): same to Lit1 but for operand2

| Type        | OpCode | SOp1 | SOp2 | Unused | R1 | R2 | R3 | Lit1 | Lit2 |
|-------------|--------|------|------|--------|----|----|----|------|------|
| Size (bits) | 8      | 4    | 4    | 1      | 5  | 5  | 5  | 64   | 64   |

Source Operand (4 bits):

* Register : Value will be coming from a VM register, as specified by r1 or r2 depending on the operand number
* Memory : Value will be read from the ROM
* Literal : Value will be the literal
* Special1 : Value will be the program digest accumulator
* Special2 : Value will be the memory digest accumulator

| Source   | Value | Chances |
|----------|-------|---------|
| Register | 0-4   | 25%     |
| Memory   | 5-8   | 25%     |
| Literal  | 9-12  | 18.75%  |
| Special1 | 13-14 | 12.5%   |
| Special2 | 14-15 | 12.5%   |

Each memory read is using the lower 32 bits literal to index the 64 bytes data
line in the ROM. The data line is subsequently added to the memory digest in
full, but since we expect the operand to be a 64 bits value, the memory counter
is used to access the i'th 8 bytes chunk (modulo 64 bytes) of this 64 bytes data line.
The memory counter is incremented after each memory read, resulting in a
different part of the randomly accessed 64 bytes being used every time.

The program is composed of multiple instructions, that are executed
sequentially. The program is randomly generated using a deterministic generator using Argon2Hprime.

After each instruction, the instruction bytes is appended to the PROG_DIGEST context.

The full program execution is done multiple times, and between each iterations
we randomly generate a new full program.

### Auxiliary functions

```
Function Argon2Hprime(seed, size) =
    output = []
    V0 = Digest(LE32(size) | seed)
    output.append(V0[0..32])
    while output.len() > 64
       V[i+1] = Digest(V[i])
       output.append(V[i+1][0..32])
    V[last] = Digest(V[last-1])
    output.append(V[last][0..size - output.len()])
    return output

Function Digest(data) = Blake2b(data)
Function DigestUpdate(ctx, data) = Blake2bUpdate(ctx, data)
Function DigestFinalize(ctx) = Blake2bFinalize(ctx)
```
