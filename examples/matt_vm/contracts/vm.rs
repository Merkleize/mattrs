//! The MATT-VM machine model: a tiny accumulator CPU whose execution traces are
//! adjudicated by the generic [`mattrs::fraud`] bisection.
//!
//! A machine state is `(pc, acc, mem)`: a program counter, one accumulator
//! register, and a fixed vector of integer memory cells. On-chain, a state is
//! committed as
//!
//! ```text
//! h = merkle_root([sha256(bn(pc)), sha256(bn(acc)), mem_root])
//! ```
//!
//! where `mem_root` is the Merkle root over per-cell leaves `sha256(bn(v))`,
//! and the program is committed as `code_root` over per-instruction leaves
//! `sha256(sha256(bn(op)) || sha256(bn(arg)))` — hashing the two script
//! numbers *separately* keeps the leaf unambiguous (concatenating variable-
//! length encodings would make e.g. `(op=5, arg=0)` and `(op=0, arg=5)`
//! collide).
//!
//! The instruction set:
//!
//! | op | name    | semantics                                   |
//! |----|---------|---------------------------------------------|
//! | 1  | `ADDI`  | `acc += arg; pc += 1`                       |
//! | 2  | `ADDM`  | `acc += mem[arg]; pc += 1`                  |
//! | 3  | `LOAD`  | `acc = mem[arg]; pc += 1`                   |
//! | 4  | `STORE` | `mem[arg] = acc; pc += 1`                   |
//! | 5  | `JMP`   | `pc = arg`                                  |
//! | 6  | `JZ`    | `pc = arg if acc == 0 else pc + 1`          |
//! | 7  | `HALT`  | no-op (`pc` unchanged)                      |
//!
//! `HALT` is deliberately the identity step: a halted machine re-executes the
//! same (fetch-verifiable) `HALT` forever, which is how a trace is padded to
//! the power-of-two step count the bisection needs. There is no way to pad
//! *past* the program — `pc` never leaves the code, so every padding step still
//! has a valid instruction-fetch proof.
//!
//! Values are constrained to 31 bits ([`MAX_VALUE`]): every arithmetic result
//! must remain a valid 4-byte script-number *operand*, since the on-chain step
//! re-runs the same `OP_ADD` (a wider result would verify once but poison the
//! next step's arithmetic; the interpreter rejects such programs upfront).
//!
//! The code and memory sizes are fixed powers of two, so instruction-fetch and
//! memory-access Merkle proofs have constant depth and the step tapscript can
//! unroll them.

use bitcoin::hashes::{Hash, sha256};

use mattrs::merkle::{MerkleTree, is_power_of_2};
use mattrs::script_utils::{bn2vch, commit_int};

/// The largest magnitude the VM allows in `acc`, a memory cell, or an
/// immediate: any 31-bit value is a valid 4-byte script-number operand.
pub const MAX_VALUE: i64 = 0x7fff_ffff;

/// `sha256(left || right)` — re-exported convenience for state commitments.
pub use mattrs::merkle::combine_hashes;

/// The VM opcodes (their discriminant is the on-chain `op` script number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Addi = 1,
    Addm = 2,
    Load = 3,
    Store = 4,
    Jmp = 5,
    Jz = 6,
    Halt = 7,
}

/// One program instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub op: Op,
    pub arg: i64,
}

impl Insn {
    pub const fn new(op: Op, arg: i64) -> Self {
        Self { op, arg }
    }

    /// The instruction's code-tree leaf:
    /// `sha256(sha256(bn(op)) || sha256(bn(arg)))`.
    pub fn leaf(&self) -> [u8; 32] {
        combine_hashes(&commit_int(self.op as i64), &commit_int(self.arg))
    }
}

/// Errors from validating or executing a VM program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    /// Code and memory sizes must be powers of two (>= 2) so the fetch and
    /// memory Merkle walks have a fixed depth.
    BadGeometry { code: usize, mem: usize },
    /// The trace length must be a power of two for the bisection.
    BadStepCount(usize),
    /// `pc` left the code (a program not padded/terminated with `HALT`).
    PcOutOfRange { pc: i64, code: usize },
    /// A memory operand addressed a cell outside the memory.
    AddrOutOfRange { addr: i64, mem: usize },
    /// A value left the 31-bit range the on-chain arithmetic supports.
    Overflow { value: i64 },
    /// A `JMP`/`JZ` target outside the code.
    BadJumpTarget { target: i64, code: usize },
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadGeometry { code, mem } => write!(
                f,
                "code ({code}) and memory ({mem}) sizes must be powers of two >= 2"
            ),
            Self::BadStepCount(n) => write!(f, "step count {n} is not a power of two"),
            Self::PcOutOfRange { pc, code } => {
                write!(f, "pc {pc} outside the {code}-instruction code")
            }
            Self::AddrOutOfRange { addr, mem } => {
                write!(f, "address {addr} outside the {mem}-cell memory")
            }
            Self::Overflow { value } => write!(f, "value {value} exceeds the 31-bit VM range"),
            Self::BadJumpTarget { target, code } => {
                write!(f, "jump target {target} outside the {code}-instruction code")
            }
        }
    }
}

impl std::error::Error for VmError {}

/// A checked program + initial memory + trace length: everything that defines
/// one VM computation (the fraud-proof's public parameters).
#[derive(Debug, Clone)]
pub struct VmSpec {
    code: Vec<Insn>,
    mem0: Vec<i64>,
    n_steps: usize,
}

impl VmSpec {
    /// Validate geometry: power-of-two code/memory sizes (padding the code
    /// with `HALT` is the caller's choice, not silently done here) and a
    /// power-of-two step count.
    pub fn new(code: Vec<Insn>, mem0: Vec<i64>, n_steps: usize) -> Result<Self, VmError> {
        if code.len() < 2 || !is_power_of_2(code.len()) || mem0.len() < 2 || !is_power_of_2(mem0.len())
        {
            return Err(VmError::BadGeometry {
                code: code.len(),
                mem: mem0.len(),
            });
        }
        if n_steps < 2 || !is_power_of_2(n_steps) {
            return Err(VmError::BadStepCount(n_steps));
        }
        for value in &mem0 {
            check_value(*value)?;
        }
        Ok(Self {
            code,
            mem0,
            n_steps,
        })
    }

    pub fn code(&self) -> &[Insn] {
        &self.code
    }

    pub fn mem0(&self) -> &[i64] {
        &self.mem0
    }

    /// The number of steps every trace of this spec covers (a power of two).
    pub fn n_steps(&self) -> usize {
        self.n_steps
    }

    /// Depth of the instruction-fetch Merkle walk.
    pub fn code_depth(&self) -> usize {
        self.code.len().trailing_zeros() as usize
    }

    /// Depth of the memory-access Merkle walk.
    pub fn mem_depth(&self) -> usize {
        self.mem0.len().trailing_zeros() as usize
    }

    /// The committed program.
    pub fn code_tree(&self) -> MerkleTree {
        MerkleTree::new(self.code.iter().map(Insn::leaf).collect())
    }

    pub fn code_root(&self) -> [u8; 32] {
        self.code_tree().root()
    }

    /// The commitment to the (public) initial state `(pc=0, acc=0, mem0)`.
    pub fn h_start(&self) -> [u8; 32] {
        state_commit(0, 0, &mem_tree(&self.mem0).root())
    }

    /// Run the spec's computation honestly and return its trace.
    pub fn trace(&self) -> Result<VmTrace, VmError> {
        self.trace_with_fault(None)
    }

    /// Run the computation, optionally corrupting the accumulator after one
    /// step — the *coherent cheater*: every state after the fault is computed
    /// honestly *from* the corrupted state, so the trace's first wrong
    /// commitment is exactly `hs[fault.step + 1]` and a bisection lands on
    /// `fault.step`.
    pub fn trace_with_fault(&self, fault: Option<Fault>) -> Result<VmTrace, VmError> {
        let mut machine = Machine::new(self.mem0.clone());
        let mut hs = Vec::with_capacity(self.n_steps + 1);
        let mut xs = Vec::with_capacity(self.n_steps);
        for step in 0..self.n_steps {
            hs.push(machine.commit());
            xs.push(machine.step_witness(self)?);
            machine.step(&self.code)?;
            if let Some(fault) = &fault
                && fault.step == step
            {
                machine.acc = check_value(machine.acc + fault.delta)?;
            }
        }
        hs.push(machine.commit());
        Ok(VmTrace { hs, xs, machine })
    }
}

fn check_value(value: i64) -> Result<i64, VmError> {
    if value.abs() > MAX_VALUE {
        return Err(VmError::Overflow { value });
    }
    Ok(value)
}

/// The Merkle tree over a memory vector's per-cell leaves `sha256(bn(v))`.
pub fn mem_tree(mem: &[i64]) -> MerkleTree {
    MerkleTree::new(mem.iter().map(|v| commit_int(*v)).collect())
}

/// The on-chain commitment to a machine state:
/// `merkle_root([sha256(bn(pc)), sha256(bn(acc)), mem_root])`.
pub fn state_commit(pc: i64, acc: i64, mem_root: &[u8; 32]) -> [u8; 32] {
    combine_hashes(
        &combine_hashes(&commit_int(pc), &commit_int(acc)),
        mem_root,
    )
}

/// A deliberate trace corruption (see [`VmSpec::trace_with_fault`]).
#[derive(Debug, Clone, Copy)]
pub struct Fault {
    /// The step after which the accumulator is corrupted.
    pub step: usize,
    /// What gets added to the accumulator.
    pub delta: i64,
}

/// A live machine: the interpreter the traces come from.
#[derive(Debug, Clone)]
pub struct Machine {
    pub pc: i64,
    pub acc: i64,
    pub mem: Vec<i64>,
}

impl Machine {
    pub fn new(mem: Vec<i64>) -> Self {
        Self { pc: 0, acc: 0, mem }
    }

    /// This state's on-chain commitment.
    pub fn commit(&self) -> [u8; 32] {
        state_commit(self.pc, self.acc, &mem_tree(&self.mem).root())
    }

    fn fetch(&self, code: &[Insn]) -> Result<Insn, VmError> {
        usize::try_from(self.pc)
            .ok()
            .and_then(|pc| code.get(pc))
            .copied()
            .ok_or(VmError::PcOutOfRange {
                pc: self.pc,
                code: code.len(),
            })
    }

    fn cell(&self, addr: i64) -> Result<usize, VmError> {
        usize::try_from(addr)
            .ok()
            .filter(|addr| *addr < self.mem.len())
            .ok_or(VmError::AddrOutOfRange {
                addr,
                mem: self.mem.len(),
            })
    }

    fn jump_target(&self, target: i64, code: &[Insn]) -> Result<i64, VmError> {
        if target < 0 || target as usize >= code.len() {
            return Err(VmError::BadJumpTarget {
                target,
                code: code.len(),
            });
        }
        Ok(target)
    }

    /// Execute one instruction.
    pub fn step(&mut self, code: &[Insn]) -> Result<(), VmError> {
        let insn = self.fetch(code)?;
        match insn.op {
            Op::Addi => {
                self.acc = check_value(self.acc + insn.arg)?;
                self.pc += 1;
            }
            Op::Addm => {
                self.acc = check_value(self.acc + self.mem[self.cell(insn.arg)?])?;
                self.pc += 1;
            }
            Op::Load => {
                self.acc = self.mem[self.cell(insn.arg)?];
                self.pc += 1;
            }
            Op::Store => {
                let cell = self.cell(insn.arg)?;
                self.mem[cell] = self.acc;
                self.pc += 1;
            }
            Op::Jmp => self.pc = self.jump_target(insn.arg, code)?,
            Op::Jz => {
                self.pc = if self.acc == 0 {
                    self.jump_target(insn.arg, code)?
                } else {
                    self.pc + 1
                };
            }
            Op::Halt => {}
        }
        // A non-HALT final instruction would leave pc == code.len(): the next
        // fetch fails, so the error surfaces while building the trace, not
        // on-chain.
        Ok(())
    }

    /// The flattened witness elements the on-chain step consumes for *this*
    /// state (the pre-step snapshot):
    ///
    /// ```text
    /// [pc, acc, mem_root, mval, mem-proof (2L+1), fetch-proof (2K), op, arg]
    /// ```
    ///
    /// `mval` and the memory proof describe the addressed cell for
    /// `ADDM`/`LOAD`/`STORE`; for the other instructions the same slots carry a
    /// well-formed dummy (cell 0) that the script drops unverified. Every spec
    /// is a single witness element — the [`fraud::Leaf`](mattrs::fraud::Leaf)
    /// script duplicates `specs.len()` *elements*, so multi-element specs would
    /// break it.
    pub fn step_witness(&self, spec: &VmSpec) -> Result<Vec<Vec<u8>>, VmError> {
        let insn = self.fetch(&spec.code)?;
        let addr = match insn.op {
            Op::Addm | Op::Load | Op::Store => self.cell(insn.arg)?,
            _ => 0,
        };
        let mem_tree = mem_tree(&self.mem);
        let mem_proof = mem_tree
            .prove_leaf(addr)
            .expect("the cell index was just validated");
        let code_proof = spec
            .code_tree()
            .prove_leaf(self.pc as usize)
            .expect("fetch validated pc");

        let mut witness = vec![
            bn2vch(self.pc),
            bn2vch(self.acc),
            mem_tree.root().to_vec(),
            bn2vch(self.mem[addr]),
        ];
        witness.extend(mem_proof.to_wit_stack());
        // The fetch proof's leaf is recomputed on-chain from (op, arg); only
        // the path itself rides in the witness.
        let stack = code_proof.to_wit_stack();
        witness.extend(stack[..stack.len() - 1].iter().cloned());
        witness.push(bn2vch(insn.op as i64));
        witness.push(bn2vch(insn.arg));
        Ok(witness)
    }
}

/// A full claimed execution: the step commitments `h_0 ..= h_n`, the per-step
/// witness values, and the machine's final state.
#[derive(Debug, Clone)]
pub struct VmTrace {
    /// `n + 1` state commitments.
    pub hs: Vec<[u8; 32]>,
    /// `n` step witnesses ([`Machine::step_witness`] layout).
    pub xs: Vec<Vec<Vec<u8>>>,
    /// The machine after the last step (the *claim*: its `pc`, `acc`, and
    /// memory root are what a prover posts on-chain).
    pub machine: Machine,
}

impl VmTrace {
    /// The claimed output (the final accumulator).
    pub fn result(&self) -> i64 {
        self.machine.acc
    }

    /// The final state's components as posted in a claim:
    /// `(acc, pc, mem_root)`.
    pub fn claim(&self) -> (i64, i64, [u8; 32]) {
        (
            self.machine.acc,
            self.machine.pc,
            mem_tree(&self.machine.mem).root(),
        )
    }
}

/// The demo program: iterative Fibonacci.
///
/// Memory layout: `m[0] = a`, `m[1] = b`, `m[2] = n` (loop counter),
/// `m[3]` scratch. Each iteration advances `(a, b) -> (b, a + b)` and
/// decrements `n`; the result (`b` after `n` iterations, i.e. `fib(n + 1)`
/// from `(0, 1)`) is loaded into `acc` before halting.
pub fn fib_program() -> Vec<Insn> {
    use Op::*;
    let code = vec![
        Insn::new(Load, 2),  //  0: acc = n
        Insn::new(Jz, 12),   //  1: done when the counter hits zero
        Insn::new(Addi, -1), //  2: acc = n - 1
        Insn::new(Store, 2), //  3: n -= 1
        Insn::new(Load, 0),  //  4: acc = a
        Insn::new(Addm, 1),  //  5: acc = a + b
        Insn::new(Store, 3), //  6: scratch = a + b
        Insn::new(Load, 1),  //  7: acc = b
        Insn::new(Store, 0), //  8: a = b
        Insn::new(Load, 3),  //  9: acc = scratch
        Insn::new(Store, 1), // 10: b = a + b
        Insn::new(Jmp, 0),   // 11: next iteration
        Insn::new(Load, 1),  // 12: acc = b (the result)
        Insn::new(Halt, 0),  // 13: spin here forever
    ];
    pad_with_halt(code)
}

/// Pad a program with `HALT` up to the next power of two.
pub fn pad_with_halt(mut code: Vec<Insn>) -> Vec<Insn> {
    let target = code.len().next_power_of_two().max(2);
    code.resize(target, Insn::new(Op::Halt, 0));
    code
}

/// The demo spec: [`fib_program`] over `mem = [0, 1, n, 0]`, traced for
/// `n_steps` steps (64 covers `n <= 5` comfortably).
pub fn fib_spec(n: i64, n_steps: usize) -> Result<VmSpec, VmError> {
    VmSpec::new(fib_program(), vec![0, 1, n, 0], n_steps)
}

/// `sha256` of a raw witness element (how the on-chain encoder commits `pc`
/// and `acc`: hashing the element bytes, i.e. the minimal script-number
/// encoding).
pub fn element_hash(element: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(element).to_byte_array()
}
