//! The VM step as a [`fraud::Computer`](mattrs::fraud::Computer): the script
//! fragments that re-run one instruction on-chain, and their off-chain mirror.
//!
//! # Witness layout ("flattened specs")
//!
//! A step value is the element vector built by `Machine::step_witness`:
//!
//! ```text
//! [pc, acc, mem_root, mval, mem-proof (2L+1), fetch-proof (2K), op, arg]
//! ```
//!
//! Every spec is a *single* witness element — the `Leaf` script duplicates
//! `specs.len()` elements, so a multi-element spec (`MerkleProofType`) would
//! desynchronize it. The `encoder` commits only `(pc, acc, mem_root)` and
//! drops everything else; `func` consumes the whole layout and re-pads its
//! `(pc', acc', mem_root')` output with dummy elements so the encoder can run
//! identically on both sides of the step.
//!
//! # What the step script enforces
//!
//! 1. *Fetch*: `(op, arg)` hash to an instruction leaf whose Merkle walk (over
//!    the witness path) ends at the program's `code_root` — with the walk's
//!    direction bits accumulated into an index that must equal `pc`. Unlike
//!    the `ram` example, the path is *bound*: a prover cannot present a valid
//!    proof for the wrong instruction.
//! 2. *Dispatch* on `op`, rejecting anything outside the ISA.
//! 3. For `ADDM`/`LOAD`/`STORE`: a memory walk against `mem_root`, again with
//!    its direction bits bound — to the operand `arg` — plus, for reads,
//!    `sha256(bn(mval)) == leaf` so the revealed cell value is the committed
//!    one. `STORE` recomputes old and new roots simultaneously (the `ram`
//!    write walk).
//!
//! Direction bits feed `OP_IF`, so tapscript's MINIMALIF rule makes them
//! genuine booleans; adding a power-of-two weight per taken right-branch is
//! therefore a faithful index decomposition, with no `OP_MUL` needed.

use std::rc::Rc;
use std::sync::Arc;

use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};

use mattrs::argtypes::{BytesType, IntType};
use mattrs::contracts::ArgSpec;
use mattrs::fraud::Computer;
use mattrs::fraud::roles::{OffChainComputer, StepValue};
use mattrs::merkle::MerkleProof;
use mattrs::script_helpers::{concat, drop as script_drop, merkle_root};
use mattrs::script_utils::{bn2vch, commit_int, vch2bn};

use super::vm::{VmSpec, combine_hashes, element_hash};

define_pushable!();

/// The number of witness elements of one step value:
/// `4 + (2L + 1) + 2K + 2`.
pub fn n_elements(spec: &VmSpec) -> usize {
    2 * spec.code_depth() + 2 * spec.mem_depth() + 7
}

/// The [`Computer`] adjudicating one step of `spec`'s program (the `code_root`
/// is baked into the step script as a constant — the program is a parameter of
/// the computation, not contract state).
pub fn vm_computer(spec: &VmSpec) -> Computer {
    Computer {
        encoder: encoder_script(spec),
        func: func_script(spec),
        specs: step_specs(spec),
    }
}

/// One [`ArgSpec`] per witness element (see the module docs for why they must
/// all be single-element).
fn step_specs(spec: &VmSpec) -> Vec<ArgSpec> {
    let int = |name: String| ArgSpec {
        name,
        arg_type: Arc::new(IntType),
    };
    let bytes = |name: String| ArgSpec {
        name,
        arg_type: Arc::new(BytesType),
    };
    let mut specs = vec![
        int("pc".into()),
        int("acc".into()),
        bytes("mem_root".into()),
        int("mval".into()),
    ];
    for level in 1..=spec.mem_depth() {
        specs.push(bytes(format!("mp_h{level}")));
        specs.push(int(format!("mp_d{level}")));
    }
    specs.push(bytes("mp_x".into()));
    for level in 1..=spec.code_depth() {
        specs.push(bytes(format!("fp_h{level}")));
        specs.push(int(format!("fp_d{level}")));
    }
    specs.push(int("op".into()));
    specs.push(int("arg".into()));
    specs
}

/// `[pc, acc, mem_root, <rest>] -> merkle_root([sha256(pc), sha256(acc), mem_root])`,
/// hashing the raw elements (the minimal script-number encodings).
fn encoder_script(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        script_drop(n_elements(spec) - 3),
        script! {
            // [pc, acc, mem_root]
            OP_TOALTSTACK               // [pc, acc]                 alt: [mem_root]
            OP_SHA256                   // [pc, H(acc)]
            OP_SWAP OP_SHA256 OP_SWAP   // [H(pc), H(acc)]
            OP_FROMALTSTACK             // [H(pc), H(acc), mem_root]
            { merkle_root(3) }
        },
    ])
}

/// One Merkle-walk reduction that also accumulates the direction bit into the
/// index on the altstack: `[h, d, cur] -> [parent]`, `alt_idx += weight` when
/// `d` says the current node is the right child.
fn bound_read_layer(weight: i64) -> ScriptBuf {
    script! {
        OP_SWAP                     // [h, cur, d]
        OP_IF                       // right child: sibling goes left
            OP_FROMALTSTACK { weight } OP_ADD OP_TOALTSTACK
        OP_ELSE                     // left child: current goes left
            OP_SWAP
        OP_ENDIF
        OP_CAT OP_SHA256
    }
}

/// The `ram` write-walk layer (recompute old and new parents simultaneously),
/// plus the same index accumulation: `[h, d, old, new] -> [old', new']`.
fn bound_write_layer(weight: i64) -> ScriptBuf {
    script! {
        2 OP_ROLL                   // [h, old, new, d]
        OP_IF
            OP_FROMALTSTACK { weight } OP_ADD OP_TOALTSTACK
            2 OP_PICK               // [h, old, new, h]
            OP_SWAP OP_CAT OP_SHA256
            OP_SWAP
            OP_ROT
            OP_SWAP                 // [H(h||new), h, old]
        OP_ELSE
            2 OP_PICK               // [h, old, new, h]
            OP_CAT OP_SHA256
            OP_SWAP OP_ROT          // [H(new||h), old, h]
        OP_ENDIF
        OP_CAT OP_SHA256 OP_SWAP    // [old', new']
    }
}

/// The bound read walk shared by `ADDM` and `LOAD`, from the dispatch-branch
/// entry to a verified `[pc, acc, mem_root, mval]`.
fn read_walk(spec: &VmSpec) -> ScriptBuf {
    let mut parts = vec![script! {
        // [pc, acc, mem_root, mval, MP(2L+1)]          alt: [arg]
        OP_DUP OP_TOALTSTACK        // save the leaf     alt: [arg, mp_x]
        0 OP_TOALTSTACK             // walk index        alt: [arg, mp_x, idx]
    }];
    for level in 0..spec.mem_depth() {
        parts.push(bound_read_layer(1 << level));
    }
    parts.push(script! {
        // [pc, acc, mem_root, mval, root']
        2 OP_PICK OP_EQUALVERIFY    // root' == mem_root
        OP_FROMALTSTACK             // [.., mval, idx]   alt: [arg, mp_x]
        OP_FROMALTSTACK             // [.., mval, idx, mp_x]
        2 OP_PICK OP_SHA256
        OP_EQUALVERIFY              // sha256(bn(mval)) == the proven leaf
        OP_FROMALTSTACK
        OP_EQUALVERIFY              // idx == arg: the walk was for *this* cell
        // [pc, acc, mem_root, mval]
    });
    concat(&parts)
}

/// `pc += 1` under the top element: `[pc, acc, x] -> [pc + 1, acc, x]`.
fn advance_pc_under() -> ScriptBuf {
    script! {
        OP_ROT OP_1ADD              // [acc, x, pc+1]
        OP_ROT OP_ROT               // [pc+1, acc, x]
    }
}

/// The dispatch-branch prologue for instructions that touch no memory: drop
/// the (unverified, dummy) memory slots and fetch `arg`.
fn no_mem_prologue(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        script_drop(2 * spec.mem_depth() + 1),
        script! {
            OP_DROP                 // mval
            OP_FROMALTSTACK         // [pc, acc, mem_root, arg]
        },
    ])
}

// Per-instruction bodies. Entry stack: [pc, acc, mem_root, mval, MP(2L+1)],
// alt: [arg]. Exit stack: [pc', acc', mem_root'], alt empty.

fn addi_body(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        no_mem_prologue(spec),
        script! {
            OP_SWAP OP_TOALTSTACK   // [pc, acc, arg]    alt: [mem_root]
            OP_ADD                  // [pc, acc + arg]
            OP_SWAP OP_1ADD OP_SWAP
            OP_FROMALTSTACK
        },
    ])
}

fn addm_body(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        read_walk(spec),
        script! {
            OP_SWAP OP_TOALTSTACK   // [pc, acc, mval]   alt: [mem_root]
            OP_ADD
            OP_SWAP OP_1ADD OP_SWAP
            OP_FROMALTSTACK
        },
    ])
}

fn load_body(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        read_walk(spec),
        script! {
            OP_ROT OP_DROP          // [pc, mem_root, mval]
            OP_SWAP                 // [pc, mval, mem_root]
        },
        advance_pc_under(),
    ])
}

fn store_body(spec: &VmSpec) -> ScriptBuf {
    let mut parts = vec![script! {
        // [pc, acc, mem_root, mval, MP(2L+1)]           alt: [arg]
        { (2 * spec.mem_depth() + 3) as i64 } OP_PICK
        OP_SHA256                   // the new leaf, sha256(bn(acc))
        0 OP_TOALTSTACK             // walk index        alt: [arg, idx]
    }];
    for level in 0..spec.mem_depth() {
        parts.push(bound_write_layer(1 << level));
    }
    parts.push(script! {
        // [pc, acc, mem_root, mval, old_root, new_root]
        OP_SWAP
        3 OP_PICK OP_EQUALVERIFY    // old_root == mem_root
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_EQUALVERIFY              // idx == arg
        // [pc, acc, mem_root, mval, new_root]
        OP_SWAP OP_DROP
        OP_SWAP OP_DROP             // [pc, acc, new_root]
    });
    parts.push(advance_pc_under());
    concat(&parts)
}

fn jmp_body(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        no_mem_prologue(spec),
        script! {
            OP_SWAP OP_TOALTSTACK   // [pc, acc, arg]    alt: [mem_root]
            OP_ROT OP_DROP OP_SWAP  // [arg, acc]
            OP_FROMALTSTACK
        },
    ])
}

fn jz_body(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        no_mem_prologue(spec),
        script! {
            OP_SWAP OP_TOALTSTACK   // [pc, acc, arg]    alt: [mem_root]
            1 OP_PICK OP_NOT
            OP_IF                   // acc == 0: jump
                OP_ROT OP_DROP OP_SWAP
            OP_ELSE                 // fall through
                OP_DROP
                OP_SWAP OP_1ADD OP_SWAP
            OP_ENDIF
            OP_FROMALTSTACK
        },
    ])
}

fn halt_body(spec: &VmSpec) -> ScriptBuf {
    concat(&[
        script_drop(2 * spec.mem_depth() + 1),
        script! {
            OP_DROP                 // mval
            OP_FROMALTSTACK OP_DROP // arg
        },
    ])
}

/// `OP_DUP <op> OP_EQUAL OP_IF OP_DROP <body> OP_ELSE ... OP_ENDIF` chain over
/// the ISA; the final arm consumes the opcode with `OP_EQUALVERIFY`, so any
/// value outside the ISA fails the script (it also cannot appear in a
/// committed program, but the script should not rely on that alone).
fn dispatch(mut arms: Vec<(i64, ScriptBuf)>) -> ScriptBuf {
    let (last_op, last_body) = arms.pop().expect("the ISA is not empty");
    let mut acc = concat(&[script! { { last_op } OP_EQUALVERIFY }, last_body]);
    for (op, body) in arms.into_iter().rev() {
        acc = concat(&[
            script! { OP_DUP { op } OP_EQUAL OP_IF OP_DROP },
            body,
            script! { OP_ELSE },
            acc,
            script! { OP_ENDIF },
        ]);
    }
    acc
}

/// The full step: fetch (bound to `pc`), dispatch, execute, re-pad.
fn func_script(spec: &VmSpec) -> ScriptBuf {
    let code_root = spec.code_root();
    let mut parts = Vec::new();

    // --- instruction fetch --------------------------------------------------
    // [pc, acc, mem_root, mval, MP(2L+1), FP(2K), op, arg]
    parts.push(script! {
        OP_2DUP OP_TOALTSTACK OP_TOALTSTACK     //                alt: [arg, op]
        // insn leaf: sha256(sha256(bn(op)) || sha256(bn(arg)))
        OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP     // [H(op), H(arg)]
        OP_CAT OP_SHA256
        0 OP_TOALTSTACK                         // walk index     alt: [arg, op, idx]
    });
    for level in 0..spec.code_depth() {
        parts.push(bound_read_layer(1 << level));
    }
    parts.push(script! {
        // [pc, acc, mem_root, mval, MP(2L+1), root']
        { code_root } OP_EQUALVERIFY            // the instruction is in the program
        OP_FROMALTSTACK                         // the walked index
        { (2 * spec.mem_depth() + 5) as i64 } OP_PICK
        OP_EQUALVERIFY                          // ... at position pc
        OP_FROMALTSTACK                         // op             alt: [arg]
    });

    // --- dispatch & execute -------------------------------------------------
    parts.push(dispatch(vec![
        (1, addi_body(spec)),
        (2, addm_body(spec)),
        (3, load_body(spec)),
        (4, store_body(spec)),
        (5, jmp_body(spec)),
        (6, jz_body(spec)),
        (7, halt_body(spec)),
    ]));

    // --- re-pad to the step layout ------------------------------------------
    // [pc', acc', mem_root'] + dummies, so the encoder applies unchanged.
    let mut pad = Vec::new();
    for _ in 0..(n_elements(spec) - 3) {
        pad.push(script! { 0 });
    }
    parts.push(concat(&pad));

    concat(&parts)
}

// ============================================================================
// Off-chain mirror
// ============================================================================

/// The step value's fixed element positions.
fn offsets(spec: &VmSpec) -> (usize, usize, usize) {
    let mem_proof = 4;
    let op = mem_proof + 2 * spec.mem_depth() + 1 + 2 * spec.code_depth();
    (mem_proof, op, op + 1)
}

/// The off-chain twin of [`vm_computer`]'s fragments, for
/// [`fraud::roles`](mattrs::fraud::roles): must agree with the scripts on
/// every protocol-valid step value.
pub fn off_chain_computer(spec: &VmSpec) -> OffChainComputer {
    let spec_for_func = spec.clone();
    OffChainComputer {
        func: Rc::new(move |x| off_chain_step(&spec_for_func, x)),
        encode: Rc::new(|x| {
            combine_hashes(
                &combine_hashes(&element_hash(&x[0]), &element_hash(&x[1])),
                &x[2].clone().try_into().expect("mem_root is 32 bytes"),
            )
        }),
    }
}

fn off_chain_step(spec: &VmSpec, x: &StepValue) -> StepValue {
    let int = |bytes: &Vec<u8>| vch2bn(bytes).expect("a step element is a valid script number");
    let (mem_proof_at, op_at, arg_at) = offsets(spec);
    let pc = int(&x[0]);
    let acc = int(&x[1]);
    let mem_root: [u8; 32] = x[2].clone().try_into().expect("mem_root is 32 bytes");
    let mval = int(&x[3]);
    let (op, arg) = (int(&x[op_at]), int(&x[arg_at]));

    let (pc, acc, mem_root) = match op {
        1 => (pc + 1, acc + arg, mem_root),
        2 => (pc + 1, acc + mval, mem_root),
        3 => (pc + 1, mval, mem_root),
        4 => {
            // Recompute the new root exactly as the write walk does.
            let depth = spec.mem_depth();
            let hashes = (0..depth)
                .map(|i| x[mem_proof_at + 2 * i].clone().try_into().expect("32-byte proof hash"))
                .collect();
            let directions = (0..depth)
                .map(|i| int(&x[mem_proof_at + 2 * i + 1]) as u8)
                .collect();
            let leaf = x[mem_proof_at + 2 * depth]
                .clone()
                .try_into()
                .expect("32-byte proof leaf");
            let proof = MerkleProof::new(hashes, directions, leaf).expect("a valid step proof");
            (pc + 1, acc, proof.get_new_root_after_update(commit_int(acc)))
        }
        5 => (arg, acc, mem_root),
        6 => (if acc == 0 { arg } else { pc + 1 }, acc, mem_root),
        7 => (pc, acc, mem_root),
        other => panic!("op {other} is outside the ISA"),
    };

    let mut next = vec![bn2vch(pc), bn2vch(acc), mem_root.to_vec()];
    next.resize(n_elements(spec), Vec::new());
    next
}
