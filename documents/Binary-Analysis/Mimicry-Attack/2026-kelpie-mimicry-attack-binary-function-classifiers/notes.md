# Notes

## One-paragraph Summary

Kelpie proposes a black-box, zero-query targeted mimicry attack against binary function classifiers. Given a payload function `p` and a target function `t`, it rewrites `p` into a semantically equivalent adversarial payload `p_adv^(t)` that looks structurally and syntactically like `t` to binary similarity/classification models. The pipeline has two stages: `KelpieCF`, which aligns the payload control-flow structure with the target at source/AST level, and `KelpieASM`, which aligns instruction-level distributions at compiler-generated assembly level while preserving semantics through liveness-based insertion safety.

## Problem and Motivation

Binary function classifiers are increasingly used for vulnerability detection, malware identification, clone detection, and provenance checking. Kelpie's key critique is that these classifiers often treat CFG shape and instruction distribution as semantic proxies. A targeted mimicry attack is stronger than ordinary evasion: the payload is not merely pushed away from its original class, but toward a specific chosen target such as a patched function or a benign payload.

## KelpieCF Implementation Path

KelpieCF operates before compilation, on the C source/AST representation of payload `p_src` and target `t_src` (Section 3.2, Algorithm 1). The implementation path is:

1. Parse payload and target source into AST/IR that exposes control structures such as `if`, `while`, `break`, `continue`, and `end`.
2. Traverse payload and target control-structure trees recursively with a matching procedure.
3. When a target control node has no corresponding payload node, insert a dummy control structure into the payload.
4. Guard inserted dummy basic blocks with an opaque predicate implemented in the prototype as a global "dead" flag.
5. Compile the resulting payload source. The intended result is a one-to-one correspondence between target basic blocks and transformed payload basic blocks.

The core invariant is semantic preservation: inserted blocks are unreachable, no original live block is changed, and no new executable path should affect payload state. The practical constraint is that the payload must have no more control-structure nodes than the target, or the attacker must split the payload / choose a larger target.

## KelpieASM Implementation Path

KelpieASM runs after KelpieCF and before final binary assembly/linking (Section 3.3). It does not rewrite linked binaries; it edits compiler-generated assembly source, such as output from `gcc -S`. This avoids fixed-offset relocation headaches because the assembler/linker later recompute labels, offsets, and relocation entries.

The implementation path is:

1. Compile both `KelpieCF(p_src, t_src)` and `t_src` to assembly, not final linked binaries.
2. Build basic-block mappings from target blocks to transformed payload blocks using the one-to-one control-flow correspondence produced by KelpieCF.
3. Compute opcode/instruction histograms for each target block and its mapped payload block.
4. For each instruction/opcode overrepresented in the target, choose candidate target instructions to insert into the mapped payload block.
5. Use a backward, flow-sensitive liveness analysis over assembly CFG instructions to compute admissible insertion positions.
6. Insert only instructions whose written registers and flags are dead at the insertion point.
7. Exclude dangerous live-region instructions: memory writes, stack manipulation (`push`, `pop`), control transfers (`jmp`, `call`, `ret`), and architecture-dependent side-effect instructions.
8. Copy instructions from target dummy/dead blocks directly into corresponding dead payload blocks, where side effects cannot execute.
9. Assemble and link normally.

The paper says the prototype derives lightweight instruction semantics from Capstone. The liveness equation is the standard backward dataflow form: `OUT[i] = union IN[succ(i)]`, `IN[i] = (OUT[i] - DEF[i]) union USE[i]`. Appendix Algorithm 2 computes allowed insertion positions for each candidate instruction.

## Key Claims

- Kelpie does not need model queries, model architecture, parameters, or training data.
- KelpieCF alone is usually insufficient for targeted mimicry; CFG-only perturbation causes limited evasion but weak target drift.
- KelpieASM alone creates stronger evasion by changing opcode-level local syntax, but still cannot reliably steer embeddings to a chosen target.
- The full pipeline works because CFG-level alignment gives block correspondence, and assembly-level alignment fills those blocks with target-like instruction distributions.

## Evidence

The evaluation tests eight binary function classifiers: Asm2vec, CLAP, GGSNN, GMN, HermesSim, jTrans, Trex, and Zeek. On classification tasks, full Kelpie substantially drops AUC and reaches non-trivial targeted mimicry success. On retrieval tasks, perturbed payloads often rank closer to the target than to their original payload. The ablation study reports that KelpieCF alone leaves payloads strongly tied to their original class, while KelpieASM alone mainly induces evasion. Combining both produces the strongest targeted mimicry.

## Limitations

- Requires source-level access to payload and target in the described prototype.
- Target must be structurally large enough, or the payload must be split.
- Does not rewrite already-linked binaries.
- The evaluated functions do not include system-call-heavy APIs, so real-world side-effect-heavy code may complicate safe insertion and equivalence reasoning.
- The implementation was not yet public in this arXiv version; the paper says artifacts will be released upon acceptance.

## Implementation Questions to Verify

- How exactly does their AST preprocessing normalize C constructs beyond `if` and `while`?
- How do they recover precise basic-block correspondence after compiler optimization?
- Which Capstone instruction groups are treated as dangerous beyond the examples listed?
- How do they preserve ABI constraints around caller/callee-saved registers, flags, stack alignment, and inline assembly boundaries?
- Whether dead flag opaque predicates survive all compiler versions/optimization levels or require volatile/external linkage tricks.
