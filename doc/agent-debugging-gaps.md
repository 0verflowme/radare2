# What stops an agent from debugging a real binary

Measured, not argued. Each finding below came from debugging real crackmes from
crackmes.one on Linux x86-64 with gdb 15.1 and radare2 6.2.0, driving the
debugger the way an automated agent must: one stateless invocation per step.

The fix for each is in [`doc/rdbg/`](rdbg/README.md).

## Method

An agent's tool call is a process boundary. `gdb -batch -x script` starts the
target, runs the script, and exits. Nothing survives. So the unit of cost is
not CPU time, it is **how many times the target had to be re-run to re-derive a
fact the agent already knew**.

Targets are stripped, position-independent, and in one case generate the code
under test at runtime, so no static analysis alone answers the question.

## Target 1: "not obfuscated" (difficulty 5.0, stripped PIE)

The name is a lie in a useful way. The binary is a compiler: it builds a
program into `mmap`'ed memory, calls `mprotect` to make it executable, reads 49
integers, and calls the generated code. The accept test lives entirely in code
that does not exist on disk.

It turned out to be a quantised neural digit classifier, 49 inputs to 64 to 64
to 10, with four 7x7 reference digits compiled in as immediate operands. The
accepting input is one the network classifies as 1.

Solved both ways. The findings are the difference between the two paths.

### Finding 1: an unscoped breakpoint on a libc function stops in the loader

`break mprotect` resolves to two locations, the PLT stub and libc's
`__GI_mprotect`. The first hit is not the program's call. It is
`_dl_protect_relro` inside the dynamic loader, during startup.

An agent that runs `break mprotect; run; print $rdi` gets `0x7ffff7dff000`,
which is the loader protecting its own relro segment. The real JIT base was
`0x7ffff7f92000`. Nothing in the output flags the difference, and both values
look equally plausible.

In this target the loader called `mprotect` six times before the program did.

**Fix.** `bp.set loc=mprotect caller_module=crackme` walks outward from the
breakpoint frame and stops only when the caller is in the named module. It
skipped the six loader calls and stopped on the program's.

### Finding 2: every address is hand-computed, and nothing names anything

Under a PIE binary the agent works with `0x555555555342` and has to know it is
`0x1342` plus a load base, maintain that arithmetic in its own notes, and redo
it whenever the base moves. radare2 reports static offsets, gdb reports runtime
addresses, and neither translates.

**Fix.** Logical locations. `@crackme+0x13d9` is accepted everywhere an address
is, and every reply carries both forms. A breakpoint set as
`@crackme+0x13d9` survives relaunch.

### Finding 3: runtime discoveries are thrown away on every call

The JIT function table has 28 entries of stride `0x70` with the code pointer at
`+0x60`. Extracting it requires a live process. It was extracted three separate
times during this investigation, identically, because the process holding it
exited between tool calls. Ten gdb invocations went into a solve that needed
about four distinct facts.

**Fix.** `note.set name=jit_base expr='$rdi'` stores a value together with the
position it was observed at, and later requests address memory as
`$jit_base+0x2828`.

### Finding 4: `set $sp = ...` silently corrupts the target

gdb's convenience variables share a namespace with registers. A script that
uses `$sp` for a VM stack pointer overwrites the real stack pointer. The error
surfaced four lines later as

    Argument to arithmetic operation not a number or boolean.

which names neither the variable nor the corruption. `$pc`, `$fp`, and every
architectural register name are the same trap.

**Fix.** Session state is named in its own namespace and `note.set` cannot
write a register.

### Finding 5: reading a register one instruction too early returns garbage

At `main+0x2df` the instruction *is* the load of `rdx`. Breaking there and
reading `$rdx` returns the previous value, and the agent reports a plausible
wrong number. Getting this right requires knowing whether a position is before
or after the instruction at it.

**Fix.** Partial. Snapshots include disassembly at the stop so the next
instruction is visible. A real before/after position model is the right answer
and is not implemented.

### Finding 6: calling a function in a stripped binary is guesswork

Turning the live target into an oracle needs a call into generated code. With
no debug info gdb has no type for the address, so the call must be cast by
hand. Of four plausible spellings, one failed with

    Argument to arithmetic operation not a number or boolean.

**Fix.** `call fn=$tmain args=[...] ret_type=long` builds the cast.

### Finding 7: a memory dump loses its own address

`dump binary memory jit.bin $base $end` writes bytes and nothing else. To
disassemble the result the agent must separately remember the base, then
reconstruct `r2 -a x86 -b 64 -m 0x7ffff7f92000 jit.bin`. Get the base wrong and
every call target in the listing is wrong, silently.

**Fix.** `mem.export` writes a sidecar with the base, the region permissions,
the logical location, and the exact radare2 command.

### What the difference costs

The same question, "find an accepting input", answered both ways:

| | stateless gdb | rdbg session |
| --- | --- | --- |
| target launches | 10 | 1 |
| times the JIT table was re-derived | 3 | 1 |
| wrong values accepted en route | 1 (loader's mprotect) | 0 |
| probes of the accept test | 1 per launch | 1500 in 4.3 s |

The last row is the one that changes what is possible. Holding the session
open makes the target callable at 266 calls per second, so the accept test
becomes a search oracle. A random walk restricted to accepting inputs found a
key differing from the author's embedded answer in 43 of 49 positions,
confirmed against the binary with no debugger attached. The same search through
`gdb -batch` is 1500 process launches.

## What this says about the build order

Recording and replay answer a different question than the one that was blocking
here. Nothing in this investigation needed reverse execution. It needed the
session to still be alive, the addresses to have names, and the target to be
callable.

That argues for session persistence, logical locations, and structured answers
first, and for record/replay to be admitted afterwards as one backend among
several, labelled by what it preserves.

One caveat worth keeping: gdb disables ASLR by default, and a recorder like rr
serialises threads onto one core. Both change the execution being observed. A
recorded run is evidence about that run, not proof the uninstrumented program
behaves the same way.
