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

## Target 2: "veil" v3.1 (difficulty 4.0, static, stripped, declared anti-debug)

A 512-cell cellular automaton. The key is 128 hex characters, which is the
initial generation. The README says "the middle is watching" and "stop guessing
futures, grow one", so the key is a preimage, not a password.

Solved. The accepting key is

    5070ed578e3ac5d1734d619f4b17b89181fe485b3c98b828d4aaef004d9ae933
    7f75ec1cf79947c126b645dd7ff01a642176700b4e416d7909a19f3ede9cf6d9

and the binary answers `access granted`. The route to it produced the most
important finding in this document.

### Finding 8: guessing one syscall name hides the whole mechanism

`catch syscall write` never fires on veil. The program uses `writev`. gdb
reports nothing unusual: the catchpoint is created, the program runs to
completion, and the agent concludes either that the program produces no output
or that anti-debugging blocked the breakpoint. Both conclusions are wrong.

**Fix.** `bp.syscall group=output` sets catchpoints for the whole family and
reports any name the kernel or gdb does not know, rather than failing silently.
`sys.trace` records the actual syscall sequence in-session, which is how the
`writev` was found, with no external tracer.

### Finding 9: gdb cannot unwind a static stripped binary at all

At the output syscall, every frame past the innermost came back empty. There is
no CFI and no symbols, so `backtrace` is useless, and with it every "who called
this" question.

**Fix.** `stack.callers` scans the stack for values that point into an
executable mapping *and* sit immediately after a real call instruction,
verified by decoding the opcode. On veil it recovered a six-deep chain where
gdb recovered one frame, which is what located the verdict site.

### Finding 10: a memory read with no process silently returns the file

Reading the comparison targets before starting the target returned 512 zero
bytes, four times over, with no error. gdb had fallen back to the ELF on disk,
where those buffers are uninitialised. The live values are what matter: 260 and
233 set cells. An agent that reads first and runs later reports that the
target is all zeros and builds everything downstream on it.

**Fix.** Every `mem.read` and `mem.export` reply carries
`source: live-process | file-backed`, and the file-backed case carries an
explicit warning naming the consequence.

### Finding 11: the debugger changed the answer, and nothing said so

This is the finding that matters. veil reads `/proc/self/status` twice at
startup and keeps the `TracerPid` result in a flag. That flag feeds a hash that
flips exactly one cell of the 512-cell comparison target before the verdict is
computed.

So the program checks a *different target* under a debugger than it does on its
own, and the difference is one bit out of 504 constraints. Nothing in the
output, the exit code, or the rendered automaton differs. The tracer check costs
two `openat` calls that look like routine startup.

Measured, with the two keys this produces:

| key | native | under rdbg, unmasked | under rdbg, masked |
| --- | --- | --- | --- |
| solved from the observed run | rejected | 1024, accepted | 1023, rejected |
| solved from the masked run | **accepted** | 1023, rejected | 1024, accepted |

The first row is the whole problem in one line. The investigation was sound,
the extracted model predicted the observed score exactly, z3 solved the
preimage in 0.5 s, and the resulting key does not work, because the execution
that was observed is not the execution that runs.

Replay fidelity would not have helped. Replaying that recording perfectly
reproduces the perturbed verdict. What was needed was for the capture not to
perturb the target, and then a way to check that it had not.

**Fix.** `antidebug.mask` substitutes a doctored `/proc/self/status` with
`TracerPid: 0` at the `openat` boundary, patching the path in place. With it the
masked run and the native run agree, and the key solved under observation is
the key that works.

**And a check, not a promise.** The mask is not trusted on its own. Running the
target natively and under each observation mode and comparing its own output
byte for byte is a capture-fidelity test that a target can fail. veil's
automaton rendering is identical across native, traced, and masked runs, which
is exactly why the one-cell target difference was so easy to miss: the visible
behaviour was preserved and only the verdict was not.

### Also found here

veil additionally times its own verification and compares against a 50.0
threshold, taking a different path when observation makes the check slow. That
path sets another bit in the same flag and moves the flipped cell again. Silent
tracepoints, which record and resume without a round trip to the client, stay
under the threshold where ordinary breakpoints do not.

### What target 2 adds to the build order

Target 1 argued for session persistence and logical locations. Target 2 argues
for something the original plan treated as a late-stage concern:

1. Every answer should name the observation regime it was obtained under.
2. A capture-fidelity check belongs in the harness from the start, because a
   target can preserve all of its visible behaviour and still change its verdict.
3. Defeating the common tracer checks is not a nice-to-have. Without it the
   observed execution is the wrong execution, and everything downstream, however
   rigorous, answers a question nobody asked.

## Target 3: "Lernaia" (difficulty 6.0, stripped PIE) and what it cost

The author's description says "It's virus kinda stuff so treat it as such, don't
run it on your own machine, you've been warned", and "a piece that doesn't
forgive cheaters or patchers". Both were literally true. This target was not
solved. It was contained, and it is the most instructive of the three.

### Finding 12: the target consumes itself, so "just relaunch" is not available

lernaia calls `readlink("/proc/self/exe")` and then `unlink()` on the result.
Every execution destroys the executable. The stateless debugging model, where
each tool call starts the program again, gets exactly one run and then fails
with "No such file or directory" and no explanation of why.

**Fix.** `rdbg start ... --protect` keeps a pristine master copy and restores
the path before every run. Runs became unlimited, and the reply says when a
restore happened, so the self-deletion is visible rather than mysterious.

### Finding 13: the key is the environment, not an input

lernaia reads no input. There is no `printf`, no `scanf`, no `read` of stdin.
Its entire import list is `free strlen memcmp dlopen gethostbyname
__memcpy_chk memcpy malloc dlclose`. It calls `uname`, takes the nodename,
resolves it with `gethostbyname`, finds the first `.` in the canonical name, and
requires SHA-256 of the dot and everything after it to equal a 256-bit constant.

So the "password" is the machine's own domain name. An agent looking for an
input to supply will not find one.

Identifying the hash took one request. Calling the function at `@foo.elf+0x23f0`
with `"abc"` and comparing the 32 output bytes to the usual candidates matched
SHA-256 exactly. That is the same pattern that extracted the neural weights from
target 1 and the automaton rule from target 2: with a live session, an unknown
function is an oracle, and identifying it is a call rather than a reading
exercise.

The expected digest is

    69994d7dd8e5e574003dae60168f2b25f595553a93a5d0c94244b33dd3daa358

over the string `.` plus the domain. The model was verified by rewriting the
nodename in memory after the `uname` syscall and confirming the program hashed
exactly `.mydomain.test`. Recovering the domain is a SHA-256 preimage, which is
a search problem rather than a debugging one. A wordlist and an exhaustive
search over short strings did not find it, and that is where this target stands.

### Finding 14: intervening is not observing, and the target knew

Writing the expected digest into the output buffer to get past the gate worked,
in the sense that execution continued. The program's response was

    [*] nice try, script kiddie
        -- the hydra doesn't forgive curiosity

The gate has a second, independent check. rdbg had already labelled the session
`scope: modeled` the moment target memory was written, which is the honest
description: from that point on, nothing observed is the program's own behaviour.

**The feature this justifies.** `scope` distinguishes `observed` from `modeled`
and lists the interventions that caused the change. Writing memory, calling into
the target, or restoring a checkpoint flips it; a fresh run clears it. Masking a
tracer check does not flip it, because removing a difference the target can see
moves the run *closer* to the unobserved program, not further away.

### Finding 15: the target modified 919 of the host's shared libraries

This is the finding that matters most, and it is a safety finding rather than a
capability one.

The tamper response did not only print a message. It appended a 134-byte
`PT_LOAD` segment with `RWE` permissions to shared libraries across the host and
hooked them so the payload runs on load. The payload XOR-decodes a string with
key `0x1d`, writes 73 bytes to file descriptor 1, re-encodes it, restores the
registers it used, and jumps back.

Measured extent: **919 of 3080 shared objects**, `libc.so.6` among them. The
count is stable, because the payload only prints; the spreading happened once,
during a single run.

The practical consequences, in order of how they appeared:

1. Every dynamically linked process on the host prints the message. Statically
   linked binaries are unaffected, which is how the mechanism was identified.
2. The message lands on file descriptor 1 of every process, so it corrupts
   **redirected output**. Two scratch files written with `cat > file <<EOF` were
   silently corrupted, because `cat`'s own standard output was the file.
3. It corrupts any JSON pipeline, because the text is interleaved with the data.
4. It corrupts git's remote-helper protocol. `git ls-remote` began returning the
   injected text as a ref name, and `git push` stopped working, so the rest of
   this work had to be pushed through the GitHub API.

Nothing in the debugger reported any of this. gdb reported a clean run with exit
code 1. There is no stop, no warning, and no record. An agent working
autonomously would have infected its own environment and carried on.

Repairing the libraries was refused by this environment's own guard on modifying
shared system resources, which is the correct outcome; the damage is documented
rather than worked around, and the container is disposable.

**Fix.** `fsmon` watches the filesystem-modifying syscalls (`open`, `openat`,
`openat2`, `unlink`, `unlinkat`, `rename`, `renameat`, `renameat2`, `truncate`,
`chmod`, `fchmodat`, `link`, `symlink`, `mkdir`, `creat`, `mknod`), resolves the
path arguments, and counts an open only when the flags intend to write. With
`block` and an `allow` list it stops the run at the first write outside the
allowed prefixes, at the syscall boundary, before the write lands.

Validated on a stand-in binary that writes one file inside the working directory
and one into `/usr/local/lib`: the first write completed, the second stopped the
run, the report named the syscall and the path, and the file was never created.

Had this existed one hour earlier, lernaia would have stopped at its first
`openat` of a library under `/usr/lib`, with the path in the reply.

### What target 3 adds to the build order

1. **Containment is a debugger feature, not an afterthought.** A tool built for
   autonomous agents to analyse untrusted binaries must report and gate the
   target's effects on the host. The agent cannot be assumed to be running
   inside somebody else's sandbox, and "the container is disposable" is not a
   property the debugger can verify.
2. **Observation and intervention must be separately labelled**, because targets
   check, and because the distinction decides whether an answer is about the
   program or about the debugging of it.
3. **Re-running is a privilege, not a given.** A target that destroys itself,
   or its environment, makes the persistent session the only workable model.

### Honest status of the three targets

| target | difficulty | result |
| --- | --- | --- |
| not obfuscated | 5.0 | solved; a key differing from the author's in 43 of 49 positions |
| veil v3.1 | 4.0 | solved; `access granted`, after correcting for the tracer-dependent target |
| Lernaia | 6.0 | not solved; stage 1 fully modelled, domain is a SHA-256 preimage |

Two of three solved. The third produced the most useful findings, which is the
usual way with a harness: the target that defeats you tells you what to build.

## Reproducing

The corpus is not committed: these are other people's crackmes, and one of them
is hostile to its host. Fetch them from crackmes.one, and run anything you did
not write yourself under `fsmon.arm` with an allowlist and `block: true`.
