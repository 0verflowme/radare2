# rdbg: persistent, programmable debug sessions for automated agents

`rdbg` is a research prototype built to answer one question empirically: what
stops an automated agent from debugging a real stripped binary?

It is a debug session that outlives the agent's tool call. A session is a
long-lived gdb hosting `server.py`, which serves newline-delimited JSON over a
unix socket. The agent never re-runs the target to re-derive what it already
knows.

## Why

An agent driving `gdb -batch` restarts the target on every tool call. Facts it
paid for (a PIE load base, an `mmap`'ed JIT region, a runtime function table)
die with the process, so every step re-derives them and the agent grows a batch
script by hand. On a real target that script becomes the project.

The measured failures that motivated each feature are in
[`doc/agent-debugging-gaps.md`](../agent-debugging-gaps.md) and
[`doc/agent-debugging-v8.md`](../agent-debugging-v8.md).

## Use

`rdbg` is a `python3` script, and it is committed without the executable bit, so
set that once in a fresh clone.

    chmod +x doc/rdbg/rdbg
    export PATH=$PWD/doc/rdbg:$PATH
    rdbg start mysession ./target
    rdbg mysession bp.set loc=mprotect caller_module=target
    rdbg mysession run stdin=...
    rdbg mysession snapshot
    rdbg ls
    rdbg stop mysession

Every request and response is JSON. From Python:

    from client import Rdbg
    d = Rdbg("mysession")
    d.req("bp.set", loc="@target+0x13d9")
    d.req("cont")

## What it adds over `gdb -batch`

**Session persistence.** State, breakpoints, and discoveries survive between
commands. Reconnecting costs nothing.

**Logical locations.** Every address is accepted and returned as
`@module+offset`, `$note+offset`, or `@anon:<region>+offset` for generated
code, never a bare runtime address. These stay valid across relaunch and ASLR.
`loc.resolve` converts one to an address; every reply describes addresses both
ways.

**Caller-scoped breakpoints.** `bp.set loc=mprotect caller_module=target`
stops only when the *caller* is in that module. Without this, `break mprotect`
stops first in the dynamic loader's own `_dl_protect_relro`, and an agent
reports the loader's argument as the target's.

**Named runtime facts.** `note.set name=jit_base expr='$rdi'` stores a value
with the position it was observed at. Later requests use `$jit_base+0x2828`.
This is the unit of knowledge that stateless debugging throws away.

**Structured stop snapshots.** One `snapshot` returns pc, registers, a
module-relative backtrace, disassembly, thread count, and the session
revision. No text parsing.

**Revisions and request IDs.** Mutations take `expected_revision` and
`request_id`. A stale revision is rejected; a retried request returns the
recorded outcome instead of stepping the target twice.

**Calling into the target.** `call fn=$tmain args=[...]` invokes a function at
an address in a stripped binary, with no debug info and no cast syntax to
guess. This turns the live target into an oracle an agent can query hundreds
of times per second.

**Memory export with provenance.** `mem.export` writes the bytes *and* a
sidecar recording the base address, region permissions, and the exact
`radare2` command to load the dump at the right virtual address.

## Status and limits

Research prototype, Linux x86-64, tested against stripped PIE and static
crackmes and against a V8 debug build.

- One writer per session; concurrent readers are fine. `interrupt` is handled
  off gdb's main thread so it works while the target runs.
- The journal records mutations but does not yet replay them.
- `checkpoint`/`restore` wrap gdb's fork checkpoints and inherit their limits
  (sockets, shared memory, threads).
- gdb disables ASLR by default. That is itself a capture perturbation; a
  recorded run is evidence about *that* run.

## Containment and honesty features

These exist because real targets needed them, not by design taste. The
measurements are in `doc/agent-debugging-gaps.md`.

**`fsmon.arm allow=[...] block=true`** watches every filesystem-modifying
syscall, resolves its path arguments, and counts an open only when the flags
intend to write. With `block`, the run stops at the first write outside the
allowed prefixes, at the syscall boundary, before it lands. `fsmon.report`
summarises by path and lists violations.

Use it for anything you did not write yourself. One crackme in the corpus
appended an executable segment to 919 of this host's shared libraries during a
single run, and gdb reported a clean exit.

**`protect`** keeps a pristine master copy of the executable and restores it
before every run, for targets that delete themselves. Without it you get one
run.

**`antidebug.mask`** substitutes a doctored `/proc/self/status` carrying
`TracerPid: 0` at the `openat` boundary. A target that branches on its own
tracer state then takes its normal path.

**`scope`** reports whether the session is still `observed` or has become
`modeled`, and lists the interventions that changed it. Writing target memory,
calling into the target, or restoring a checkpoint flips it; a fresh run clears
it. Masking a tracer check does not flip it, because it removes a difference the
target can see rather than adding one.

**`sys.trace`** records the target's syscall sequence in-session, with
module-relative call sites, so the mechanism can be discovered instead of
guessed. **`bp.syscall group=...`** catches a whole family (`output` covers
`write`, `writev`, `pwrite64`, `sendto`, `sendmsg`) and names anything the
kernel or gdb does not know, rather than failing silently.

**`stack.callers`** recovers a call chain by scanning the stack for values that
land in an executable mapping *and* directly follow a decoded call instruction.
This is for static stripped binaries and for generated code, where gdb's
unwinder returns one frame or several addresses that are not frames at all.

**Silent tracepoints** (`bp.set ... silent=true record=["rbx"]`) record and
resume without a round trip to the client, which keeps them under the timing
thresholds that targets use to detect instrumentation. Read them with `bp.log`.

## Large real targets

Tested against the official V8 debug build, which is where these came from.

**Symbols.** Every address carries its function name, the offset into it, and
the source file and line when debug info is present. Module-plus-offset is the
fallback, not the answer.

**Generated code.** A program counter with no backing file is reported as
`@anon:<region start>+<offset>` with the region's bounds, size and permissions.
On a JavaScript engine most interesting program counters look like this, and the
code range can be hundreds of megabytes.

**`sample.one`** returns the program counter and the recovered caller chain in
one request. Interrupt, sample, resume, repeat is how a hang gets diagnosed, and
it needs the session to survive between samples.

A tracepoint inside generated code is the case that settles the architecture:
its address is only knowable from a running process and is different in the
next one, so a debugger that restarts the target on every call cannot set it at
all.

## Verifying that observation did not change the answer

Run the target natively and under each observation mode, and compare its own
output byte for byte. This is a test a target can fail, and one in the corpus
does: it checks a one-cell-different comparison target under a debugger while
every visible behaviour stays identical.

A recorded or observed run is evidence about *that* run. It is not proof the
uninstrumented program behaves the same way.
