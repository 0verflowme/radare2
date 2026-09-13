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
[`doc/agent-debugging-gaps.md`](../agent-debugging-gaps.md).

## Use

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
`@module+offset` or `$note+offset`, never a bare runtime address. These stay
valid across relaunch and ASLR. `loc.resolve` converts one to an address;
every reply describes addresses both ways.

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
crackmes.

- One writer per session; concurrent readers are fine. `interrupt` is handled
  off gdb's main thread so it works while the target runs.
- The journal records mutations but does not yet replay them.
- `checkpoint`/`restore` wrap gdb's fork checkpoints and inherit their limits
  (sockets, shared memory, threads).
- gdb disables ASLR by default. That is itself a capture perturbation; a
  recorded run is evidence about *that* run.
