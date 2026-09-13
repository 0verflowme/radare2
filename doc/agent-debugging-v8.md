# Debugging a real engine: V8's d8

A companion to [`doc/agent-debugging-gaps.md`](agent-debugging-gaps.md), which
covers three crackmes. Those are small and adversarial. A JavaScript engine is
the opposite: 4.7 MB of binary with full debug info, ten threads, a 512 MB
executable code range, and code that does not exist until it is generated. It
produced the finding that settles the architecture.

The official V8 debug build for 15.5.31 was used, so `DCHECK`s are live and a
failure is a real bug report rather than a wrong answer.

Twenty-two stress programs were run against it. Twenty-one behaved. One hung:

    /(a+)+$/.test("a".repeat(40) + "b")

Catastrophic backtracking, and a good bug to debug because there is no crash.
Nothing faults, nothing prints, and the process simply never returns.

### Finding 16: on a hang, the agent has to interrupt, and gdb's backtrace is noise

The first `run` never returns, which rdbg reports rather than hanging the
caller:

    "stopped": false,
    "note": "target still running after 6s; use op=interrupt"

After interrupting, the program counter is `0x7fffc2a001f1`, inside an
anonymous `rwxp` mapping with no backing file. That is V8's code range: the
regexp was compiled to machine code. gdb's own backtrace from there is

    #0  0x00007fffc2a001f1
    #1  0x000000000000000d
    #2  0xffffffffffffffd6
    #3  0xfffffffffffffffb

Not truncated, not an error. Four plausible-looking addresses that are not
frames at all. An agent that reports this is reporting noise.

**Fix.** `stack.callers` recovered the real chain from the same stop, and with
symbol resolution added it reads:

    v8::Shell::Main                d8.cc:8420
    v8::Shell::RunMain             d8.cc:7452
    v8::Shell::RunMainIsolate      d8.cc:7538
    v8::SourceGroup::Execute       d8.cc:6407
    v8::Shell::ExecuteSource       d8.cc:1300
    [generated code]

### Finding 17: nothing names generated code, so there is nothing to reason about

A program counter in JIT code has no module, so module-relative locations do not
apply and every reply about it was a bare address. That is the one thing logical
locations were supposed to eliminate.

**Fix.** Anonymous executable mappings are reported as
`@anon:0x7fffc2a00000+0x1f1` together with the region's bounds, size and
permissions, so the agent has a handle, knows how large the code range is
(536,608,768 bytes here), and can export it.

### Finding 18: symbols existed all along and nothing used them

Every reply was module-plus-offset because the crackmes had no symbols. On a
real target this throws away the most useful thing present. Addresses now carry
the function name, the offset into it, and the source file and line from the
debug info.

### Finding 19: a JIT address dies with the process, which settles the session question

This is the strongest argument in the whole study for a persistent session, and
it took a real engine to produce it.

Diagnosing the hang needs a tracepoint inside the generated matcher. Its address
is only knowable from a running process, and it is different in the next one.
With `gdb -batch` the sequence is: run, find the address, exit, and the address
is now meaningless. The measurement is not merely expensive, it is unavailable.

With the session held open it is three requests. A silent tracepoint on the
matcher's backtrack-stack push, recording the input position and the backtrack
stack pointer:

        0x7fffc2a001eb   sub    $0x4,%rbx          ; push a backtrack entry
        0x7fffc2a001ef   mov    %edi,(%rbx)        ; save the input position
    =>  0x7fffc2a001f1   movabs 0x34a400174420,%rax ; backtrack stack limit
        0x7fffc2a001fe   ja     ...                ; overflow check
        0x7fffc2a00205   test   %edi,%edi          ; end of input?
        0x7fffc2a0020d   movzbl (%rsi,%rdi,1),%edx ; load input character
        0x7fffc2a00211   cmp    $0x61,%edx         ; 'a'
        0x7fffc2a0021a   add    $0x1,%rdi          ; advance
        0x7fffc2a0021e   jmp    0x7fffc2a00205     ; the inner a+ loop

Two seconds of tracing:

| measurement | value |
| --- | --- |
| backtrack pushes recorded | 5037 |
| distinct input positions | 13, from -14 to -1 |
| backtrack stack pointer span | 384 bytes |
| input position moved forward | 2518 times |
| input position moved backward | 2518 times |

Forward exactly equals backward. The matcher is not making progress and never
will: it is enumerating the ways to partition a run of `a` between the inner and
outer quantifiers, and the `$` at the end fails every one. That is the diagnosis,
measured rather than inferred, from code with no symbols and no source.

Fourteen interrupt-and-sample cycles all landed inside the same code region, so
the hang is entirely in generated code and not in any C++ loop.

### What target 4 adds to the build order

1. **Symbolise everything.** An address without its function and source line is
   a worse answer than one with it, and the information is already there.
2. **Name generated code.** For a JavaScript engine, most of the interesting
   program counters have no module. Regions need identity.
3. **Support a hang, not only a crash.** Interrupt, sample, resume, repeat is a
   primary workflow, and it needs the session to survive between samples.
4. **Per-process addresses settle the architecture.** When the address you need
   cannot outlive the process that had it, a debugger that restarts the process
   on every call cannot answer the question at all. This is not an efficiency
   argument.

### Reproducing

The build is published and needs no special handling:

    curl -O https://storage.googleapis.com/chromium-v8/official/canary/v8-linux64-dbg-15.5.31.zip

Then, with `doc/rdbg/` on PATH:

    rdbg start d8 ./d8
    rdbg d8 --json '{"op":"run","args":["redos.js"],"wait_timeout":6}'
    rdbg d8 interrupt
    rdbg d8 --json '{"op":"sample.one","module":"d8"}'
