# Hunting a new bug in V8, and what it actually takes

A companion to [`doc/agent-debugging-v8.md`](../agent-debugging-v8.md). That
document diagnoses a bug. This one tries to *find* one that nobody has found
before, which is a different and much harder problem.

Target: the official V8 debug build for 15.5.31, `DCHECK`s live, natives syntax
deliberately unused. A crash reached through `%`-functions proves nothing,
because those are unsafe by contract.

## Result, stated first

**No new bug found.** Across roughly 20,000 generated programs, 2,600
differential comparisons and 54,540 metamorphic checks: zero crashes, zero
`DCHECK` failures, zero miscompiles, zero violated invariants.

That is the expected outcome and worth saying plainly. V8 is fuzzed
continuously by ClusterFuzz on thousands of cores with coverage-guided,
grammar-aware and structure-aware fuzzers, plus stress and differential
variants. A blind generator on four cores for a few hours is not going to reach
anything those have not already swept. The honest expected yield for novel
memory-safety bugs under these conditions is approximately zero.

What the exercise did produce is a working pipeline and six classes of false
positive caught before they could be reported as findings. Those are the
transferable parts.

## Three oracles, because crashes are the least likely bug

**`fuzz.py` — reentrancy.** V8's memory-safety bugs cluster where a builtin
calls back into JavaScript while holding an assumption about its receiver: a
getter, a `valueOf`, a Proxy trap, an iterator's `next`, a comparator. The
generator pairs ten exotic receivers (resizable and shared typed arrays, holey
and double arrays, Proxies, `arguments`) with roughly sixty operations drawn
from the newest shipped and staged surface, and injects a mutation into the
callback: resize, transfer, detach, reproto, freeze, shrink.

**`diffuzz.py` — differential.** For an optimising compiler, a miscompile is
more likely than a crash and has nothing to crash. The same deterministic
program runs under the optimiser, under `--jitless`, and under the new
`--turbolev-future` tier. Disagreement means one of the three is wrong.
Every candidate is re-run three times per configuration before being believed.

**`temporal_meta2.js` — metamorphic.** Differential testing needs a second
implementation. Metamorphic testing does not: it checks relations that must
hold between results of the same implementation. Temporal is newly staged and
its arithmetic is calendar- and timezone-aware, so relations like "the duration
from a to b, added to a, lands on b" are exactly what breaks at month ends and
leap days.

**`triage.py`** decides which candidates are real: does it reproduce, does a
timeout finish with a longer budget, does it still happen without stress flags,
and what is the smallest surviving form.

## The six false positives, which are the real lesson

Every one of these looked like a finding first.

**Unbounded growth read as a hang.** 41 timeouts, all the same shape:

    Iterator.from(V).map(x => { V.push({}); return x; }).toArray()

An array iterator is live, so pushing during iteration extends the iteration
forever. Correct JavaScript, guaranteed timeout, no bug. Fixed by bounding every
mutation to fire a few times, which keeps the reentrancy without manufacturing
infinite loops.

**Four unsound invariants, 3,618 "violations".** The first metamorphic run
reported thousands of failures. All four rules were wrong, not V8:

| rule | why it is not an invariant |
| --- | --- |
| add then subtract returns the start | calendar months clamp: `2000-01-31 +1M` is `2000-02-29`, `-1M` is `2000-01-29` |
| compare agrees with until's sign | backwards: `compare(a,b)` is -1 when `a<b`, `a.until(b)` is positive when `b>a` |
| total of a duration negates cleanly | with a calendar anchor, 14 months back spans a different number of days than 14 months forward |
| until equals since with operands swapped | the two calls balance against different anchors, so they may legitimately differ above days |

With those removed and the sign convention fixed, 54,540 checks passed clean.

**An address-space cap that killed the target at startup.** Adding
`RLIMIT_AS` of 3 GiB produced a 100% hit rate. V8 reserves a 4 GiB
pointer-compression cage up front, so every run died before executing anything.
A 100% hit rate is always the harness and never the target.

**Contradictory flags of my own.** 31 of 200 cases exited on `SIGTRAP` with
`Flag processing error: --max-semi-space-size is implied by
--stress-compaction but also specified explicitly`. `interesting()` now treats
any harness error as a harness error, loudly, and never as a finding.

**A torn scratch file read as a SIGBUS.** The most convincing one. A candidate
reported

    Received signal 7 BUS_ADRERR 06d7fc7c6000
    ==== C stack trace ===============================
    libv8_libbase.so(v8::base::debug::StackTrace::StackTrace()+0x1e) ...

with a real V8 stack trace, alongside a `SyntaxError` in the generated file.
`BUS_ADRERR` means reading a mapping whose backing file changed underneath, and
d8 mmaps the script. Two copies of the same worker were running and both wrote
one scratch path, so d8 mapped a file the other was rewriting. The scratch file
now carries the pid, a syntax error in our own output counts as a harness fault,
and the offending seed runs clean 150 times over.

That one has a causal chain worth tracing, because every link is mine. A process
check searched for `/fuzz.py` while the workers ran as `python3 fuzz.py`, so
`ps` reported zero workers while seventeen were running and progressing. That
made a `pkill` silently match nothing, which left duplicate workers alive, which
raced on one scratch path, which forged a crash. I diagnosed a nonexistent
worker failure twice before thinking to check the monitor rather than the thing
being monitored.

The rule that would have caught four of the six immediately: an implausible hit
rate is a statement about the harness. 100% was an address-space cap, 15% was a
flag conflict, and 34% was unbounded array growth. Real V8 bugs do not arrive at
those rates.

## If the goal is to actually find a novel bug

Three honest routes, in increasing order of cost:

1. **Change target.** QuickJS, mujs, JerryScript and Hermes are real engines
   with orders of magnitude less fuzzing investment than V8. A novel crash there
   is plausible in hours rather than months, and the diagnosis pipeline is the
   thing being demonstrated either way.
2. **Change technique.** Coverage-guided fuzzing against a V8 fuzzer target, or
   Fuzzilli, which mutates in V8's own IL and is what actually finds V8 bugs.
   A blind generator cannot compete with feedback.
3. **Change budget.** Thousands of core-hours, which is what the bugs that do
   get found cost.

Reproducing a known CVE proves less, but it proves it against ground truth. The
two are answers to different questions, and neither substitutes for the other.

## Running it

    python3 fuzz.py <seed-start> <count> <outdir> [worker-id]
    python3 diffuzz.py <seed-start> <count> <outdir> [worker-id]
    python3 triage.py [hit files...]
    d8 --harmony --js-staging --harmony-temporal temporal_meta2.js

Every case is reproducible from its seed. Paths to `d8` are at the top of each
script.
