"""Reentrancy fuzzer for a V8 debug build.

V8's memory-safety bugs cluster where a builtin calls back into JavaScript while
holding an assumption about its receiver: a getter, a valueOf, a Proxy trap, an
iterator's next, a comparator. The newest builtins have the least coverage of
that pattern, so the generator pairs freshly shipped or staged APIs with
callbacks that mutate the receiver mid-operation.

A debug build has DCHECKs compiled in, so a DCHECK failure here is a real bug
report rather than a wrong answer. Natives syntax is deliberately not used:
%-functions are unsafe by contract and crashing through them proves nothing.

Usage: fuzz.py <seed-start> <count> <outdir> [worker-id]
"""
import os, random, subprocess, sys, textwrap, time

# An earlier version capped the child's address space with RLIMIT_AS. Do not:
# V8 reserves a 4 GiB pointer-compression cage up front, so any cap small enough
# to be useful kills d8 before it executes anything, which showed up as a 100%
# hit rate. The heap is bounded with --max-old-space-size instead and runaway
# cases are caught by the subprocess timeout.

D8 = "/home/user/work/v8/dbg/d8"
CWD = "/home/user/work/v8/dbg"
NOISE = ("script kiddie", "forgive curiosity")

BASE_FLAGS = [
    "--harmony", "--js-staging", "--harmony-temporal", "--harmony-struct",
    "--harmony-shadow-realm", "--js-iterator-includes", "--js-iterator-join",
    "--js-iterator-sequencing", "--expose-gc",
]
# Extra pipelines. A new optimising tier is exactly where miscompiles live.
FLAG_SETS = [
    [],
    ["--future"],
    ["--turbolev-future"],
    ["--jitless"],
    ["--stress-compaction"],
    ["--expose-externalize-string"],
]

# ---------------------------------------------------------------- receivers

RECEIVERS = {
    "resizable_ta": """
        const ab = new ArrayBuffer(0x200, {maxByteLength: 0x2000});
        const V = new %(tat)s(ab);
        for (let i = 0; i < V.length; i++) V[i] = i %% 251;
    """,
    "plain_ta": """
        const ab = new ArrayBuffer(0x200);
        const V = new %(tat)s(ab);
        for (let i = 0; i < V.length; i++) V[i] = i %% 251;
    """,
    "shared_ta": """
        const ab = new SharedArrayBuffer(0x200, {maxByteLength: 0x2000});
        const V = new %(tat)s(ab);
        for (let i = 0; i < V.length; i++) V[i] = i %% 251;
    """,
    "holey_array": """
        const V = [1, 2, , 4, 5, , 7];
        V[100] = 9;
    """,
    "packed_double": """
        const V = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
    """,
    "large_array": """
        const V = Array.from({length: 600}, (_, i) => i);
    """,
    "proxy_array": """
        const t = [1, 2, 3, 4, 5];
        const V = new Proxy(t, {
            get(o, k) { return k === "length" ? 5 : o[k]; },
            has(o, k) { return true; },
        });
    """,
    "argobj": """
        function mk() { return arguments; }
        const V = mk(1, 2, 3, 4, 5);
    """,
    "string_obj": """
        const V = Object.assign(["a", "b", "c"], {extra: 1});
    """,
    "map_backed": """
        const V = Array.from(new Map([[1, 2], [3, 4], [5, 6]]).keys());
    """,
}

TATYPES = ["Uint8Array", "Int32Array", "Float64Array", "Float32Array",
           "BigInt64Array", "Uint8ClampedArray", "Int16Array", "Float16Array"]

# ---------------------------------------------------------------- mutations

MUTATIONS = [
    "try { ab.resize(8); } catch (e) {}",
    "try { ab.resize(0x2000); } catch (e) {}",
    "try { ab.transfer(); } catch (e) {}",
    "try { ab.grow(0x1000); } catch (e) {}",
    "try { V.length = 0; } catch (e) {}",
    "try { V.length = 1; } catch (e) {}",
    "try { V.length = 9999; } catch (e) {}",
    "try { Object.setPrototypeOf(V, null); } catch (e) {}",
    "try { Object.setPrototypeOf(V, {0: 7, 1: 8, length: 2}); } catch (e) {}",
    "try { Object.freeze(V); } catch (e) {}",
    "try { Object.seal(V); } catch (e) {}",
    "try { delete V[1]; } catch (e) {}",
    "try { V[0] = {}; } catch (e) {}",
    "try { V[2] = 1.5; } catch (e) {}",
    "try { V.push({}); } catch (e) {}",
    "try { V.shift(); } catch (e) {}",
    "try { V.reverse(); } catch (e) {}",
    "gc();",
    "gc(); gc();",
    "try { Object.defineProperty(V, 1, {get(){return 3;}}); } catch (e) {}",
    "try { V[Symbol.iterator] = function*(){ yield 1; }; } catch (e) {}",
]

# ---------------------------------------------------------------- operations
# Each is a template using V (receiver) and CB (a reentrant callback call).

OPS = [
    # newly shipped array/iterator surface
    "R = Array.from(V, x => { CB; return x; });",
    "R = Array.prototype.flatMap.call(V, x => { CB; return [x]; });",
    "R = Array.prototype.sort.call(V, (a, b) => { CB; return a < b ? -1 : 1; });",
    "R = Array.prototype.toSorted.call(V, (a, b) => { CB; return a < b ? -1 : 1; });",
    "R = Array.prototype.toSpliced ? 0 : Array.prototype.with.call(V, 0, 5);",
    "R = Array.prototype.copyWithin.call(V, 0, 1);",
    "R = Array.prototype.findLast.call(V, x => { CB; return false; });",
    "R = Array.prototype.at.call(V, -1);",
    "R = Array.prototype.includes.call(V, {valueOf(){ CB; return 1; }});",
    "R = Array.prototype.lastIndexOf.call(V, {valueOf(){ CB; return 1; }});",
    "R = Array.prototype.join.call(V, {toString(){ CB; return \",\"; }});",
    "R = Array.prototype.fill.call(V, {valueOf(){ CB; return 1; }});",
    "R = Array.prototype.reduce.call(V, (a, x) => { CB; return a; }, 0);",
    "R = Array.prototype.flat.call([V, [V]], 2).length;",
    # typed array specific
    "R = V.subarray ? V.subarray(1, 3).length : 0;",
    "R = V.set ? (V.set([1,2,3], 0), 1) : 0;",
    "R = typeof V.sort === 'function' ? V.sort((a,b) => { CB; return 0; }) : 0;",
    # iterator helpers and the new proposals
    "R = Iterator.from(V).map(x => { CB; return x; }).toArray().length;",
    "R = Iterator.from(V).take(3).toArray().length;",
    "R = Iterator.from(V).drop(1).flatMap(x => { CB; return [x]; }).toArray().length;",
    "R = Iterator.from(V).reduce((a, x) => { CB; return a; }, 0);",
    "R = Iterator.prototype.includes ? Iterator.from(V).includes({valueOf(){ CB; return 1; }}) : 0;",
    "R = Iterator.prototype.join ? Iterator.from(V).join({toString(){ CB; return '-'; }}) : 0;",
    "R = Iterator.concat ? Iterator.concat(Iterator.from(V), (function*(){ CB; yield 1; })()).toArray().length : 0;",
    "R = Iterator.zip ? Iterator.zip([Iterator.from(V), (function*(){ CB; yield 1; })()]).toArray().length : 0;",
    # grouping and collections
    "R = Object.keys(Object.groupBy(V, x => { CB; return 'k' + (x & 1); })).length;",
    "R = Map.groupBy(V, x => { CB; return x & 1; }).size;",
    "R = new Set(V).union ? new Set(V).union(new Set([1,2])).size : 0;",
    "R = new Set(V).symmetricDifference(new Set([1,2,3])).size;",
    "R = new Set(V).isSubsetOf(new Set([1,2,3]));",
    # strings and base64/hex
    "R = Uint8Array.fromBase64 ? Uint8Array.fromBase64('AAECAwQ=').length : 0;",
    "R = V.setFromHex ? (function(){ try { return V.setFromHex('00112233'); } catch(e) { return 0; } })() : 0;",
    "R = V.toBase64 ? V.toBase64().length : 0;",
    # regexp
    "R = String(V).replace(/(\\d)(\\d)?/g, (m, a, b) => { CB; return a; }).length;",
    "R = [...String(V).matchAll(/\\d/g)].length;",
    "R = new RegExp('[\\\\p{ASCII}--[a]]', 'v').test(String(V));",
    "R = RegExp.escape ? RegExp.escape(String(V)).length : 0;",
    # JSON
    "R = JSON.stringify(V, function (k, v) { CB; return v; }).length;",
    "R = JSON.parse('[1,2,3]', function (k, v) { CB; return v; }).length;",
    # Temporal arithmetic, brand new and arithmetic-heavy
    "R = Temporal.PlainDate.from('2024-02-29').add({months: 12, days: 1}).toString();",
    "R = Temporal.Duration.from({hours: 1e6}).round({largestUnit: 'years', relativeTo: '2024-01-01'}).toString();",
    "R = Temporal.PlainDateTime.from('2024-01-31T23:59:59.999999999').until('2025-03-01T00:00:00').toString();",
    "R = Temporal.ZonedDateTime.from('2024-03-10T02:30[America/New_York]').toString();",
    "R = Temporal.PlainYearMonth.from({year: 2024, month: 2}).daysInMonth;",
    "R = Temporal.Duration.from({days: 1}).total({unit: 'nanoseconds'});",
    "R = Temporal.Instant.fromEpochNanoseconds(8640000000000000000000n).toString();",
    "R = Temporal.PlainDate.from({year: 275760, month: 9, day: 13}).toString();",
    "R = Temporal.PlainTime.from('12:00').since('11:00', {largestUnit: 'hours'}).toString();",
    "R = Temporal.PlainMonthDay.from('--02-29').toPlainDate({year: 2023}).toString();",
    "R = Temporal.Duration.from('P1Y1M1DT1H1M1.999999999S').round({smallestUnit: 'nanoseconds', largestUnit: 'days', relativeTo: '2024-02-28'}).toString();",
    "R = Temporal.ZonedDateTime.from('2024-11-03T01:30[America/New_York]').add({hours: 1}).toString();",
    # explicit resource management
    "R = (function(){ let n = 0; { using d = { [Symbol.dispose]() { CB; n++; } }; } return n; })();",
    # shared structs
    "R = (function(){ const T = new SharedStructType(['a','b']); const s = new T(); s.a = 1; CB; return s.a; })();",
    "R = (function(){ const a = new SharedArray(4); a[0] = 1; CB; return a.length; })();",
    # proxies against the new surface
    "R = Object.keys(new Proxy(V, {ownKeys(o){ CB; return Reflect.ownKeys(o); }, getOwnPropertyDescriptor(o,k){ return Reflect.getOwnPropertyDescriptor(o,k); }})).length;",
    "R = Reflect.ownKeys(new Proxy(V, {ownKeys(){ CB; return ['0','1']; }, getOwnPropertyDescriptor(){ return {value:1, configurable:true, enumerable:true}; }})).length;",
    # structured clone-ish and misc
    "R = Object.entries(Object.fromEntries(Array.from(V, (x,i) => ['k'+i, x]))).length;",
    "R = Array.isArray(V) ? V.flat(Infinity).length : 0;",
]

def gen(seed):
    r = random.Random(seed)
    recv_name = r.choice(list(RECEIVERS))
    recv = RECEIVERS[recv_name] % {"tat": r.choice(TATYPES)}
    op = r.choice(OPS)
    nmut = r.randint(1, 3)
    muts = " ".join(r.choice(MUTATIONS) for _ in range(nmut))
    # Bound the mutation. An array iterator is live, so an unbounded push in a
    # callback extends the iteration forever: a guaranteed timeout that is
    # correct JavaScript and not a bug. Firing a few times keeps the reentrancy
    # without manufacturing infinite loops.
    muts = "if (MUT_N++ < %d) { %s }" % (r.randint(1, 3), muts)
    op_body = op.replace("CB", muts)
    warm = r.choice([0, 0, 1, 12, 60])       # optimisation pressure
    use_gc = r.random() < 0.4
    body = textwrap.dedent(recv).strip()
    src = [
        "// seed %d receiver=%s warm=%d" % (seed, recv_name, warm),
        "let R; let MUT_N = 0;",
        "function once() {",
        "  " + body.replace("\n", "\n  "),
        "  " + op_body,
        "  return R;",
        "}",
    ]
    if warm:
        src.append("for (let i = 0; i < %d; i++) { try { once(); } catch (e) {} }" % warm)
    src.append("try { print(String(once()).slice(0, 60)); } catch (e) { print('threw ' + e.constructor.name); }")
    if use_gc:
        src.append("gc();")
    flags = BASE_FLAGS + r.choice(FLAG_SETS) + \
        ["--max-old-space-size=512"]
    return "\n".join(src) + "\n", flags


def clean(t):
    return "\n".join(l for l in t.splitlines()
                     if not any(n in l for n in NOISE))


INTERESTING = ("Fatal error", "Check failed", "DCHECK", "Received signal",
               "# Fatal", "unreachable code", "FATAL", "Segmentation fault",
               "CHECK_", "ASAN", "UndefinedBehavior")


HARNESS_ERRORS = (
    "Flag processing error",          # contradictory flags we passed ourselves
    "Invalid or unexpected token",    # our scratch file was torn under d8
    "SyntaxError",                    # the generator emitted something invalid
    "Error reading file",
    "is implied by",
)


def interesting(rc, out, err):
    blob = out + "\n" + err
    # Our own fault, not the target's. Report it loudly rather than counting it.
    for h in HARNESS_ERRORS:
        if h in blob:
            print("HARNESS ERROR (not a finding): %s" % blob.strip().splitlines()[0][:120],
                  flush=True)
            return None
    if any(s in blob for s in INTERESTING):
        return "signal-text"
    if rc == "timeout":
        return "hang"
    if rc not in (0, 1):
        return "exit-%s" % rc
    return None


def main():
    start = int(sys.argv[1]); count = int(sys.argv[2])
    outdir = sys.argv[3]; wid = sys.argv[4] if len(sys.argv) > 4 else "0"
    os.makedirs(outdir, exist_ok=True)
    found = 0
    t0 = time.time()
    for seed in range(start, start + count):
        src, flags = gen(seed)
        # The pid is load-bearing. Two workers sharing one scratch path let d8
        # mmap a file another worker was rewriting, which surfaced as
        # "Received signal 7 BUS_ADRERR" with a real C stack trace plus a
        # SyntaxError: a convincing fake crash, entirely of our own making.
        path = os.path.join(outdir, "w%s_%d_cur.js" % (wid, os.getpid()))
        with open(path, "w") as fh:
            fh.write(src)
        try:
            p = subprocess.run([D8] + flags + [path], cwd=CWD,
                               capture_output=True, timeout=10)
            rc, out, err = p.returncode, clean(p.stdout.decode("utf-8", "replace")), \
                clean(p.stderr.decode("utf-8", "replace"))
        except subprocess.TimeoutExpired:
            rc, out, err = "timeout", "", ""
        except Exception as e:                      # noqa: E722 - keep going
            print("case %d raised %s: %s" % (seed, type(e).__name__, e), flush=True)
            continue
        why = interesting(rc, out, err)
        if why:
            found += 1
            keep = os.path.join(outdir, "hit_%s_%d_%s.js" % (wid, seed, why))
            with open(keep, "w") as fh:
                fh.write("// flags: %s\n// why: %s rc=%s\n" % (" ".join(flags), why, rc))
                fh.write("/* stdout:\n%s\n*/\n/* stderr:\n%s\n*/\n" % (out[:2000], err[:4000]))
                fh.write(src)
            print("HIT seed=%d %s rc=%s -> %s" % (seed, why, rc, keep), flush=True)
        if (seed - start) % 200 == 199:
            el = time.time() - t0
            print("w%s progress %d/%d  %.1f cases/s  hits=%d"
                  % (wid, seed - start + 1, count, (seed - start + 1) / el, found),
                  flush=True)
    print("w%s done: %d cases, %d hits, %.0fs" % (wid, count, found, time.time() - t0),
          flush=True)


if __name__ == "__main__":
    main()
