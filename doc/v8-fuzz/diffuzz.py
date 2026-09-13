"""Differential fuzzer: look for JIT miscompiles in a V8 debug build.

A crash is not the only kind of real bug, and for an optimising compiler it is
not the most likely one. If the same deterministic program prints one answer
with the optimiser and a different answer with --jitless, one of the two is
wrong, and that is a miscompile: a genuine bug with no crash to find.

The oracle is cheap and strong, but only as good as the program's determinism,
so the generator here deliberately excludes anything clock-, address- or
allocation-order dependent. Every candidate is then re-run several times per
configuration before being believed.

Usage: diffuzz.py <seed-start> <count> <outdir> [worker-id]
"""
import os, random, subprocess, sys, time

D8 = "/home/user/work/v8/dbg/d8"
CWD = "/home/user/work/v8/dbg"
NOISE = ("script kiddie", "forgive curiosity")

COMMON = ["--harmony", "--js-staging", "--harmony-temporal",
          "--js-iterator-includes", "--js-iterator-join",
          "--js-iterator-sequencing"]
# A: everything on.  B: no optimiser at all.  C: the new tier.
CONFIGS = {
    "opt": COMMON,
    "jitless": COMMON + ["--jitless"],
    "turbolev": COMMON + ["--turbolev-future"],
}

# Deterministic receivers only: no clocks, no randomness, no address exposure.
RECEIVERS = [
    "const V = [1, 2, 3, 4, 5, 6, 7, 8];",
    "const V = [1.5, -2.5, 3.25, -4.125, 0, -0, 1e308, -1e308];",
    "const V = [1, 2, , 4, , 6, 7];",
    "const V = Array.from({length: 40}, (_, i) => i - 20);",
    "const V = new Int32Array([1, -1, 2147483647, -2147483648, 0, 5]);",
    "const V = new Uint8Array([0, 1, 127, 128, 255, 3]);",
    "const V = new Float64Array([0.1, -0.1, 1/3, NaN, Infinity, -Infinity]);",
    "const V = new Float32Array([0.1, -0.1, 1/3, 16777217, 1e38, -0]);",
    "const V = new BigInt64Array([1n, -1n, 9223372036854775807n, -9223372036854775808n]);",
    "const V = ['b', 'a', 'c', 'A', 'B', '\\u00e9', '\\u0041'];",
    "const V = [true, false, 1, 0, '', 'x', null, undefined];",
]

# Pure, deterministic expressions over V. Arithmetic and conversion edges are
# where an optimiser and an interpreter are most likely to disagree.
EXPRS = [
    "V.reduce((a, x) => a + Number(x), 0)",
    "V.reduce((a, x) => (a * 31 + Number(x)) | 0, 7)",
    "V.reduce((a, x) => Math.min(a, Number(x)), Infinity)",
    "V.reduce((a, x) => Math.max(a, Number(x)), -Infinity)",
    "V.map(x => Number(x) | 0).join(',')",
    "V.map(x => Number(x) >>> 0).join(',')",
    "V.map(x => (Number(x) << 1) >> 1).join(',')",
    "V.map(x => Math.fround(Number(x))).join(',')",
    "V.map(x => Math.f16round ? Math.f16round(Number(x)) : 0).join(',')",
    "V.map(x => Math.trunc(Number(x))).join(',')",
    "V.map(x => Math.round(Number(x))).join(',')",
    "V.map(x => Math.sign(Number(x))).join(',')",
    "V.map(x => Math.abs(Number(x))).join(',')",
    "V.map(x => Number(x) % 7).join(',')",
    "V.map(x => Number(x) / 3).join(',')",
    "V.map(x => (Number(x) ** 2) | 0).join(',')",
    "V.map(x => ~~(Number(x) * 1.5)).join(',')",
    "V.map(x => String(Number(x))).join('|')",
    "V.map(x => (Number(x) >= 0) ? 'p' : 'n').join('')",
    "V.map(x => Object.is(Number(x), -0) ? 'z' : 'o').join('')",
    "V.map(x => Number.isInteger(Number(x))).join(',')",
    "V.map(x => (Number(x) | 0) === Number(x)).join(',')",
    "Array.from(V).sort((a, b) => Number(a) < Number(b) ? -1 : Number(a) > Number(b) ? 1 : 0).join(',')",
    "Array.from(V).filter(x => Number(x) > 0).length",
    "Array.prototype.indexOf.call(V, V[2])",
    "Array.prototype.lastIndexOf.call(V, V[1])",
    "Array.prototype.includes.call(V, V[0])",
    "Array.from(V).reverse().join(',')",
    "Array.from(V).slice(1, -1).join(',')",
    "Array.from(V).flat().length",
    "Iterator.from(Array.from(V)).map(x => Number(x) + 1).reduce((a, b) => a + b, 0)",
    "Iterator.from(Array.from(V)).take(4).toArray().join(',')",
    "Iterator.from(Array.from(V)).drop(2).toArray().length",
    "Iterator.prototype.join ? Iterator.from(Array.from(V)).join('-') : 'na'",
    "JSON.stringify(Array.from(V, x => Number(x)))",
    "Object.keys(Object.groupBy(Array.from(V), x => (Number(x) & 1) ? 'odd' : 'even')).sort().join(',')",
    "String(Array.from(V).map(x => Number(x)).sort((a,b)=>a-b))",
    "new Set(Array.from(V, x => Number(x) | 0)).size",
    "Array.from(V, x => Number(x)).every(x => x === x)",
    "Array.from(V, x => Number(x)).some(x => x < 0)",
    "Array.from(V).findLastIndex(x => Number(x) < 0)",
    "Array.from(V).at(-2) === undefined ? 'u' : String(Array.from(V).at(-2))",
    "Array.from(V).with(0, 42).join(',')",
    "Array.from(V).toSorted((a,b) => Number(a)-Number(b)).join(',')",
    "Array.from(V).toReversed().join(',')",
    "Temporal.Duration.from({seconds: Array.from(V).length}).total({unit: 'minutes'})",
    "Temporal.PlainDate.from('2024-02-29').add({days: Array.from(V).length}).toString()",
]


def gen(seed):
    r = random.Random(seed)
    recv = r.choice(RECEIVERS)
    n = r.randint(1, 3)
    exprs = [r.choice(EXPRS) for _ in range(n)]
    warm = r.choice([0, 1, 5, 30, 200])
    lines = [
        "// seed %d warm=%d" % (seed, warm),
        "function f() {",
        "  " + recv,
        "  let out = [];",
    ]
    for e in exprs:
        lines.append("  try { out.push(String(%s)); } catch (e) { out.push('E:' + e.constructor.name); }" % e)
    lines += ["  return out.join('#');", "}"]
    if warm:
        lines.append("for (let i = 0; i < %d; i++) f();" % warm)
    lines.append("print(f());")
    return "\n".join(lines) + "\n"


def clean(t):
    return "\n".join(l for l in t.splitlines()
                     if not any(n in l for n in NOISE)
                     and "experimental features" not in l)


def run(src, flags, timeout=10):
    p = "/tmp/diffuzz_%d.js" % os.getpid()
    with open(p, "w") as fh:
        fh.write(src)
    try:
        r = subprocess.run([D8] + flags + [p], cwd=CWD,
                           capture_output=True, timeout=timeout)
        return r.returncode, clean(r.stdout.decode("utf-8", "replace")).strip()
    except subprocess.TimeoutExpired:
        return "timeout", ""


def stable(src, flags, times=3):
    """Same answer every time under one configuration?"""
    seen = set()
    for _ in range(times):
        rc, out = run(src, flags)
        seen.add((rc, out))
    return (len(seen) == 1), seen.pop() if len(seen) == 1 else None


def main():
    start = int(sys.argv[1]); count = int(sys.argv[2])
    outdir = sys.argv[3]; wid = sys.argv[4] if len(sys.argv) > 4 else "d"
    os.makedirs(outdir, exist_ok=True)
    found = 0
    t0 = time.time()
    for seed in range(start, start + count):
        src = gen(seed)
        res = {}
        bad = False
        for name, flags in CONFIGS.items():
            rc, out = run(src, flags)
            if rc == "timeout":
                bad = True
                break
            res[name] = (rc, out)
        if bad:
            continue
        vals = set(res.values())
        if len(vals) > 1:
            # confirm determinism within each configuration before believing it
            ok = True
            detail = {}
            for name, flags in CONFIGS.items():
                st, v = stable(src, flags)
                if not st:
                    ok = False
                    break
                detail[name] = v
            if ok and len(set(detail.values())) > 1:
                found += 1
                keep = os.path.join(outdir, "diff_%s_%d.js" % (wid, seed))
                with open(keep, "w") as fh:
                    fh.write("// MISMATCH between configurations, each stable over 3 runs\n")
                    for name in CONFIGS:
                        fh.write("// %-9s rc=%s out=%r\n" % (name, detail[name][0], detail[name][1][:200]))
                    fh.write("// flags base: %s\n" % " ".join(COMMON))
                    fh.write(src)
                print("MISMATCH seed=%d -> %s" % (seed, keep), flush=True)
                for name in CONFIGS:
                    print("    %-9s %r" % (name, detail[name][1][:120]), flush=True)
        if (seed - start) % 100 == 99:
            el = time.time() - t0
            print("w%s progress %d/%d  %.1f cases/s  mismatches=%d"
                  % (wid, seed - start + 1, count, (seed - start + 1) / el, found),
                  flush=True)
    print("w%s done: %d cases, %d mismatches, %.0fs"
          % (wid, count, found, time.time() - t0), flush=True)


main()
