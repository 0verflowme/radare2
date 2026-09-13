"""Triage fuzzer hits against a V8 debug build.

A hit is a candidate, not a finding. This decides which ones are real:

  reproducible   does it happen again, same flags
  not-slow       a timeout that finishes with a longer budget is slow, not hung
  flag-dependent does it still happen without stress or experimental flags
  minimal        the smallest surviving form

Only a crash or DCHECK that reproduces without stress flags is worth reporting.
"""
import os, re, subprocess, sys, glob

D8 = "/home/user/work/v8/dbg/d8"
CWD = "/home/user/work/v8/dbg"
NOISE = ("script kiddie", "forgive curiosity")
INTERESTING = ("Fatal error", "Check failed", "DCHECK", "Received signal",
               "# Fatal", "unreachable code", "FATAL", "CHECK_")
STRESS = {"--stress-compaction", "--jitless", "--expose-externalize-string"}


def clean(t):
    return "\n".join(l for l in t.splitlines()
                     if not any(n in l for n in NOISE))


def run(src, flags, timeout):
    p = "/tmp/triage_case.js"
    with open(p, "w") as fh:
        fh.write(src)
    try:
        r = subprocess.run([D8] + flags + [p], cwd=CWD,
                           capture_output=True, timeout=timeout)
        return r.returncode, clean(r.stdout.decode("utf-8", "replace")), \
            clean(r.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return "timeout", "", ""


def crashed(rc, out, err):
    blob = out + "\n" + err
    if any(s in blob for s in INTERESTING):
        return True
    return rc not in (0, 1, "timeout")


def parse_hit(path):
    txt = open(path, errors="replace").read()
    m = re.search(r"^// flags: (.*)$", txt, re.M)
    flags = m.group(1).split() if m else []
    # the generated program starts at the first "// seed" line
    i = txt.find("// seed ")
    src = txt[i:] if i >= 0 else txt
    return flags, src


def minimise(src, flags, timeout):
    """Drop lines while the crash survives."""
    lines = src.split("\n")
    keep = list(lines)
    i = 0
    while i < len(keep):
        trial = keep[:i] + keep[i + 1:]
        rc, out, err = run("\n".join(trial), flags, timeout)
        if crashed(rc, out, err):
            keep = trial
        else:
            i += 1
    return "\n".join(keep)


def main():
    hits = sorted(sys.argv[1:]) or sorted(glob.glob("/home/user/work/v8/out/hit_*.js"))
    if not hits:
        print("no hits to triage")
        return
    print("triaging %d hit(s)\n" % len(hits))
    real = []
    for h in hits:
        flags, src = parse_hit(h)
        name = os.path.basename(h)
        rc, out, err = run(src, flags, 10)
        if rc == "timeout":
            # a timeout that finishes with a bigger budget was merely slow
            rc2, out2, err2 = run(src, flags, 60)
            if rc2 != "timeout":
                print("%-40s SLOW not hung (finished within 60s)" % name)
                continue
            # still hung: does it need the stress flags?
            plain = [f for f in flags if f not in STRESS]
            rc3, _o, _e = run(src, plain, 60)
            verdict = "HANGS without stress flags" if rc3 == "timeout" \
                else "hangs only with stress flags"
            print("%-40s %s" % (name, verdict))
            if rc3 == "timeout":
                real.append((h, flags, src, "hang"))
            continue
        if not crashed(rc, out, err):
            print("%-40s did not reproduce (rc=%s)" % (name, rc))
            continue
        plain = [f for f in flags if f not in STRESS]
        rc3, out3, err3 = run(src, plain, 20)
        needs_stress = not crashed(rc3, out3, err3)
        sig = ""
        for s in INTERESTING:
            if s in out + err:
                sig = s
                break
        print("%-40s CRASH rc=%s %s%s" % (name, rc, sig,
                                          "  (needs stress flags)" if needs_stress else ""))
        real.append((h, flags if needs_stress else plain, src, "crash"))
    print()
    if not real:
        print("nothing survived triage")
        return
    for h, flags, src, kind in real:
        print("=" * 72)
        print("SURVIVED:", os.path.basename(h), kind)
        if kind == "crash":
            small = minimise(src, flags, 20)
            out = h.replace("hit_", "min_")
            with open(out, "w") as fh:
                fh.write("// flags: %s\n" % " ".join(flags) + small)
            print("minimised to %d lines -> %s" % (len(small.split("\n")), out))
            print(small)


main()
