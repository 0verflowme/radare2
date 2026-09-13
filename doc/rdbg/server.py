# rdbg: persistent, programmable debug session server hosted inside gdb.
# Loaded with:  gdb -q -x server.py <binary>
# Speaks newline-delimited JSON over a unix socket (RDBG_SOCK).
import gdb, json, os, queue, re, socket, threading, time, traceback

SOCK = os.environ.get("RDBG_SOCK") or "/tmp/rdbg.sock"
STATE = {
    "revision": 0,          # bumped on every target mutation
    "journal": [],          # ordered record of mutations
    "notes": {},            # named runtime facts
    "bps": {},              # id -> descriptor
    "done": {},             # request_id -> response (idempotent retry)
    "launch": None,         # argv/stdin used for the last run
    "outfile": None,        # where the target's own stdout went
    "protect": None,        # {"path","master"} for self-deleting targets
    "provisioned": 0,       # times the binary had to be restored
    "interventions": [],    # target-changing acts: this run is no longer pristine
}
LOCK = threading.Lock()

# The inferior resumes asynchronously: gdb.execute("continue") returns before
# the target stops, so there is no frame to inspect in the same callback.
# Resume commands therefore issue the command, then wait for a stop event.
STOP_EV = threading.Event()
LAST_STOP = {}

# Syscall-level support. Two things a stripped static binary forces on you:
# you cannot guess which syscall produces output (veil uses writev, not write),
# and you cannot see the target reading /proc/self/status to find its tracer.
SYSMASK = {"enabled": False, "subs": {}, "hits": [], "trace": None,
           "trace_cap": 0}

# Filesystem effects. An untrusted target can modify the machine it is being
# analysed on. lernaia appended a 134-byte constructor to 919 of this host's
# shared libraries during a single run, and nothing in the debugger said so.
FSMON = {"armed": False, "records": [], "allow": [], "block": False,
         "violations": [], "cap": 4000}

# syscall number -> (name, [arg registers holding a path], writes?)
FS_SYSCALLS = {
    2:   ("open",      ["rdi"], "flags:rsi"),
    257: ("openat",    ["rsi"], "flags:rdx"),
    437: ("openat2",   ["rsi"], None),
    87:  ("unlink",    ["rdi"], True),
    263: ("unlinkat",  ["rsi"], True),
    82:  ("rename",    ["rdi", "rsi"], True),
    264: ("renameat",  ["rsi", "rcx"], True),
    316: ("renameat2", ["rsi", "rcx"], True),
    76:  ("truncate",  ["rdi"], True),
    90:  ("chmod",     ["rdi"], True),
    268: ("fchmodat",  ["rsi"], True),
    86:  ("link",      ["rdi", "rsi"], True),
    88:  ("symlink",   ["rdi", "rsi"], True),
    83:  ("mkdir",     ["rdi"], True),
    85:  ("creat",     ["rdi"], True),
    133: ("mknod",     ["rdi"], True),
}
O_WRONLY, O_RDWR, O_CREAT, O_TRUNC = 1, 2, 0o100, 0o1000

SYSCALL_GROUPS = {
    "output": ["write", "writev", "pwrite64", "sendto", "sendmsg"],
    "input": ["read", "readv", "pread64", "recvfrom", "recvmsg"],
    "open": ["open", "openat", "openat2"],
    "exec": ["execve", "execveat"],
    "proc": ["fork", "vfork", "clone", "clone3"],
    "antidebug": ["ptrace", "prctl", "openat", "process_vm_readv"],
}


def _on_stop(ev):
    d = {"kind": type(ev).__name__}
    try:
        if hasattr(ev, "breakpoints") and ev.breakpoints:
            d["breakpoints"] = [b.number for b in ev.breakpoints]
            d["reason"] = "breakpoint"
        elif hasattr(ev, "stop_signal"):
            d["reason"] = "signal"
            d["signal"] = ev.stop_signal
    except Exception:
        pass
    LAST_STOP.clear(); LAST_STOP.update(d)
    STOP_EV.set()


def _on_exit(ev):
    d = {"kind": "exited", "reason": "exited"}
    try:
        d["exit_code"] = ev.exit_code
    except Exception:
        pass
    LAST_STOP.clear(); LAST_STOP.update(d)
    STOP_EV.set()


gdb.events.stop.connect(_on_stop)
gdb.events.exited.connect(_on_exit)

# ---------------------------------------------------------------- utilities

def _ex(cmd):
    return gdb.execute(cmd, to_string=True)

def _u64(v):
    return int(v) & 0xFFFFFFFFFFFFFFFF

def _mappings():
    """[(start,end,offset,perms,path)] from info proc mappings."""
    out = []
    try:
        txt = _ex("info proc mappings")
    except gdb.error:
        return out
    for ln in txt.splitlines():
        p = ln.split()
        if len(p) >= 5 and p[0].startswith("0x"):
            try:
                start = int(p[0], 16); end = int(p[1], 16)
                off = int(p[3], 16); perms = p[4]
            except ValueError:
                continue
            path = p[5] if len(p) > 5 else ""
            out.append((start, end, off, perms, path))
    return out

def _module_bases():
    """path -> lowest mapped address (the load base)."""
    bases = {}
    for start, _e, off, _p, path in _mappings():
        if not path or path.startswith("["):
            continue
        if path not in bases or start < bases[path]:
            bases[path] = start
        if off == 0:
            bases[path] = min(bases.get(path, start), start)
    return bases

def _main_module():
    try:
        prog = gdb.current_progspace().filename
    except Exception:
        prog = None
    return prog

def _module_for(addr):
    """Return (path, offset, perms) for a runtime address."""
    for start, end, off, perms, path in _mappings():
        if start <= addr < end:
            if path:
                base = _module_bases().get(path, start)
                return (path, addr - base, perms)
            return (None, addr, perms)
    return (None, addr, None)

def _elf_static_base(path):
    """Minimum PT_LOAD p_vaddr: the link-time base. 0x400000 for a classic
    non-PIE binary, 0 for PIE. Lets logical locations resolve before any run."""
    try:
        with open(path, "rb") as fh:
            hdr = fh.read(64)
            if hdr[:4] != b"\x7fELF" or hdr[4] != 2:
                return None
            import struct
            phoff = struct.unpack_from("<Q", hdr, 32)[0]
            phentsize = struct.unpack_from("<H", hdr, 54)[0]
            phnum = struct.unpack_from("<H", hdr, 56)[0]
            fh.seek(phoff)
            ph = fh.read(phentsize * phnum)
        best = None
        for i in range(phnum):
            o = i * phentsize
            p_type = struct.unpack_from("<I", ph, o)[0]
            if p_type != 1:          # PT_LOAD
                continue
            vaddr = struct.unpack_from("<Q", ph, o + 16)[0]
            if best is None or vaddr < best:
                best = vaddr
        return best
    except Exception:
        return None


def _match_module(token):
    """Resolve a module token (basename or substring) to its load base."""
    bases = _module_bases()
    if not bases:
        # No process yet. A non-PIE binary still has a fixed base on disk.
        prog = _main_module()
        if prog and token in ("", "main", "exe", os.path.basename(prog)):
            sb = _elf_static_base(prog)
            if sb:
                return prog, sb
            raise gdb.error(
                "%r is position-independent and the target is not running, so "
                "its load base is unknown. Use run with at_entry=true, then set "
                "the breakpoint." % os.path.basename(prog))
    if token in ("", "main", "exe"):
        mm = _main_module()
        if mm and mm in bases:
            return mm, bases[mm]
        # fall back to lowest-addressed file mapping
        if bases:
            path = min(bases, key=lambda p: bases[p])
            return path, bases[path]
        raise gdb.error("no module mappings yet; run the target first")
    for path, base in bases.items():
        if os.path.basename(path) == token:
            return path, base
    for path, base in bases.items():
        if token in path:
            return path, base
    raise gdb.error("no module matching %r (mapped: %s)" %
                    (token, sorted(os.path.basename(p) for p in bases)))

LOC_RE = re.compile(r"^@(?P<mod>[^+]*)\+(?P<off>0x[0-9a-fA-F]+|\d+)$")
NOTE_RE = re.compile(r"^\$(?P<name>[A-Za-z_]\w*)(?:\+(?P<off>0x[0-9a-fA-F]+|\d+))?$")

def resolve_loc(loc):
    """Logical location -> (runtime_address, description).

    Accepted forms:
      @module+0xOFF   module-relative (survives relaunch / ASLR)
      $note           a stored runtime fact, optionally $note+0xOFF
      0xADDR          raw runtime address
      anything else   handed to gdb's own expression/linespec evaluator
    """
    loc = loc.strip()
    m = LOC_RE.match(loc)
    if m:
        path, base = _match_module(m.group("mod"))
        off = int(m.group("off"), 0)
        return base + off, "%s+%#x" % (os.path.basename(path), off)
    m = NOTE_RE.match(loc)
    if m:
        name = m.group("name")
        with LOCK:
            if name not in STATE["notes"]:
                raise gdb.error("no note named %r" % name)
            val = STATE["notes"][name]["value"]
        off = int(m.group("off"), 0) if m.group("off") else 0
        return int(val) + off, "$%s+%#x" % (name, off)
    if loc.startswith("0x"):
        return int(loc, 16), loc
    v = gdb.parse_and_eval(loc)
    try:
        return _u64(v), loc
    except gdb.error:
        return _u64(v.address), loc

def describe_addr(addr):
    path, off, perms = _module_for(addr)
    d = {"addr": "%#x" % addr}
    if path:
        d["loc"] = "@%s+%#x" % (os.path.basename(path), off)
        d["module"] = os.path.basename(path)
        d["module_offset"] = "%#x" % off
    if perms:
        d["perms"] = perms
    if not path:
        # name anonymous regions relative to a note when we can
        with LOCK:
            notes = dict(STATE["notes"])
        best = None
        for nm, rec in notes.items():
            try:
                nv = int(rec["value"])
            except Exception:
                continue
            if nv <= addr and (best is None or nv > best[1]):
                best = (nm, nv)
        if best:
            d["loc"] = "$%s+%#x" % (best[0], addr - best[1])
    return d

def _cur_frame():
    """Valid right after a stop inside a post_event callback.

    gdb.selected_frame() raises "No frame is currently selected" when a run
    control command was issued from Python, so prefer newest_frame().
    """
    for getter in (gdb.newest_frame, gdb.selected_frame):
        try:
            f = getter()
            if f is not None:
                return f
        except gdb.error:
            continue
    return None


def _regs():
    out = {}
    frame = _cur_frame()
    if frame is None:
        return out
    for r in ("rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10",
              "r11","r12","r13","r14","r15","rip","eflags"):
        try:
            out[r] = "%#x" % _u64(frame.read_register(r))
        except Exception:
            pass
    return out

def _running():
    try:
        inf = gdb.selected_inferior()
        return inf.pid != 0 and len(inf.threads()) > 0
    except Exception:
        return False

# ---------------------------------------------------------------- breakpoints

class ScopedBP(gdb.Breakpoint):
    """Breakpoint that can require its *caller* to live in a given module,
    and can record instead of stopping.

    Caller scoping is what makes `break mprotect` usable: the dynamic loader
    calls mprotect during startup, and an unscoped breakpoint stops there
    first, so an agent reports the loader's argument as the program's.

    silent=True turns it into a tracepoint: it records and returns False, so
    gdb resumes without a round trip to the client.
    """
    def __init__(self, spec, caller_module=None, bid=None, silent=False,
                 record=None, cap=20000, **kw):
        self.caller_module = caller_module
        self.bid = bid
        self.skipped = 0
        self.silent_mode = silent
        self.record_regs = record or []
        self.cap = int(cap)
        self.log = []
        super().__init__(spec, **kw)

    def _record(self):
        if len(self.log) >= self.cap:
            return
        e = {}
        try:
            f = gdb.newest_frame()
            e["pc"] = "%#x" % _u64(f.pc())
            for r in self.record_regs:
                try:
                    e[r] = int(f.read_register(r))
                except Exception:
                    pass
        except Exception:
            pass
        self.log.append(e)

    def stop(self):
        if self.silent_mode:
            self._record()
            return False            # record and keep running
        if not self.caller_module:
            return True
        try:
            f = gdb.newest_frame()
            # walk outward to the first frame outside the breakpoint's own module
            cur = f
            for _ in range(8):
                cur = cur.older()
                if cur is None:
                    return True
                pc = _u64(cur.pc())
                path, _off, _p = _module_for(pc)
                if path is None:
                    continue
                want = self.caller_module
                if os.path.basename(path) == want or want in path:
                    return True
                return self._skip()
            return True
        except Exception:
            return True

    def _skip(self):
        self.skipped += 1
        return False

# ---------------------------------------------------------------- handlers

def h_ping(req):
    return {"pong": True, "pid": os.getpid(), "running": _running()}

def h_snapshot(req):
    """One structured call that answers 'where am I and what is around me'."""
    with LOCK:
        rev = STATE["revision"]
    if not _running():
        return {"revision": rev, "running": False}
    frame = _cur_frame()
    if frame is None:
        return {"revision": rev, "running": True, "no_frame": True}
    pc = _u64(frame.pc())
    with LOCK:
        niv = len(STATE["interventions"])
    snap = {"revision": rev, "running": True, "pc": describe_addr(pc),
            "scope": "modeled" if niv else "observed",
            "interventions": niv, "regs": _regs()}
    try:
        snap["thread"] = gdb.selected_thread().num
        snap["threads"] = len(gdb.selected_inferior().threads())
    except Exception:
        pass
    # backtrace with module-relative frames
    bt = []
    f = frame
    for _ in range(int(req.get("depth", 8))):
        if f is None:
            break
        e = describe_addr(_u64(f.pc()))
        try:
            if f.name():
                e["name"] = f.name()
        except Exception:
            pass
        bt.append(e)
        try:
            f = f.older()
        except Exception:
            break
    snap["backtrace"] = bt
    n = int(req.get("disasm", 6))
    if n:
        try:
            arch = frame.architecture()
            ins = arch.disassemble(pc, count=n)
            snap["disasm"] = [{"addr": "%#x" % i["addr"], "text": i["asm"]} for i in ins]
        except Exception:
            pass
    return snap

def h_loc_resolve(req):
    addr, desc = resolve_loc(req["loc"])
    d = describe_addr(addr)
    d["input"] = req["loc"]; d["resolved_from"] = desc
    return d

def h_eval(req):
    v = gdb.parse_and_eval(req["expr"])
    out = {"expr": req["expr"], "str": str(v)}
    try:
        out["int"] = int(v)
        out["hex"] = "%#x" % _u64(v)
    except Exception:
        pass
    try:
        out["type"] = str(v.type)
    except Exception:
        pass
    return out

def h_mem_read(req):
    addr, _ = resolve_loc(req["loc"])
    n = int(req.get("len", 64))
    live = _running()
    buf = bytes(gdb.selected_inferior().read_memory(addr, n))
    out = {"addr": "%#x" % addr, "len": n, "hex": buf.hex(),
           "source": "live-process" if live else "file-backed"}
    if not live:
        # gdb silently falls back to the executable's own contents. A .bss or
        # runtime-initialised buffer then reads as zeroes, and an agent reports
        # that as the target's value.
        out["warning"] = ("no process running: these bytes come from the ELF on "
                          "disk, not from memory. Runtime-initialised data "
                          "(.bss, decoded buffers) will read as zero.")
    if req.get("words"):
        w = int(req["words"])
        fmt = {4: "<I", 8: "<Q"}[w]
        import struct
        out["values"] = [struct.unpack_from(fmt, buf, i)[0]
                         for i in range(0, n - w + 1, w)]
    return out

def h_mem_write(req):
    addr, _ = resolve_loc(req["loc"])
    data = bytes.fromhex(req["hex"])
    gdb.selected_inferior().write_memory(addr, data)
    _note_intervention("mem.write", req)
    with LOCK:
        n = len(STATE["interventions"])
    return {"addr": "%#x" % addr, "wrote": len(data),
            "scope": "modeled", "interventions": n}

def h_mem_export(req):
    """Dump a region AND record its base, so a disassembler can load it right."""
    addr, _ = resolve_loc(req["loc"])
    n = int(req["len"])
    path = req["path"]
    live = _running()
    buf = bytes(gdb.selected_inferior().read_memory(addr, n))
    with open(path, "wb") as fh:
        fh.write(buf)
    meta = {"base": "%#x" % addr, "len": n, "file": path,
            "source": "live-process" if live else "file-backed",
            "region": describe_addr(addr),
            "r2": "r2 -a x86 -b 64 -m %#x %s" % (addr, path)}
    if not live:
        meta["warning"] = ("no process running: these bytes come from the ELF on "
                           "disk, not from memory")
    with open(path + ".json", "w") as fh:
        json.dump(meta, fh, indent=1)
    return meta

def h_bp_set(req):
    loc = req["loc"]
    caller = req.get("caller_module")
    if loc.startswith("@") or loc.startswith("$") or loc.startswith("0x"):
        addr, desc = resolve_loc(loc)
        spec = "*%#x" % addr
    else:
        spec, desc = loc, loc
    with LOCK:
        bid = "b%d" % (len(STATE["bps"]) + 1)
    bp = ScopedBP(spec, caller_module=caller, bid=bid,
                  silent=bool(req.get("silent")),
                  record=req.get("record"), cap=req.get("cap", 20000))
    rec = {"id": bid, "loc": loc, "spec": spec, "desc": desc,
           "caller_module": caller, "gdb_num": bp.number,
           "silent": bool(req.get("silent")),
           "record": req.get("record"),
           "locations": bp.locations and len(bp.locations) or 1}
    with LOCK:
        STATE["bps"][bid] = dict(rec, obj=bp)
    if rec["locations"] > 1 and not caller:
        rec["warning"] = ("spec matched %d locations; pass caller_module to "
                          "scope it (e.g. the loader also calls this)"
                          % rec["locations"])
    return rec

def h_bp_list(req):
    with LOCK:
        items = []
        for bid, r in STATE["bps"].items():
            o = r.get("obj")
            items.append({"id": bid, "loc": r["loc"], "spec": r["spec"],
                          "caller_module": r.get("caller_module"),
                          "silent": getattr(o, "silent_mode", False),
                          "hits": getattr(o, "hit_count", None),
                          "recorded": len(getattr(o, "log", [])),
                          "skipped": getattr(o, "skipped", 0),
                          "enabled": getattr(o, "enabled", None)})
    return {"breakpoints": items}

def h_bp_log(req):
    """Read back what a silent tracepoint recorded."""
    with LOCK:
        r = STATE["bps"].get(req["id"])
    if not r:
        raise gdb.error("no breakpoint %r" % req["id"])
    o = r["obj"]
    log = list(getattr(o, "log", []))
    n = int(req.get("tail", 0))
    out = log[-n:] if n else log
    res = {"id": req["id"], "hits": getattr(o, "hit_count", None),
           "recorded": len(log), "entries": out}
    if len(log) >= getattr(o, "cap", 0):
        res["truncated_at"] = o.cap
    return res


def h_bp_clear_log(req):
    with LOCK:
        r = STATE["bps"].get(req["id"])
    if r:
        r["obj"].log = []
    return {"cleared": req["id"]}


def h_bp_delete(req):
    with LOCK:
        r = STATE["bps"].pop(req["id"], None)
    if not r:
        return {"deleted": False}
    try:
        r["obj"].delete()
    except Exception:
        pass
    return {"deleted": True, "id": req["id"]}

# Acts that change what the target computes, as opposed to merely observing it.
# Once one has been applied, nothing downstream is an observation of the
# program's own behaviour any more, and every reply says so.
INTERVENING = {"mem.write", "call", "restore"}


def _note_intervention(kind, req):
    rec = {"kind": kind, "t": time.time(),
           "where": {k: v for k, v in req.items()
                     if k in ("loc", "fn", "hex", "args", "id")}}
    with LOCK:
        STATE["interventions"].append(rec)


def h_scope(req):
    """Is the current session still observing, or has it been steered?"""
    with LOCK:
        iv = list(STATE["interventions"])
    return {
        "scope": "modeled" if iv else "observed",
        "interventions": iv,
        "count": len(iv),
        "meaning": ("observed: the target ran its own course and these facts are "
                    "about that execution. modeled: the session wrote target "
                    "memory or called into the target, so results describe an "
                    "execution the debugger helped produce, not one the program "
                    "would have taken on its own."),
        "masking": bool(SYSMASK.get("enabled")),
        "masking_note": ("a masked run is closer to the unobserved program, not "
                         "further: it removes a difference the target can see"),
    }


def _mutate(req, fn, kind):
    """Run a target mutation under revision + journal + retry protection."""
    rid = req.get("request_id")
    with LOCK:
        if rid and rid in STATE["done"]:
            out = dict(STATE["done"][rid])
            out["replayed"] = True        # retry returns the recorded outcome
            return out
        exp = req.get("expected_revision")
        if exp is not None and int(exp) != STATE["revision"]:
            raise gdb.error("stale revision: expected %s, target is at %d"
                            % (exp, STATE["revision"]))
    res = fn()
    if kind in INTERVENING:
        _note_intervention(kind, req)
    with LOCK:
        STATE["revision"] += 1
        res = dict(res or {})
        res["revision"] = STATE["revision"]
        STATE["journal"].append({"kind": kind, "req": {
            k: v for k, v in req.items() if k != "request_id"},
            "revision": STATE["revision"], "t": time.time()})
        if rid:
            STATE["done"][rid] = res
    return res

def h_run(req):
    def go():
        args = req.get("args") or []
        stdin_data = req.get("stdin")
        d = os.path.dirname(SOCK)
        # Everything goes on the run line. `set args` is discarded as soon as
        # the run command carries a redirection, which silently strips the
        # program's arguments and can leave it blocking on gdb's own stdin.
        prov = _provision()
        verb = "starti" if req.get("at_entry") else "run"
        parts = [verb] + [str(a) for a in args]
        if stdin_data is not None:
            p = os.path.join(d, "stdin-%s" % os.path.basename(SOCK))
            with open(p, "w") as fh:
                fh.write(stdin_data)
            parts.append("< " + p)
        else:
            # never inherit gdb's stdin: a target that reads it hangs forever
            parts.append("< /dev/null")
        if req.get("capture_output", True):
            outp = os.path.join(d, "out-%s.txt" % os.path.basename(SOCK))
            try:
                os.unlink(outp)
            except OSError:
                pass
            parts.append("> " + outp)
            parts.append("2>&1")
            STATE["outfile"] = outp
        cmd = " ".join(parts)
        with LOCK:
            STATE["launch"] = {"args": args, "stdin": stdin_data, "cmd": cmd}
            STATE["interventions"] = []   # a new run starts observing again
        STOP_EV.clear()
        _ex(cmd)
        res = {"resumed": True, "cmd": cmd,
               "at_entry": bool(req.get("at_entry"))}
        if prov:
            res["provisioned"] = prov
        return res
    return _mutate(req, go, "run")

def _resume(cmd, req):
    def go():
        STOP_EV.clear()
        try:
            _ex(cmd)
        except gdb.error as e:
            return {"gdb_error": str(e), "resumed": False}
        return {"resumed": True}
    return _mutate(req, go, cmd.split()[0])


def h_cont(req):   return _resume("continue", req)


def h__raw_cont(req):
    STOP_EV.clear()
    try:
        _ex("continue")
    except gdb.error as e:
        return {"resumed": False, "gdb_error": str(e)}
    return {"resumed": True}
def h_step(req):   return _resume("step %d" % int(req.get("n", 1)), req)
def h_next(req):   return _resume("next %d" % int(req.get("n", 1)), req)
def h_stepi(req):  return _resume("stepi %d" % int(req.get("n", 1)), req)
def h_finish(req): return _resume("finish", req)

def h_call(req):
    """Call a function in the target by address, no debug info needed."""
    addr, desc = resolve_loc(req["fn"])
    args = req.get("args", [])
    argt = req.get("arg_types") or ["long"] * len(args)
    ret = req.get("ret_type", "long")
    vals = []
    for a in args:
        if isinstance(a, str):
            av, _ = resolve_loc(a) if (a.startswith("@") or a.startswith("$")) else (gdb.parse_and_eval(a), None)
            vals.append("%#x" % _u64(av))
        else:
            vals.append(str(int(a)))
    expr = "((%s(*)(%s))%#x)(%s)" % (ret, ",".join(argt), addr, ",".join(vals))
    def go():
        v = gdb.parse_and_eval(expr)
        out = {"fn": desc, "expr": expr, "str": str(v)}
        try:
            out["int"] = int(v); out["hex"] = "%#x" % _u64(v)
        except Exception:
            pass
        return out
    return _mutate(req, go, "call")

def h_note_set(req):
    name = req["name"]
    if "expr" in req:
        v = gdb.parse_and_eval(req["expr"])
        try:
            value = _u64(v)
        except Exception:
            value = str(v)
        src = req["expr"]
    else:
        value = req["value"]
        src = "literal"
    pos = None
    if _running():
        try:
            f = _cur_frame()
            pos = describe_addr(_u64(f.pc())) if f else None
        except Exception:
            pass
    with LOCK:
        STATE["notes"][name] = {
            "name": name, "value": value, "source": src,
            "observed_at": pos, "revision": STATE["revision"], "t": time.time(),
            "text": req.get("text"),
        }
        rec = dict(STATE["notes"][name])
    if isinstance(value, int):
        rec["hex"] = "%#x" % value
        rec["where"] = describe_addr(value) if _running() else None
    return rec

def h_note_list(req):
    with LOCK:
        notes = {}
        for k, v in STATE["notes"].items():
            d = dict(v)
            if isinstance(v["value"], int):
                d["hex"] = "%#x" % v["value"]
            notes[k] = d
    return {"notes": notes}

def h_protect(req):
    """Guard a target that destroys its own executable.

    lernaia readlinks /proc/self/exe and unlinks it, so each execution consumes
    the binary and there is no second run. Keeping a pristine master and
    restoring the path before every run makes runs unlimited again.
    """
    import shutil
    path = req.get("path") or _main_module()
    if not path:
        raise gdb.error("no program to protect")
    master = req.get("master") or (os.path.join(
        os.path.dirname(SOCK), "master-%s" % os.path.basename(path)))
    if not os.path.exists(master):
        if not os.path.exists(path):
            raise gdb.error("neither %r nor a master copy %r exists" % (path, master))
        shutil.copy2(path, master)
    STATE["protect"] = {"path": path, "master": master}
    return {"protecting": path, "master": master,
            "note": "the executable is restored from the master before each run"}


def _provision():
    """Restore the guarded executable if the last run destroyed or changed it."""
    p = STATE.get("protect")
    if not p:
        return None
    import shutil
    path, master = p["path"], p["master"]
    missing = not os.path.exists(path)
    changed = False
    if not missing:
        try:
            changed = (os.path.getsize(path) != os.path.getsize(master))
        except OSError:
            changed = True
    if missing or changed:
        shutil.copy2(master, path)
        os.chmod(path, 0o755)
        STATE["provisioned"] += 1
        return {"restored": path, "was": "missing" if missing else "modified",
                "count": STATE["provisioned"]}
    return None


def h_protect_status(req):
    p = STATE.get("protect")
    out = {"protect": p, "provisioned": STATE["provisioned"]}
    if p:
        out["executable_present"] = os.path.exists(p["path"])
    return out


def h_output(req):
    """The target's own stdout/stderr for the current run, verbatim."""
    p = STATE.get("outfile")
    if not p or not os.path.exists(p):
        return {"output": None, "reason": "no captured output"}
    with open(p, "rb") as fh:
        data = fh.read()
    txt = data.decode("utf-8", "replace")
    if req.get("tail"):
        txt = "\n".join(txt.splitlines()[-int(req["tail"]):])
    return {"file": p, "bytes": len(data), "output": txt}


def h_journal(req):
    with LOCK:
        return {"revision": STATE["revision"], "journal": list(STATE["journal"]),
                "launch": STATE["launch"]}

def h_mappings(req):
    return {"mappings": [
        {"start": "%#x" % s, "end": "%#x" % e, "size": e - s,
         "perms": p, "path": path}
        for s, e, _o, p, path in _mappings()]}

def h_gdb(req):
    """Escape hatch: run a raw gdb command."""
    return {"out": _ex(req["cmd"])}

def _at_syscall_entry():
    """True when stopped at syscall entry (rax == -ENOSYS on x86-64)."""
    try:
        f = _cur_frame()
        if f is None:
            return False
        return int(f.read_register("rax")) == -38
    except Exception:
        return False


def _syscall_nr():
    try:
        return int(_cur_frame().read_register("orig_rax"))
    except Exception:
        return None


def _read_cstr(addr, cap=512):
    out = bytearray()
    inf = gdb.selected_inferior()
    while len(out) < cap:
        chunk = bytes(inf.read_memory(addr + len(out), 64))
        i = chunk.find(b"\x00")
        if i >= 0:
            out += chunk[:i]
            break
        out += chunk
    return bytes(out).decode("utf-8", "replace")


def h_sys_group(req):
    return {"groups": SYSCALL_GROUPS}


def h_bp_syscall(req):
    """Catchpoint by name or by semantic group.

    Guessing one name is how an agent misses the real mechanism: `write` never
    fires on a target that uses `writev`. A group catches the whole family.
    """
    names = []
    if req.get("group"):
        g = req["group"]
        if g not in SYSCALL_GROUPS:
            raise gdb.error("unknown group %r (have %s)"
                            % (g, sorted(SYSCALL_GROUPS)))
        names = list(SYSCALL_GROUPS[g])
    if req.get("name"):
        names.append(req["name"])
    if not names:
        raise gdb.error("pass name= or group=")
    set_ok, failed = [], {}
    for n in names:
        try:
            _ex("catch syscall %s" % n)
            set_ok.append(n)
        except gdb.error as e:
            failed[n] = str(e)
    return {"caught": set_ok, "unavailable": failed,
            "note": "a name absent from this kernel/gdb is reported, not silent"}


def h_sys_trace(req):
    """Arm a full syscall trace; the transport auto-continues and records."""
    cap = int(req.get("cap", 400))
    _ex("catch syscall")
    SYSMASK["trace"] = []
    SYSMASK["trace_cap"] = cap
    return {"armed": True, "cap": cap}


def h_sys_trace_get(req):
    return {"trace": SYSMASK["trace"] or [], "count": len(SYSMASK["trace"] or [])}


def h_fsmon_arm(req):
    """Watch, and optionally stop on, filesystem writes by the target.

    allow: path prefixes the target may legitimately write under.
    block: stop the run at the first write outside them, before it lands.
    """
    FSMON["armed"] = True
    FSMON["records"] = []
    FSMON["violations"] = []
    FSMON["allow"] = [os.path.abspath(p) for p in (req.get("allow") or [])]
    FSMON["block"] = bool(req.get("block"))
    names = sorted(set(n for n, _a, _w in FS_SYSCALLS.values()))
    caught, missing = [], []
    for n in names:
        try:
            _ex("catch syscall %s" % n)
            caught.append(n)
        except gdb.error:
            missing.append(n)
    return {"armed": True, "allow": FSMON["allow"], "block": FSMON["block"],
            "watching": caught, "unavailable": missing}


def h_fsmon_report(req):
    recs = FSMON["records"]
    if req.get("outside_only"):
        recs = [r for r in recs if not r.get("allowed")]
    by_path = {}
    for r in recs:
        by_path.setdefault(r["path"], {"path": r["path"], "ops": set(), "n": 0})
        by_path[r["path"]]["ops"].add(r["syscall"])
        by_path[r["path"]]["n"] += 1
    summary = sorted(({"path": v["path"], "ops": sorted(v["ops"]), "count": v["n"]}
                      for v in by_path.values()), key=lambda d: -d["count"])
    return {"armed": FSMON["armed"], "total": len(FSMON["records"]),
            "distinct_paths": len(by_path),
            "violations": FSMON["violations"][:50],
            "paths": summary[: int(req.get("limit", 60))]}


def _fs_allowed(path):
    if not FSMON["allow"]:
        return True
    ap = os.path.abspath(path)
    return any(ap == a or ap.startswith(a.rstrip("/") + "/")
               for a in FSMON["allow"])


def _fs_check(nr, entry):
    """Record a filesystem-modifying syscall. Returns True to absorb the stop."""
    if not FSMON["armed"] or nr not in FS_SYSCALLS:
        return None
    if not entry:
        return {"absorb": True}
    name, regs, wflag = FS_SYSCALLS[nr]
    try:
        f = _cur_frame()
    except Exception:
        return {"absorb": True}
    # only count opens that intend to write
    if isinstance(wflag, str) and wflag.startswith("flags:"):
        try:
            fl = int(f.read_register(wflag.split(":", 1)[1])) & 0xFFFFFFFF
        except Exception:
            fl = 0
        if not (fl & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)):
            return {"absorb": True}
    paths = []
    for r in regs:
        try:
            p = _read_cstr(_u64(f.read_register(r)))
            if p:
                paths.append(p)
        except Exception:
            pass
    for p in paths:
        allowed = _fs_allowed(p)
        rec = {"syscall": name, "path": p, "allowed": allowed,
               "at": describe_addr(_u64(f.pc()))}
        if len(FSMON["records"]) < FSMON["cap"]:
            FSMON["records"].append(rec)
        if not allowed:
            FSMON["violations"].append(rec)
            if FSMON["block"]:
                return {"absorb": False, "violation": rec}
    return {"absorb": True}


def h_antidebug_mask(req):
    """Make the target's own tracer check come back clean.

    veil opens /proc/self/status and reads TracerPid. Under any debugger that
    is non-zero, so the target can take a different path and the agent sees a
    normal-looking run. This substitutes a doctored file at the openat
    boundary, in place, so the read returns TracerPid: 0.
    """
    subs = {}
    wanted = req.get("paths") or ["/proc/self/status"]
    d = os.path.dirname(SOCK)
    for i, p in enumerate(wanted):
        # replacement path must fit in the original buffer (patched in place)
        repl = os.path.join("/tmp", ".rd%d%d" % (os.getpid() % 1000, i))
        if len(repl) > len(p):
            raise gdb.error("replacement %r longer than %r; cannot patch in place"
                            % (repl, p))
        subs[p] = repl
    SYSMASK["enabled"] = True
    SYSMASK["subs"] = subs
    SYSMASK["hits"] = []
    _ex("catch syscall openat")
    return {"masking": subs, "armed": True,
            "caveat": "the target is still traced; only its view of TracerPid changes"}


def _materialise_status(real_path, repl_path):
    """Write a copy of the target's /proc/<pid>/status with TracerPid: 0."""
    try:
        pid = gdb.selected_inferior().pid
        src = real_path.replace("/proc/self/", "/proc/%d/" % pid)
        with open(src, "rb") as fh:
            data = fh.read()
    except Exception:
        data = b"Name:\tunknown\nTracerPid:\t0\n"
    out = []
    for ln in data.split(b"\n"):
        if ln.startswith(b"TracerPid:"):
            ln = b"TracerPid:\t0"
        out.append(ln)
    with open(repl_path, "wb") as fh:
        fh.write(b"\n".join(out))
    return repl_path


def h__autohandle(req):
    """Decide whether the current stop is ours to absorb silently."""
    if not _running():
        return {"handled": False, "reason": "not running"}
    nr = _syscall_nr()
    entry = _at_syscall_entry()
    # record for the trace, if one is armed
    if SYSMASK["trace"] is not None and nr is not None:
        if len(SYSMASK["trace"]) < SYSMASK["trace_cap"]:
            rec = {"nr": nr, "entry": entry}
            try:
                f = _cur_frame()
                rec["args"] = ["%#x" % _u64(f.read_register(r))
                               for r in ("rdi", "rsi", "rdx")]
                if not entry:
                    rec["ret"] = int(f.read_register("rax"))
            except Exception:
                pass
            rec["pc"] = describe_addr(_u64(_cur_frame().pc()))
            SYSMASK["trace"].append(rec)
            return {"handled": True, "reason": "traced"}
        return {"handled": False, "reason": "trace cap reached"}
    fs = _fs_check(nr, entry)
    if fs is not None and not fs.get("absorb"):
        return {"handled": False, "reason": "filesystem write outside allowlist",
                "violation": fs.get("violation")}
    if fs is not None and fs.get("absorb") and not SYSMASK["enabled"]:
        return {"handled": True, "reason": "fsmon recorded"}
    # openat masking: absorb both the entry and the return stop
    if SYSMASK["enabled"] and nr == 257 and not entry:
        return {"handled": True, "reason": "openat return"}
    if SYSMASK["enabled"] and entry and nr == 257:
        try:
            f = _cur_frame()
            pathp = _u64(f.read_register("rsi"))
            path = _read_cstr(pathp)
        except Exception:
            return {"handled": False, "reason": "unreadable path"}
        if path in SYSMASK["subs"]:
            repl = SYSMASK["subs"][path]
            _materialise_status(path, repl)
            buf = repl.encode() + b"\x00"
            gdb.selected_inferior().write_memory(pathp, buf)
            SYSMASK["hits"].append({"path": path, "replaced_with": repl,
                                    "at": describe_addr(_u64(f.pc()))})
            return {"handled": True, "reason": "masked openat", "path": path}
        return {"handled": True, "reason": "openat not masked: %s" % path}
    return {"handled": False, "reason": "nr=%s entry=%s" % (nr, entry)}


def _exec_ranges():
    return [(st, en, path) for st, en, _o, p, path in _mappings() if "x" in p]


def _is_call_site(addr):
    """Does a call instruction end exactly at addr? Confirms a return address."""
    inf = gdb.selected_inferior()
    try:
        pre = bytes(inf.read_memory(addr - 8, 8))
    except gdb.MemoryError:
        return None
    # direct call rel32: E8 xx xx xx xx  (5 bytes)
    if pre[3] == 0xE8:
        import struct
        rel = struct.unpack("<i", pre[4:8])[0]
        return {"form": "call rel32", "at": "%#x" % (addr - 5),
                "target": "%#x" % ((addr + rel) & 0xFFFFFFFFFFFFFFFF)}
    # indirect call: FF /2 with various modrm/prefix lengths
    for ln in (2, 3, 4, 6, 7):
        i = 8 - ln
        if pre[i] == 0xFF and ((pre[i + 1] >> 3) & 7) == 2:
            return {"form": "call indirect", "at": "%#x" % (addr - ln)}
        if ln >= 3 and pre[i] in (0x41, 0x48, 0x49) and pre[i + 1] == 0xFF \
                and ((pre[i + 2] >> 3) & 7) == 2:
            return {"form": "call indirect", "at": "%#x" % (addr - ln)}
    return None


def h_stack_callers(req):
    """Recover a call chain by scanning the stack for return addresses.

    gdb cannot unwind a static stripped binary with no CFI: every frame past
    the innermost comes back empty. Scanning for stack slots that point just
    after a real call instruction recovers the chain the way a human does.
    """
    if not _running():
        raise gdb.error("target is not running")
    f = _cur_frame()
    rsp = _u64(f.read_register("rsp"))
    depth = int(req.get("bytes", 2048))
    want_mod = req.get("module")
    inf = gdb.selected_inferior()
    import struct
    raw = bytes(inf.read_memory(rsp, depth))
    ranges = _exec_ranges()
    out = []
    for off in range(0, len(raw) - 8, 8):
        v = struct.unpack_from("<Q", raw, off)[0]
        if v < 0x1000:
            continue
        hit = next((r for r in ranges if r[0] <= v < r[1]), None)
        if not hit:
            continue
        if want_mod and os.path.basename(hit[2] or "") != want_mod:
            continue
        ev = _is_call_site(v)
        if not ev:
            continue
        e = describe_addr(v)
        e["stack_offset"] = "%#x" % off
        e["stack_at"] = "%#x" % (rsp + off)
        e["call"] = ev
        if ev.get("at"):
            e["call_site"] = describe_addr(int(ev["at"], 16))
        out.append(e)
    return {"rsp": "%#x" % rsp, "scanned_bytes": depth,
            "callers": out, "count": len(out),
            "method": "return-address scan confirmed by a preceding call opcode",
            "caveat": "heuristic: stale slots can appear; confirmed entries are "
                      "return addresses, not necessarily the live chain"}


def h_antidebug_status(req):
    return {"enabled": SYSMASK["enabled"], "subs": SYSMASK["subs"],
            "hits": SYSMASK["hits"]}


def h_checkpoint(req):
    def go():
        out = _ex("checkpoint")
        m = re.search(r"checkpoint (\d+)", out)
        return {"out": out.strip(), "id": int(m.group(1)) if m else None}
    return _mutate(req, go, "checkpoint")

def h_restore(req):
    def go():
        return {"out": _ex("restart %d" % int(req["id"])).strip()}
    return _mutate(req, go, "restore")

HANDLERS = {
    "ping": h_ping, "snapshot": h_snapshot, "loc.resolve": h_loc_resolve,
    "eval": h_eval, "mem.read": h_mem_read, "mem.write": h_mem_write,
    "mem.export": h_mem_export, "bp.set": h_bp_set, "bp.list": h_bp_list,
    "bp.delete": h_bp_delete, "run": h_run, "cont": h_cont, "step": h_step,
    "next": h_next, "stepi": h_stepi, "finish": h_finish, "call": h_call,
    "note.set": h_note_set, "note.list": h_note_list, "journal": h_journal,
    "mappings": h_mappings, "gdb": h_gdb, "checkpoint": h_checkpoint,
    "restore": h_restore, "bp.syscall": h_bp_syscall,
    "sys.groups": h_sys_group, "sys.trace": h_sys_trace,
    "sys.trace.get": h_sys_trace_get, "antidebug.mask": h_antidebug_mask,
    "antidebug.status": h_antidebug_status, "_autohandle": h__autohandle,
    "_raw_cont": h__raw_cont, "output": h_output,
    "protect": h_protect, "protect.status": h_protect_status, "scope": h_scope,
    "fsmon.arm": h_fsmon_arm, "fsmon.report": h_fsmon_report,
    "stack.callers": h_stack_callers, "bp.log": h_bp_log,
    "bp.clear_log": h_bp_clear_log,
}

# ---------------------------------------------------------------- transport

def _dispatch(req):
    op = req.get("op")
    fn = HANDLERS.get(op)
    if fn is None:
        return {"ok": False, "error": "unknown op %r" % op,
                "ops": sorted(HANDLERS)}
    try:
        return {"ok": True, "result": fn(req)}
    except gdb.error as e:
        return {"ok": False, "error": str(e), "error_kind": "gdb"}
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e),
                "trace": traceback.format_exc()}

RESUME_OPS = {"run", "cont", "step", "next", "stepi", "finish", "restore"}


def _on_main(req, timeout):
    """Run one dispatch on gdb's main thread and return its response."""
    box, ev = {}, threading.Event()

    def work():
        try:
            box["r"] = _dispatch(req)
        except Exception as e:
            box["r"] = {"ok": False, "error": str(e)}
        finally:
            ev.set()

    gdb.post_event(work)
    if not ev.wait(timeout=timeout):
        return {"ok": False, "error": "timeout waiting for gdb main thread"}
    return box["r"]


def _serve_resume(req, timeout):
    """Issue a resume, wait for the target to actually stop, then snapshot."""
    first = _on_main(req, timeout)
    if not first.get("ok"):
        return first
    issued = first.get("result", {})
    if not issued.get("resumed"):
        return first
    wait_s = float(req.get("wait_timeout", timeout))
    absorbed = 0
    while True:
        if not STOP_EV.wait(timeout=wait_s):
            return {"ok": True, "result": dict(
                issued, stopped=False, absorbed=absorbed,
                note="target still running after %gs; use op=interrupt" % wait_s)}
        if LAST_STOP.get("reason") == "exited":
            break
        auto = _on_main({"op": "_autohandle"}, timeout)
        if not (auto.get("ok") and auto["result"].get("handled")):
            break
        absorbed += 1
        if absorbed > int(req.get("absorb_cap", 20000)):
            break
        cont = _on_main({"op": "_raw_cont"}, timeout)
        if not cont.get("ok"):
            break
    snap = _on_main({"op": "snapshot", "disasm": req.get("disasm", 4),
                     "depth": req.get("depth", 8)}, timeout)
    out = dict(issued)
    out["stopped"] = True
    out["absorbed"] = absorbed
    out["stop"] = dict(LAST_STOP)
    if snap.get("ok"):
        out.update(snap["result"])
    else:
        out["snapshot_error"] = snap.get("error")
    return {"ok": True, "result": out}


def _serve_conn(conn):
    f = conn.makefile("rwb")
    while True:
        line = f.readline()
        if not line:
            break
        try:
            req = json.loads(line)
        except Exception as e:
            f.write((json.dumps({"ok": False, "error": "bad json: %s" % e})
                     + "\n").encode()); f.flush(); continue
        if req.get("op") == "interrupt":
            # handled off the gdb main thread so it works while running
            try:
                pid = gdb.selected_inferior().pid
                os.kill(pid, 2)
                resp = {"ok": True, "result": {"interrupted": pid}}
            except Exception as e:
                resp = {"ok": False, "error": str(e)}
            f.write((json.dumps(resp) + "\n").encode()); f.flush(); continue
        tmo = float(req.get("timeout", 3600))
        if req.get("op") in RESUME_OPS:
            resp = _serve_resume(req, tmo)
        else:
            resp = _on_main(req, tmo)
        f.write((json.dumps(resp) + "\n").encode()); f.flush()
    try:
        conn.close()
    except Exception:
        pass

def _accept_loop(srv):
    while True:
        try:
            conn, _ = srv.accept()
        except Exception:
            return
        threading.Thread(target=_serve_conn, args=(conn,), daemon=True).start()

def _start():
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    srv.listen(8)
    threading.Thread(target=_accept_loop, args=(srv,), daemon=True).start()
    with open(SOCK + ".ready", "w") as fh:
        fh.write(str(os.getpid()))

_ex("set confirm off")
_ex("set pagination off")
_ex("set height 0")
_start()
print("[rdbg] listening on %s" % SOCK)
