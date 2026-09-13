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
}
LOCK = threading.Lock()

# The inferior resumes asynchronously: gdb.execute("continue") returns before
# the target stops, so there is no frame to inspect in the same callback.
# Resume commands therefore issue the command, then wait for a stop event.
STOP_EV = threading.Event()
LAST_STOP = {}


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

def _match_module(token):
    """Resolve a module token (basename or substring) to its load base."""
    bases = _module_bases()
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
    """Breakpoint that can require its *caller* to live in a given module.

    This is what makes `break mprotect` usable: the dynamic loader calls
    mprotect during startup, and an unscoped breakpoint stops there first.
    """
    def __init__(self, spec, caller_module=None, bid=None, **kw):
        self.caller_module = caller_module
        self.bid = bid
        self.skipped = 0
        super().__init__(spec, **kw)

    def stop(self):
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
    snap = {"revision": rev, "running": True, "pc": describe_addr(pc),
            "regs": _regs()}
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
    buf = bytes(gdb.selected_inferior().read_memory(addr, n))
    out = {"addr": "%#x" % addr, "len": n, "hex": buf.hex()}
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
    return {"addr": "%#x" % addr, "wrote": len(data)}

def h_mem_export(req):
    """Dump a region AND record its base, so a disassembler can load it right."""
    addr, _ = resolve_loc(req["loc"])
    n = int(req["len"])
    path = req["path"]
    buf = bytes(gdb.selected_inferior().read_memory(addr, n))
    with open(path, "wb") as fh:
        fh.write(buf)
    meta = {"base": "%#x" % addr, "len": n, "file": path,
            "source": describe_addr(addr),
            "r2": "r2 -a x86 -b 64 -m %#x %s" % (addr, path)}
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
    bp = ScopedBP(spec, caller_module=caller, bid=bid)
    rec = {"id": bid, "loc": loc, "spec": spec, "desc": desc,
           "caller_module": caller, "gdb_num": bp.number,
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
                          "hits": getattr(o, "hit_count", None),
                          "skipped": getattr(o, "skipped", 0),
                          "enabled": getattr(o, "enabled", None)})
    return {"breakpoints": items}

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
        args = req.get("args")
        if args:
            _ex("set args " + " ".join(args))
        stdin_data = req.get("stdin")
        cmd = "run"
        if stdin_data is not None:
            p = os.path.join(os.path.dirname(SOCK), "stdin-%d" % os.getpid())
            with open(p, "w") as fh:
                fh.write(stdin_data)
            cmd = "run < " + p
        with LOCK:
            STATE["launch"] = {"args": args, "stdin": stdin_data, "cmd": cmd}
        STOP_EV.clear()
        _ex(cmd)
        return {"resumed": True}
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
    "restore": h_restore,
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
    if not STOP_EV.wait(timeout=wait_s):
        return {"ok": True, "result": dict(
            issued, stopped=False,
            note="target still running after %gs; use op=interrupt" % wait_s)}
    snap = _on_main({"op": "snapshot", "disasm": req.get("disasm", 4),
                     "depth": req.get("depth", 8)}, timeout)
    out = dict(issued)
    out["stopped"] = True
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
