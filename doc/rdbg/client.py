"""Python client for an rdbg session. Stateless calls over a live session."""
import json, os, socket, struct

class Rdbg:
    def __init__(self, name, run_dir=None):
        run_dir = run_dir or os.environ.get("RDBG_DIR") or os.path.expanduser("~/.rdbg")
        self.path = os.path.join(run_dir, "%s.sock" % name)
        self.name = name
        self._s = None

    def _conn(self):
        if self._s is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.path)
            self._s = (s, s.makefile("rwb"))
        return self._s

    def req(self, op, **kw):
        _s, f = self._conn()
        kw["op"] = op
        f.write((json.dumps(kw) + "\n").encode()); f.flush()
        line = f.readline()
        if not line:
            raise RuntimeError("session %s closed" % self.name)
        r = json.loads(line)
        if not r.get("ok"):
            raise RuntimeError("rdbg %s: %s" % (op, r.get("error")))
        return r["result"]

    # --- conveniences -----------------------------------------------------
    def note(self, name):
        return int(self.req("note.list")["notes"][name]["value"])

    def notes(self):
        return self.req("note.list")["notes"]

    def read(self, addr, n):
        return bytes.fromhex(self.req("mem.read", loc=hex(addr) if isinstance(addr, int) else addr, len=n)["hex"])

    def write(self, addr, data):
        return self.req("mem.write", loc=hex(addr) if isinstance(addr, int) else addr, hex=data.hex())

    def u64(self, addr):
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def i32(self, addr):
        return struct.unpack("<i", self.read(addr, 4))[0]

    def call(self, fn, *args, ret_type="long"):
        return self.req("call", fn=fn, args=list(args), ret_type=ret_type)["int"]

    def snapshot(self, **kw):
        return self.req("snapshot", **kw)
