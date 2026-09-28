#!/usr/bin/env python3
"""The landing lease's client -- the `do` backend, and the node rules it shares.

    landing-lease.sh take    --as <agent> --repo <name>
    landing-lease.sh renew   --as <agent> --repo <name> --epoch <n>
    landing-lease.sh release --as <agent> --repo <name> --epoch <n>
    landing-lease.py doctor                 (one line for tools/appl-init.sh --check)
    landing-lease.py check-node <path> [--as-prefix NAME]
    landing-lease.py check-lease <name> <agent> <node or ''> [--as-prefix NAME]
    landing-lease.py check-endpoint <url> [--as-prefix NAME]

Stdlib only. Python 3.9+. landing-lease.sh execs this file: ONE process and ONE signed
HTTPS POST per verb (a take whose answer is lost is retried once, see lease_core.py). No
git, no operator_cli, no second program.

The lease used to be two Room messages -- /mem to read the holder, /remember to write
it -- run through 11-27 operator_cli starts and ~12-15 s of polling per landing, with no
compare-and-swap between them, so two machines could both read "free" and both win. It
is now one Durable Object per repository (../worker/) holding an epoch CAS; this file
signs the request and reads the answer. The generic half -- backend selection, the
transport, the answer-to-outcome mapping and the exit codes -- is lease_core.py; only the
Muretai-specific half lives here:

  node      <node> is the `node=<absolute path>` line in <dispatch dir>/node (written by
            `dispatch-init.sh --node`). A missing or untrusted line refuses with the
            dispatch-init.sh call; there is no fallback to ~/muretai-node, and the cwd never
            matters. --as must name a key the node holds (it refuses, it never mints).
  identity  the request is signed by the node's dedicated lease identity, the `lease=<name>`
            line beside node= (written by `dispatch-init.sh --lease`), from
            <node>/keys/<name>.key -- never the agent identity (whose key is never even
            opened) and never a binding token. A lease identity bound to a principal is
            refused before any request: the DO allowlists this key, so it must be one
            nothing else can drive.
  signing   shared/crypto.py, loaded from the NODE (the checkout that holds the key), else
            from this checkout -- the file has no import outside the standard library.
  endpoint  LANDING_LEASE_ENDPOINT, else `url` in the [lease] configuration
            (LANDING_LEASE_CONFIG, default <dispatch dir>/lease.toml), else the
            `endpoint=` line in <dispatch dir>/node (written by `dispatch-init.sh
            --lease-endpoint`). Never a constant in this repository.

dispatch-take.sh and dispatch-init.sh load this file for the node rules (`resolve_node`,
`check_node`, `require_identity`, `run_cli`); `check-node` is the shell-facing form.
`check-lease` and `check-endpoint` are what dispatch-init.sh runs before it writes a
lease= or endpoint= line: the checks a take applies (`check_lease`, and
lease_core.check_url -- the one url validator), so a line the init accepts is one the
take accepts. Every refusal here that names a dispatch-init.sh flag names one that
exists (tests/test_dispatch_init_lease.py holds the two to each other).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
CHECKOUT = HERE.parents[3]
sys.path.insert(0, str(HERE))
import lease_core  # noqa: E402  (this directory, not a package)

PROG = "landing-lease"
INIT_SH = "bash .cursor/skills/isolated-session/scripts/dispatch-init.sh"
INIT_HINT = ("%s --as <agent> --repo <name>=<path> --node <absolute path of this machine's node>"
             % INIT_SH)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
USAGE = ("usage: landing-lease.sh take|renew|release --as <agent> --repo <name> "
         "[--epoch <n>]   (--epoch is required for renew and release)")


class Refusal(Exception):
    """A refusal with its exit code. Raised by the node helpers so each caller
    prints it under its own name (landing-lease / dispatch-take / dispatch-init)."""

    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code = code
        self.msg = msg


# -- the node -----------------------------------------------------------------------

def dispatch_dir() -> Path:
    return Path(os.environ.get("DISPATCH_DIR")
                or (Path.home() / ".muretai" / "dispatch"))


def kv_file(path: Path, key: str) -> str:
    if not path.is_file() or path.is_symlink():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip()
    return ""


def _git_common_dir(p: Path) -> Optional[Path]:
    """The git common directory `p` belongs to, read from the files git keeps -- the
    `.git` directory, or a linked worktree's `.git` file and its `commondir` -- so that
    judging a node starts no git process (the lease is one process). None outside git."""
    for d in [p] + list(p.parents):
        g = d / ".git"
        try:
            if g.is_dir():
                return g.resolve()
            if not g.is_file():
                continue
            text = g.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not text.startswith("gitdir:"):
            return None
        gd = Path(text[len("gitdir:"):].strip())
        if not gd.is_absolute():
            gd = d / gd
        try:
            cd = gd / "commondir"
            if cd.is_file():
                c = Path(cd.read_text(encoding="utf-8").strip())
                return (c if c.is_absolute() else gd / c).resolve()
        except OSError:
            return None
        return gd.resolve()
    return None


def _this_repository() -> List[Path]:
    """This repository's checkouts to refuse as a node: the checkout holding this
    script, the primary it belongs to, and DISPATCH_SKILL_REPO when set."""
    roots = [CHECKOUT.resolve()]
    common = _git_common_dir(CHECKOUT)
    if common is not None:
        roots.append(common.parent)
    extra = os.environ.get("DISPATCH_SKILL_REPO") or ""
    if extra:
        roots.append(Path(extra).resolve())
    return roots


def check_node(value: str) -> Path:
    """The node directory `value` names, or Refusal(2). Trusted only if absolute,
    free of `..`, an existing directory (not a symlink) owned by this user,
    holding a regular operator_cli.py, and not this repository or one of its
    worktrees -- the repository copy is exactly what the M1 defect ran."""
    def refuse(why: str) -> None:
        raise Refusal(2, "the node %r %s. Point the node line at this machine's node: %s"
                      % (value, why, INIT_HINT))

    if not value:
        refuse("is empty")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        refuse("carries a control character")
    if not os.path.isabs(value):
        refuse("is not an absolute path")
    if ".." in Path(value).parts:
        refuse("contains '..'")
    p = Path(value)
    try:
        st = os.lstat(str(p))
    except FileNotFoundError:
        refuse("does not exist")
    except OSError as e:
        refuse("cannot be read (%s)" % e.strerror)
    if stat.S_ISLNK(st.st_mode):
        refuse("is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        refuse("is not a directory")
    if st.st_uid != os.getuid():
        refuse("is owned by uid %d, not this user" % st.st_uid)
    try:
        cst = os.lstat(str(p / "operator_cli.py"))
        cli_ok = stat.S_ISREG(cst.st_mode)
    except OSError:
        cli_ok = False
    if not cli_ok:
        refuse("holds no operator_cli.py (a regular file, not a symlink)")
    real = p.resolve()
    repo = _this_repository()
    if any(real == r or r in real.parents for r in repo):
        refuse("is this repository, not a node")
    common = _git_common_dir(real)
    if common is not None and common.parent in repo:
        refuse("is a worktree of this repository, not a node")
    return p


def resolve_node(ddir: Optional[Path] = None) -> Path:
    """The node named by <dispatch dir>/node, validated. No line is a refusal."""
    ddir = ddir if ddir is not None else dispatch_dir()
    node_file = ddir / "node"
    value = kv_file(node_file, "node")
    if not value:
        raise Refusal(2, "no node= line in %s: this machine has not said which node it "
                         "lands through. Configure it once: %s" % (node_file, INIT_HINT))
    return check_node(value)


def require_identity(node: Path, as_name: str) -> None:
    """--as must name a key the node holds. Refuses (never mints) otherwise."""
    if (not as_name or as_name in (".", "..") or "/" in as_name or "\\" in as_name
            or "\0" in as_name or as_name.startswith(".")):
        raise Refusal(2, "--as %r is not an agent name" % as_name)
    keys = node / "keys"
    if not (keys / (as_name + ".key")).exists() and not (keys / (as_name + ".signer.json")).exists():
        raise Refusal(2, "no identity %r in the node's keys/ (%s). --as on a missing key "
                         "refuses; create it on the node first." % (as_name, keys))


def cli_path(node: Path) -> Path:
    return Path(os.environ.get("DISPATCH_CLI") or (node / "operator_cli.py"))


def node_env(node: Path) -> dict:
    env = dict(os.environ)
    env["MURETAI_STATE_DIR"] = str(node)
    return env


def run_cli(node: Path, as_name: str, *args: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    """operator_cli --as <name> <args>, run as the node: its file (or DISPATCH_CLI),
    its state, its directory as the cwd. A timeout is a failed call, not a crash.
    (dispatch-take.sh's; the lease itself never starts operator_cli.)"""
    argv = [sys.executable, str(cli_path(node)), "--as", as_name, *args]
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              cwd=str(node), env=node_env(node))
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "timed out after %ss" % timeout)


# -- the lease identity --------------------------------------------------------------------

def _config_error(r: Refusal) -> lease_core.ConfigError:
    return lease_core.ConfigError(r.msg)


def load_crypto(node: Path):
    """shared/crypto.py from the node, else from this checkout, loaded by path."""
    for base in (node, CHECKOUT):
        f = base / "shared" / "crypto.py"
        if f.is_file() and not f.is_symlink():
            spec = importlib.util.spec_from_file_location("_landing_lease_crypto", str(f))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            return mod
    raise lease_core.ConfigError("no shared/crypto.py in the node %s or in this checkout" % node)


def load_lease_key(node: Path, name: str, crypto) -> tuple:
    """(seed, did) of <node>/keys/<name>.key. Only that one file is opened."""
    keys = node / "keys"
    path = keys / (name + ".key")
    if not path.is_file() or path.is_symlink():
        if (keys / (name + ".signer.json")).exists():
            raise lease_core.ConfigError(
                "the lease identity %r is held by a remote signer; the lease signs with a "
                "plain key file, %s" % (name, path))
        raise lease_core.ConfigError("no lease identity %r in the node's keys/ (%s): create "
                                     "it on the node, unbound, first" % (name, keys))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        seed = bytes.fromhex(data["seed"])
        if len(seed) != 32:
            raise ValueError("seed length")
        did = crypto.did_from_public(crypto.ed25519_public_from_seed(seed))
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise lease_core.ConfigError("the lease identity %r (%s) cannot be read: %s"
                                     % (name, path, type(e).__name__))
    if data.get("did") and data["did"] != did:
        raise lease_core.ConfigError("the lease identity %r does not match the DID it records" % name)
    return seed, did


def check_lease(node: Path, name: str, as_name: str) -> tuple:
    """(crypto, seed, did) of the lease identity `name`, or ConfigError: an identity
    name, not the agent itself, a plain key the node holds, bound to no principal. The
    one rule shared by a take and by `dispatch-init.sh --lease`, so the init never
    writes a line the take would refuse."""
    if not NAME_RE.fullmatch(name):
        raise lease_core.ConfigError("lease=%r is not an identity name" % name)
    if name == as_name:
        raise lease_core.ConfigError(
            "lease=%s names the agent itself; the lease signs with a dedicated, unbound "
            "identity, never the agent's" % name)
    crypto = load_crypto(node)
    seed, did = load_lease_key(node, name, crypto)
    refuse_if_bound(did, name)
    return crypto, seed, did


def refuse_if_bound(did: str, name: str) -> None:
    """A binding record naming a principal (agent/binding.py's layout) is a refusal:
    the lease identity must be one no principal can drive. Unreadable fails closed.

    The directory is listed first. os.path.lexists of the record returns false when
    the directory itself cannot be traversed (mode 000), and that used to look like
    "no binding" and let the take succeed."""
    d = Path(os.environ.get("MURETAI_BINDING_DIR") or (Path.home() / ".muretai" / "bindings"))
    try:
        names = os.listdir(str(d))
    except FileNotFoundError:
        return
    except OSError:
        raise lease_core.ConfigError(
            "the bindings directory cannot be read, so the lease identity %r cannot be "
            "shown to be unbound; refusing" % (name,))
    rec_name = did.replace(":", "_").replace("/", "_") + ".json"
    if rec_name not in names:
        return
    rec = d / rec_name
    principal = "unreadable"
    try:
        if rec.is_file() and not rec.is_symlink():
            principal = json.loads(rec.read_text(encoding="utf-8")).get("principal")
    except (OSError, ValueError, AttributeError):
        principal = "unreadable"
    if principal is not None:
        raise lease_core.ConfigError(
            "the lease identity %r (%s) is bound to a principal (%s); the lease signs only "
            "with an unbound identity -- unbind it, or name a dedicated unbound key on the "
            "lease= line" % (name, did, rec))


class DoBackend(lease_core.Backend):
    """One signed POST to <url>/lease/<repo> per verb."""

    def __init__(self, url: str, repo: str, did: str, seed: bytes, crypto, epoch: Optional[int]):
        self.url, self.repo, self.me = url, repo, did
        self._seed, self._crypto, self._epoch = seed, crypto, epoch

    def send(self, verb: str):
        payload = {"verb": verb, "repo": self.repo, "did": self.me,
                   "ts": int(time.time()), "nonce": secrets.token_hex(16)}
        if verb != "take":
            payload["epoch"] = self._epoch
        msg = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
        sig = base64.b64encode(self._crypto.ed25519_sign(self._seed, msg)).decode("ascii")
        return lease_core.post_json(self.url, "/lease/" + urllib.parse.quote(self.repo, safe=""),
                                    {"payload": payload, "sig": sig})


def lease_url(cfg: Dict[str, str], ddir: Path) -> str:
    return (lease_core.env_first("LANDING_LEASE_ENDPOINT") or (cfg.get("url") or "").strip()
            or kv_file(ddir / "node", "endpoint"))


def config_file(ddir: Path) -> Path:
    return lease_core.config_path(os.environ.get("LANDING_LEASE_CONFIG"), ddir / "lease.toml")


# -- the verbs ------------------------------------------------------------------------------

def parse_args(argv: List[str]) -> tuple:
    if not argv or argv[0] not in ("take", "renew", "release"):
        raise lease_core.ConfigError(USAGE)
    verb, as_name, repo, epoch = argv[0], "", "", None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--ttl-s":
            raise lease_core.ConfigError("--ttl-s is not accepted: the lease length is the "
                                         "lease service's own setting, not the client's")
        if a in ("--as", "--repo", "--epoch") and i + 1 < len(argv):
            v = argv[i + 1]
            if a == "--as":
                as_name = v
            elif a == "--repo":
                repo = v
            else:
                if not re.fullmatch(r"[0-9]{1,15}", v):
                    raise lease_core.ConfigError("--epoch must be a whole number, got %r" % v)
                epoch = int(v)
            i += 2
            continue
        raise lease_core.ConfigError("unknown argument %r. %s" % (a, USAGE))
    if not as_name or not repo:
        raise lease_core.ConfigError(USAGE)
    if not REPO_RE.match(repo):
        raise lease_core.ConfigError("--repo %r is not a repository name" % repo)
    if verb != "take" and epoch is None:
        raise lease_core.ConfigError("%s needs --epoch <n>, the epoch the take was granted" % verb)
    return verb, as_name, repo, epoch


def lease_main(argv: List[str]) -> int:
    try:
        verb, as_name, repo, epoch = parse_args(argv)
        ddir = dispatch_dir()
        cfg = lease_core.read_config(config_file(ddir))
    except lease_core.ConfigError as e:
        return lease_core.emit(PROG, lease_core.Outcome("config", reason=str(e)))

    def build_do(cfg: Dict[str, str]) -> lease_core.Backend:
        try:
            node = resolve_node(ddir)
            require_identity(node, as_name)
        except Refusal as r:
            raise _config_error(r)
        name = kv_file(ddir / "node", "lease")
        if not name:
            raise lease_core.ConfigError(
                "no lease= line in %s: name this machine's dedicated, unbound lease identity "
                "(a key in the node's keys/): %s --as %s --repo %s=<path> --lease <identity name>"
                % (ddir / "node", INIT_SH, as_name, repo))
        crypto, seed, did = check_lease(node, name, as_name)
        url = lease_url(cfg, ddir)
        if not url:
            raise lease_core.ConfigError(
                "no lease endpoint configured: %s --as %s --repo %s=<path> --lease-endpoint "
                "<https url> (or url in the [lease] section of %s, or LANDING_LEASE_ENDPOINT)"
                % (INIT_SH, as_name, repo, config_file(ddir)))
        lease_core.check_url(url)
        return DoBackend(url, repo, did, seed, crypto, epoch)

    return lease_core.dispatch(PROG, verb, cfg, {"do": build_do})


def doctor_main() -> int:
    """One line for tools/appl-init.sh --check: `OK lease: ...` / `MISSING lease: ...`.
    Names the backend and whether it answers. A GET, never a POST: it takes nothing.
    It prints no path: the doctor's lines are shown to people on other machines."""
    ddir = dispatch_dir()
    try:
        cfg = lease_core.read_config(config_file(ddir))
        name = lease_core.select_backend(cfg)
    except lease_core.ConfigError as e:
        print("MISSING lease: %s -- fix the [lease] configuration (LANDING_LEASE_CONFIG, "
              "default lease.toml in the dispatch directory)" % " ".join(str(e).split()))
        return 1
    if name not in lease_core.BUILT:
        print("MISSING lease: backend %s is not implemented in this build -- set "
              "backend = \"do\" in the [lease] configuration" % name)
        return 1
    url = lease_url(cfg, ddir)
    if not url:
        print("MISSING lease: backend %s has no url -- add endpoint=<https url of your lease "
              "Worker> to the node file in the dispatch directory" % name)
        return 1
    why = lease_core.probe(url)
    if why:
        print("MISSING lease: backend %s -- %s; check endpoint= in the dispatch node file"
              % (name, " ".join(why.split())))
        return 1
    print("OK lease: backend %s at %s answers" % (name, url))
    return 0


def check_node_main(argv: List[str]) -> int:
    """`landing-lease.py check-node <path> [--as-prefix NAME]`: print the node path
    and exit 0, or print the refusal and exit 2."""
    prefix = PROG
    if len(argv) >= 3 and argv[1] == "--as-prefix":
        prefix = argv[2]
    try:
        node = check_node(argv[0] if argv else "")
    except Refusal as r:
        sys.stderr.write("%s: %s\n" % (prefix, r.msg))
        return r.code
    sys.stdout.write("%s\n" % node)
    return 0


def _prefix(argv: List[str], at: int) -> str:
    if len(argv) >= at + 2 and argv[at] == "--as-prefix":
        return argv[at + 1]
    return PROG


def _config_refusal(prefix: str, e: lease_core.ConfigError) -> int:
    sys.stderr.write("%s: %s\n" % (prefix, lease_core.printable(" ".join(str(e).split()), 600)))
    return lease_core.EXIT_CONFIG


def check_lease_main(argv: List[str]) -> int:
    """`landing-lease.py check-lease <name> <agent> <node or ''> [--as-prefix NAME]`:
    print the lease identity's DID and exit 0, or print the refusal and exit 2. An empty
    node means the node= line in <dispatch dir>/node, resolved as a take resolves it."""
    if len(argv) < 3:
        sys.stderr.write("usage: landing-lease.py check-lease <name> <agent> <node or ''> "
                         "[--as-prefix NAME]\n")
        return 2
    prefix = _prefix(argv, 3)
    name, as_name, node_arg = argv[0], argv[1], argv[2]
    try:
        node = check_node(node_arg) if node_arg else resolve_node()
        _crypto, _seed, did = check_lease(node, name, as_name)
    except Refusal as r:
        sys.stderr.write("%s: %s\n" % (prefix, r.msg))
        return r.code
    except lease_core.ConfigError as e:
        return _config_refusal(prefix, e)
    sys.stdout.write("%s\n" % did)
    return 0


def check_endpoint_main(argv: List[str]) -> int:
    """`landing-lease.py check-endpoint <url> [--as-prefix NAME]`: exit 0 when a take
    would use the url (lease_core.check_url, the one validator -- no second policy), else
    print why and exit 2. A control character is refused first: urlsplit drops some of
    them silently, and one written into the node file would be a second line."""
    prefix = _prefix(argv, 1)
    url = argv[0] if argv else ""
    try:
        if any(ord(c) < 32 or ord(c) == 127 for c in url):
            raise lease_core.ConfigError("the lease url %r carries a control character" % url)
        lease_core.check_url(url)
    except lease_core.ConfigError as e:
        return _config_refusal(prefix, e)
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["check-node"]:
        sys.exit(check_node_main(sys.argv[2:]))
    if sys.argv[1:2] == ["check-lease"]:
        sys.exit(check_lease_main(sys.argv[2:]))
    if sys.argv[1:2] == ["check-endpoint"]:
        sys.exit(check_endpoint_main(sys.argv[2:]))
    if sys.argv[1:2] == ["doctor"]:
        sys.exit(doctor_main())
    sys.exit(lease_main(sys.argv[1:]))
