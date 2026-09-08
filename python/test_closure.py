#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""python/test_closure.py — the slice imports nothing outside itself.

Two legs, because each catches what the other cannot:
  static   every `from shared import X` / `import shared.X` anywhere in a slice module (lazy
           imports inside functions included) names a module of the slice, and no module
           imports `agent`, `relay`, `relay_proxy`, `tools` or `examples` at all;
  dynamic  each module is imported in a fresh interpreter whose sys.path holds ONLY this
           directory (plus the stdlib), from an unrelated cwd, and every `shared.*` module that
           ends up loaded is one of ours, from our directory. That is the "no core present"
           test core's own contract suite runs on its single-file reference (part13).
Before either: tools/manifest.json accounts for exactly what is on disk, because every consumer's
vendor script cuts by that file.
`cryptobox` needs the optional `cryptography` package; without it the dynamic leg SKIPS that
one module and says so — a missing optional dependency is not a closure failure.

Run:  python3 python/test_closure.py
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
M = json.loads((ROOT / "tools" / "manifest.json").read_text("utf-8"))
SLICE = set(M["python"]["modules"])
FORBIDDEN = set(M["python"]["forbiddenImports"])

passed = 0
failures: list[str] = []


def ok(cond: bool, label: str) -> None:
    global passed
    if cond:
        passed += 1
    else:
        failures.append(label)
        print(f"  FAIL {label}")


# ---- the manifest accounts for disk (a consumer cuts by this file; a module or vector it does not
# name would travel nowhere, and one it names that is not here would fail every vendor script)
on_disk = sorted(p.stem for p in (HERE / "shared").glob("*.py"))
nested = sorted(str(p.relative_to(HERE)) for p in (HERE / "shared").rglob("*.py") if p.parent != HERE / "shared" and "__pycache__" not in p.parts)
ok(not nested, f"python/shared/ has no .py below its top level (a consumer copies by name, never a tree): {nested}")
ok(on_disk == sorted(SLICE), f"python/shared/ holds exactly the manifest's modules: disk {on_disk} vs manifest {sorted(SLICE)}")
for t in M["python"]["verbatimTests"] + M["python"]["homeTests"]:
    ok((HERE / t).exists(), f"python/{t} is named by the manifest but is not here")
vec = sorted(p.name for p in (ROOT / "vectors").glob("*.json"))
ok(vec == sorted(M["vectors"]), f"vectors/ holds exactly the manifest's files: {vec}")
print(f"manifest: {len(SLICE)} modules, {len(M['vectors'])} vector files, accounted for on disk")

# ---- static leg
for m in sorted(SLICE):
    src = (HERE / "shared" / f"{m}.py").read_text("utf-8")
    tree = ast.parse(src, filename=f"shared/{m}.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level:
                ok(False, f"{m}: relative import `{'.' * node.level}{mod}` (the slice uses absolute `shared` imports)")
            elif mod == "shared":
                for a in node.names:
                    ok(a.name in SLICE, f"{m}: `from shared import {a.name}` — {a.name} is not in the slice")
            elif mod.startswith("shared."):
                sub = mod.split(".", 2)[1]
                ok(sub in SLICE, f"{m}: `from {mod} import …` — {sub} is not in the slice")
            else:
                ok(mod.split(".")[0] not in FORBIDDEN, f"{m}: `from {mod} import …` reaches outside the slice")
        elif isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
                or (isinstance(node.func, ast.Name) and node.func.id == "__import__")):
            ok(False, f"{m}: a dynamic import (`importlib.import_module` / `__import__`) — the closure cannot be read, so it is refused")
        elif isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if a.name.startswith("shared."):
                    ok(a.name.split(".")[1] in SLICE, f"{m}: `import {a.name}` — not in the slice")
                else:
                    ok(top not in FORBIDDEN, f"{m}: `import {a.name}` reaches outside the slice")
print(f"static: {len(SLICE)} modules walked, every shared import stays inside the slice")

# ---- dynamic leg
PROBE = """
import json, sys
import shared.{m}
loaded = sorted(k for k in sys.modules if k == 'shared' or k.startswith('shared.'))
foreign = sorted(k for k in sys.modules if k.split('.')[0] in {forbidden!r})
print(json.dumps({{'loaded': loaded, 'foreign': foreign, 'file': sys.modules['shared.{m}'].__file__}}))
"""
with tempfile.TemporaryDirectory() as tmp:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(HERE), "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1"}
    for m in sorted(SLICE):
        r = subprocess.run([sys.executable, "-c", PROBE.format(m=m, forbidden=sorted(FORBIDDEN))],
                           cwd=tmp, env=env, capture_output=True, text=True)
        if r.returncode != 0 and m == "cryptobox" and "cryptography" in r.stderr:
            print(f"  skip shared.cryptobox: optional dependency `cryptography` is not installed")
            continue
        ok(r.returncode == 0, f"import shared.{m} with only this directory on sys.path: {r.stderr.strip().splitlines()[-1:] if r.stderr else 'exit ' + str(r.returncode)}")
        if r.returncode != 0:
            continue
        out = json.loads(r.stdout.strip().splitlines()[-1])
        strays = [k for k in out["loaded"] if k != "shared" and k.split(".", 1)[1] not in SLICE]
        ok(not strays, f"shared.{m}: loaded modules outside the slice: {strays}")
        ok(not out["foreign"], f"shared.{m}: loaded forbidden modules: {out['foreign']}")
        ok(Path(out["file"]).resolve().parent == (HERE / "shared").resolve(), f"shared.{m}: imported from {out['file']}, not from this directory")
print(f"dynamic: {len(SLICE)} modules imported in isolation")

if failures:
    print(f"\nFAILED — {len(failures)} of {passed + len(failures)} checks")
    sys.exit(1)
print(f"\nOK — {passed} checks: the slice is closed (nothing from core is needed or reachable).")
