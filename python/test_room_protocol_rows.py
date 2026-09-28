#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""python/test_room_protocol_rows.py — the Room API protocol rows, held in step across languages.

Seam 0.3.6 adds two JSON-RPC error codes and three METHOD_CLASSES rows to
python/shared/protocol.py and mirrors them into js/, go/ and php/:

  ROOM_MEMBER_REQUIRED = {"code": -32048, "message": "Room member required"}
  ROOM_MEM_REFUSED     = {"code": -32049, "message": "Room memory refused"}
  room.mem/read, room.mem/append, room.kv/cas -> the class of a member-only synchronous
                                                 method (as trust/status: DEGRADE_LOSSY, "B")

The pins, each a numbered block below:
  (a) both codes exist in Python with exactly those numbers and messages, beside
      REMOTE_OPS_VERB_DENIED (-32047), and no other error constant reuses either number;
  (b) the three methods classify as member-only (B), never DEGRADE_UNKNOWN (D) and never the
      consent-weakening class C;
  (c) every language mirror carries the same numbers, names and classes as Python, and no
      mirror row disagrees with Python for any name it carries; tools/check-manifest.mjs and
      js/conformance/run.mjs stay green;
  (d) the package version reads 0.3.6;
  (e) nothing else in python/shared/protocol.py changed: against the 0.3.5 file, the diff is
      insertions only, in the two places named above;
  refusals: a method this protocol never defined — including near misses of the new names and
      the names a JavaScript object inherits — still classifies D in every language.

The mirror surface each language must expose (read by the probes below):
  js/seam.mjs    export ERRORS (name -> {code, message}), export METHOD_CLASSES (method -> class),
                 export function degradationClass(method)
  go/seam.go     var Errors map[string]RPCError (fields Code int, Message string),
                 var MethodClasses map[string]string, func DegradationClass(string) string
  php/seam.php   Wire::ERRORS (name => ['code' => int, 'message' => string]),
                 Wire::METHOD_CLASSES (method => class), Wire::degradationClass(string): string

Needs node, go and php on PATH, like `npm test`, `go run ./conformance` and `npm run test:php`.

Run:  python3 python/test_room_protocol_rows.py
"""
from __future__ import annotations

import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from shared import protocol  # noqa: E402

NEW_ERRORS = {
    "ROOM_MEMBER_REQUIRED": {"code": -32048, "message": "Room member required"},
    "ROOM_MEM_REFUSED": {"code": -32049, "message": "Room memory refused"},
}
NEW_METHODS = ("room.mem/read", "room.mem/append", "room.kv/cas")
MEMBER_ONLY = "B"          # DEGRADE_LOSSY, the class trust/status carries (no room/charter row)
UNKNOWN = "D"
# The commit the 0.3.6 change is made on top of: python/shared/protocol.py as 0.3.5 left it.
BASE = "4d3a6ed"

# Names no version of this protocol defines. The first is plainly made up; the rest are near
# misses of the new rows (case, whitespace, prefix, suffix, separator, NUL) — a lookup that
# normalises, prefix-matches or splits would classify one of them — and the names every
# JavaScript object inherits, which a bare `METHOD_CLASSES[m] ?? 'D'` answers with a function.
UNKNOWN_METHODS = [
    "zz.seamtest/never-defined",
    "room.mem/Read",
    "ROOM.MEM/READ",
    "room.mem/read ",
    " room.mem/read",
    "room.mem",
    "room.mem/",
    "room.mem/read/extra",
    "room.mem/readx",
    "room.mem.read",
    "room.kv/cas\u0000",
    "room.kv/",
    "room.kv/CAS",
    "room/mem/read",
    "",
    "__proto__",
    "constructor",
    "toString",
    "hasOwnProperty",
    "valueOf",
]

passed = 0
failures: list[str] = []


def ok(cond: bool, label: str) -> None:
    global passed
    if cond:
        passed += 1
    else:
        failures.append(label)
        print(f"  FAIL {label}")


def py_errors() -> dict[str, dict]:
    """Every module-level error object in protocol.py: name -> {code, message}."""
    return {k: v for k, v in vars(protocol).items()
            if k.isupper() and isinstance(v, dict) and set(v) == {"code", "message"}
            and isinstance(v["code"], int)}


# ------------------------------------------------------------------ (a) the two codes, Python
errs = py_errors()
for name, want in NEW_ERRORS.items():
    ok(getattr(protocol, name, None) == want, f"(a) protocol.{name} == {want} (found {getattr(protocol, name, None)!r})")
for name, want in NEW_ERRORS.items():
    holders = sorted(k for k, v in errs.items() if v["code"] == want["code"])
    ok(holders == [name], f"(a) code {want['code']} is carried by {name} alone (found {holders})")
ok(getattr(protocol, "REMOTE_OPS_VERB_DENIED", None) == {"code": -32047, "message": "Remote ops verb denied"},
   "(a) REMOTE_OPS_VERB_DENIED is untouched at -32047")
for reserved in (-32050, -32051):
    holders = sorted(k for k, v in errs.items() if v["code"] == reserved)
    ok(holders == [], f"(a) the double-reserved {reserved} stays unused (found {holders})")

src = (HERE / "shared" / "protocol.py").read_text("utf-8")
order = [m.group(1) for m in re.finditer(r"^([A-Z_]+) = \{\"code\": (-?\d+)", src, re.M)]
if all(n in order for n in ("REMOTE_OPS_VERB_DENIED", *NEW_ERRORS)):
    i = order.index("REMOTE_OPS_VERB_DENIED")
    ok(order[i + 1:i + 3] == list(NEW_ERRORS),
       f"(a) the two codes are defined right after REMOTE_OPS_VERB_DENIED, in number order (found {order[i + 1:i + 3]})")
else:
    ok(False, "(a) ROOM_MEMBER_REQUIRED and ROOM_MEM_REFUSED are defined as `NAME = {\"code\": …` lines in protocol.py")

# ------------------------------------------------------------------ (b) the three rows, Python
ok(protocol.DEGRADE_LOSSY == MEMBER_ONLY and protocol.DEGRADE_UNKNOWN == UNKNOWN,
   "(b) the class letters did not move (B lossy, D unknown)")
ok(protocol.METHOD_CLASSES.get("trust/status") == MEMBER_ONLY, "(b) trust/status is still class B")
for m in NEW_METHODS:
    got = protocol.METHOD_CLASSES.get(m)
    ok(got == MEMBER_ONLY, f"(b) METHOD_CLASSES[{m!r}] is B, as trust/status (found {got!r})")
    ok(protocol.degradation_class(m) == MEMBER_ONLY, f"(b) degradation_class({m!r}) is B, never D (found {protocol.degradation_class(m)!r})")
ok([k for k, v in protocol.METHOD_CLASSES.items() if v == protocol.DEGRADE_CONSENT] == ["introduce/propose"],
   "(b) introduce/propose is still the only class-C method")
# refusal: additive only — a method nobody defined is still D
for m in UNKNOWN_METHODS:
    ok(protocol.degradation_class(m) == UNKNOWN, f"(refusal) python degradation_class({m!r}) is D (found {protocol.degradation_class(m)!r})")
    ok(m not in protocol.METHOD_CLASSES, f"(refusal) python METHOD_CLASSES has no row {m!r}")

# ------------------------------------------------------------------ (c) the mirrors
JS_PROBE = r"""
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const mod = await import(pathToFileURL(process.argv[1]).href);
const names = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const errors = {};
for (const [k, v] of Object.entries(mod.ERRORS)) errors[k] = { code: v.code, message: v.message };
const classes = {};
for (const [k, v] of Object.entries(mod.METHOD_CLASSES)) classes[k] = v;
const probe = names.map((m) => { const c = mod.degradationClass(m); return [m, typeof c === 'string' ? c : `<${typeof c}>`]; });
process.stdout.write(JSON.stringify({ errors, classes, probe }) + '\n');
"""

GO_PROBE = r"""package main

import (
	"encoding/json"
	"fmt"
	"os"

	seam "github.com/muretai/agent-seam/go"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		panic(err)
	}
	errs := map[string]map[string]interface{}{}
	for k, v := range seam.Errors {
		errs[k] = map[string]interface{}{"code": v.Code, "message": v.Message}
	}
	classes := map[string]string{}
	for k, v := range seam.MethodClasses {
		classes[k] = v
	}
	probe := [][]string{}
	for _, m := range names {
		probe = append(probe, []string{m, seam.DegradationClass(m)})
	}
	out, err := json.Marshal(map[string]interface{}{"errors": errs, "classes": classes, "probe": probe})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
"""

PHP_PROBE = r"""<?php
use Muretai\AgentEntry\Wire;
require $argv[1];
$names = json_decode(file_get_contents($argv[2]), true);
$errors = new stdClass();
foreach (Wire::ERRORS as $k => $v) { $errors->{$k} = ['code' => $v['code'], 'message' => $v['message']]; }
$classes = new stdClass();
foreach (Wire::METHOD_CLASSES as $k => $v) { $classes->{$k} = $v; }
$probe = [];
foreach ($names as $m) { $c = Wire::degradationClass($m); $probe[] = [$m, is_string($c) ? $c : '<' . gettype($c) . '>']; }
echo json_encode(['errors' => $errors, 'classes' => $classes, 'probe' => $probe],
                 JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), "\n";
"""


def run_probe(lang: str, tmp: Path, names_file: Path):
    """(argv, cwd, env) for the language's probe, or None when the runtime is absent."""
    env = dict(os.environ)
    if lang == "js":
        if not shutil.which("node"):
            return None
        return ["node", "--input-type=module", "-e", JS_PROBE, "--", str(ROOT / "js" / "seam.mjs"), str(names_file)], tmp, env
    if lang == "go":
        if not shutil.which("go"):
            return None
        d = tmp / "goprobe"
        d.mkdir()
        (d / "go.mod").write_text("module seamprobe\n\ngo 1.21\n\n"
                                  "require github.com/muretai/agent-seam/go v0.0.0\n\n"
                                  f"replace github.com/muretai/agent-seam/go => {ROOT / 'go'}\n", "utf-8")
        (d / "main.go").write_text(GO_PROBE, "utf-8")
        env.update({"GOWORK": "off", "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"})
        return ["go", "run", ".", str(names_file)], d, env
    if lang == "php":
        if not shutil.which("php"):
            return None
        p = tmp / "probe.php"
        p.write_text(PHP_PROBE, "utf-8")
        return ["php", str(p), str(ROOT / "php" / "seam.php"), str(names_file)], tmp, env
    raise ValueError(lang)


probe_names = list(NEW_METHODS) + UNKNOWN_METHODS
mirrors: dict[str, dict] = {"python": {
    "errors": errs,
    "classes": dict(protocol.METHOD_CLASSES),
    "probe": [[m, protocol.degradation_class(m)] for m in probe_names],
}}
with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    names_file = tmp / "names.json"
    names_file.write_text(json.dumps(probe_names), "utf-8")
    for lang in ("js", "go", "php"):
        spec = run_probe(lang, tmp, names_file)
        if spec is None:
            ok(False, f"(c) {lang}: its runtime is not on PATH, so its mirror cannot be checked (a skip here would be a silent pass)")
            continue
        argv, cwd, env = spec
        r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
        tail = (r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-3:]
        ok(r.returncode == 0, f"(c) {lang}: the probe reads ERRORS, METHOD_CLASSES and the degradation-class function: {tail}")
        if r.returncode != 0:
            continue
        mirrors[lang] = json.loads(r.stdout.strip().splitlines()[-1])

for lang, got in mirrors.items():
    if lang == "python":
        continue
    # the two codes, same name, number and message as Python
    for name, want in NEW_ERRORS.items():
        ok(got["errors"].get(name) == want, f"(c) {lang}: ERRORS.{name} == {want} (found {got['errors'].get(name)!r})")
        holders = sorted(k for k, v in got["errors"].items() if v.get("code") == want["code"])
        ok(holders == [name], f"(c) {lang}: code {want['code']} is carried by {name} alone (found {holders})")
    # no row a mirror carries disagrees with Python
    drift = sorted(k for k, v in got["errors"].items() if errs.get(k) != v)
    ok(drift == [], f"(c) {lang}: every ERRORS entry equals Python's same-named constant (differing or unknown: {drift})")
    codes = [v.get("code") for v in got["errors"].values()]
    ok(len(codes) == len(set(codes)), f"(c) {lang}: no two ERRORS entries share a code")
    # the three rows, same class as Python
    for m in NEW_METHODS:
        ok(got["classes"].get(m) == MEMBER_ONLY, f"(c) {lang}: METHOD_CLASSES[{m!r}] is B (found {got['classes'].get(m)!r})")
    cdrift = sorted(k for k, v in got["classes"].items() if protocol.METHOD_CLASSES.get(k) != v)
    ok(cdrift == [], f"(c) {lang}: every METHOD_CLASSES row equals Python's (differing or unknown: {cdrift})")
    # the function, not only the table, answers identically — new rows and refusals alike
    py_probe = mirrors["python"]["probe"]
    for (m, want), pair in zip(py_probe, got["probe"]):
        ok(pair == [m, want], f"(c/refusal) {lang}: degradationClass({m!r}) == {want!r} as in Python (found {pair[1] if pair[0] == m else pair!r})")
    ok(len(got["probe"]) == len(py_probe), f"(c) {lang}: the probe answered every name ({len(got['probe'])} of {len(py_probe)})")

# ------------------------------------------------------------------ (c) the JS checks stay green
for argv in (["node", "tools/check-manifest.mjs"], ["node", "js/conformance/run.mjs"]):
    if not shutil.which("node"):
        ok(False, f"(c) `{' '.join(argv)}` needs node on PATH")
        continue
    r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=300)
    tail = ((r.stdout + r.stderr).strip().splitlines() or [f"exit {r.returncode}"])[-3:]
    ok(r.returncode == 0, f"(c) `{' '.join(argv)}` stays green: {tail}")

# ------------------------------------------------------------------ (d) the version
pkg = json.loads((ROOT / "package.json").read_text("utf-8"))
ok(pkg.get("version") == "0.3.6", f"(d) package.json version is 0.3.6 (found {pkg.get('version')!r})")

# ------------------------------------------------------------------ (e) nothing else in protocol.py moved
# A pin for THIS release: when protocol.py next changes on purpose, move BASE to that release's parent.
r = subprocess.run(["git", "show", f"{BASE}:python/shared/protocol.py"], cwd=ROOT, capture_output=True, text=True)
ok(r.returncode == 0, f"(e) git can read protocol.py at {BASE}: {r.stderr.strip()[:120]}")
if r.returncode == 0:
    old = r.stdout.splitlines()
    new = src.splitlines()
    ops = difflib.SequenceMatcher(a=old, b=new, autojunk=False).get_opcodes()
    changed = [(tag, i1, i2) for tag, i1, i2, _, _ in ops if tag in ("replace", "delete")]
    ok(changed == [], f"(e) no 0.3.5 line of protocol.py was changed or removed (at old lines {[i1 + 1 for _, i1, _ in changed]})")
    try:
        errs_at = old.index('REMOTE_OPS_VERB_DENIED = {"code": -32047, "message": "Remote ops verb denied"}')
        errs_end = next(i for i in range(errs_at, len(old)) if old[i].startswith("# ---- DID-gated artifacts"))
        cls_at = old.index("METHOD_CLASSES: dict[str, str] = {")
        cls_end = next(i for i in range(cls_at, len(old)) if old[i] == "}")
    except (ValueError, StopIteration):
        ok(False, "(e) the 0.3.5 anchors (REMOTE_OPS_VERB_DENIED, DID-gated banner, METHOD_CLASSES) are found")
    else:
        code_in_errs: list[str] = []
        rows_in_cls: list[str] = []
        for tag, i1, _, j1, j2 in ops:
            if tag != "insert":
                continue
            block = new[j1:j2]
            code = [l for l in block if l.strip() and not l.lstrip().startswith("#")]
            if not code:
                continue                                     # comments and blank lines only
            if errs_at < i1 <= errs_end:
                code_in_errs.extend(code)
            elif cls_at < i1 <= cls_end:
                rows_in_cls.extend(code)
            else:
                ok(False, f"(e) code inserted outside the two allowed places, before old line {i1 + 1}: {code[:2]}")
        try:
            tree = ast.parse("\n".join(l.strip() for l in code_in_errs) if code_in_errs else "")
            assigned = [(n.targets[0].id, ast.literal_eval(n.value)) for n in tree.body
                        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)]
            ok(len(assigned) == len(tree.body) and assigned == list(NEW_ERRORS.items()),
               f"(e) the code added beside REMOTE_OPS_VERB_DENIED is exactly the two constants (found {assigned})")
        except SyntaxError as e:
            ok(False, f"(e) the code added beside REMOTE_OPS_VERB_DENIED parses on its own: {e}")
        row = re.compile(r'^    "(room\.mem/read|room\.mem/append|room\.kv/cas)": DEGRADE_LOSSY,$')
        found = [row.match(l).group(1) if row.match(l) else l for l in rows_in_cls]
        ok(sorted(found) == sorted(NEW_METHODS),
           f"(e) the lines added inside METHOD_CLASSES are exactly the three rows, as DEGRADE_LOSSY (found {found})")

if failures:
    print(f"\nFAILED — {len(failures)} of {passed + len(failures)} checks")
    sys.exit(1)
print(f"\nOK — {passed} checks: the Room API rows agree across python, js, go and php, and nothing else moved.")
