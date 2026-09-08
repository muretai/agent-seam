#!/usr/bin/env node
// SPDX-License-Identifier: MIT
/*
 * tools/check-manifest.mjs — tools/manifest.json tells the truth about js/seam.mjs.
 *
 * Every consumer cuts this file by the manifest: the door splices the region between `start`
 * and `end` into itself and carries the declarations under `pinnedMarker` by name; the two
 * consumers that vendor the whole file still pin its section list. So the manifest must be
 * exact, and this check is the only thing that makes it so:
 *
 *   - the file is UTF-8 with LF line ends and no BOM (the door's splice is line-based);
 *   - the three markers each match exactly one line, in the order marker < start < end;
 *   - the region holds exactly the named sections, in order, is at least `minLines` long
 *     (a mangled banner would otherwise shrink the region to nothing and every consumer's
 *     "region equals region" would pass on two empty strings), and carries no `import`;
 *   - the pinned zone holds exactly the named declarations and NOTHING ELSE — no more (a
 *     consumer would silently not carry one), no fewer, no bare statement between them;
 *   - every pinned name declared with `export` is actually exported by the module (a
 *     declaration inside a comment, or behind `if (false)`, is not a declaration);
 *   - nothing above the pinned marker is code except the `node:` imports, and after the end
 *     marker there is exactly one footer export.
 *
 * COMMENTS ARE STRIPPED BEFORE A LINE IS JUDGED. The first cut of this file looked at each
 * line's first characters: a pinned declaration wrapped in `/* … *\/` still counted, a
 * statement prefixed with `/**\/` read as a comment, and `export var` / an indented `export
 * const` / two declarations on one line were not counted at all. Four attacks, one afternoon.
 *
 * Run: node tools/check-manifest.mjs      (part of `npm test`)
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import process from 'node:process';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SEAM = join(ROOT, 'js', 'seam.mjs');
const M = JSON.parse(readFileSync(join(ROOT, 'tools', 'manifest.json'), 'utf8'));
const raw = readFileSync(SEAM);
let pass = 0; const fails = [];
const ok = (cond, label) => { if (cond) pass += 1; else { fails.push(label); console.log(`  FAIL ${label}`); } };

// ---- bytes
ok(!(raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf), 'js/seam.mjs has no UTF-8 BOM');
const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
ok(!text.includes('\r'), 'js/seam.mjs uses LF line ends');
const lines = text.split('\n');

// ---- comments, stripped as SPANS so a line is judged by what is left of it
let inComment = false;
/** The code on one line with `/* … *\/` spans and `// …` tails removed, trimmed. Carries
 *  block-comment state across lines. */
function code(l) {
  let out = '';
  let quote = null;                            // inside '…', "…" or `…` — a `//` there is text
  for (let k = 0; k < l.length; k += 1) {
    const ch = l[k];
    if (quote) {
      out += ch;
      if (ch === '\\' && k + 1 < l.length) { out += l[k + 1]; k += 1; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (inComment) { if (l.startsWith('*/', k)) { inComment = false; k += 1; } continue; }
    if (l.startsWith('/*', k)) { inComment = true; k += 1; continue; }
    if (l.startsWith('//', k)) break;
    if (ch === "'" || ch === '"' || ch === '`') quote = ch;
    out += ch;
  }
  return out.trim();
}
const stripped = lines.map(code);            // one pass, in order, so the state is right
ok(!inComment, 'js/seam.mjs closes every block comment');

// ---- markers
const jr = M.jsRegion;
const only = (re, name) => {
  const hits = lines.map((l, i) => (new RegExp(re).test(l) ? i : -1)).filter((i) => i >= 0);
  ok(hits.length === 1, `manifest ${name} ${JSON.stringify(re)} matches exactly one line (matched ${hits.length})`);
  return hits[0] ?? -1;
};
const marker = only(jr.pinnedMarker, 'pinnedMarker');
const start = only(jr.start, 'start');
const end = only(jr.end, 'end');
ok(marker >= 0 && start > marker && end > start, `markers are ordered: pinned ${marker + 1} < start ${start + 1} < end ${end + 1}`);
if (fails.length) { console.log(`\nFAILED — ${fails.length} of ${pass + fails.length} checks`); process.exit(1); }

// ---- the region
const region = lines.slice(start, end);
ok(region.length >= jr.minLines, `region is ${region.length} lines, at least minLines ${jr.minLines}`);
const banners = region.map((l) => /^\/\/ ={10,} (.+)$/.exec(l)).filter(Boolean).map((m) => m[1].trim());
ok(JSON.stringify(banners) === JSON.stringify(jr.sections), `region sections are exactly the manifest's, in order (found ${banners.length}: ${banners.join(' | ')})`);
const regionImports = stripped.slice(start, end).map((l, k) => [start + k + 1, l]).filter(([, l]) => /^(import\b|export\s+\*\s+from\b|export\s+\{[^}]*\}\s+from\b)/.test(l));
ok(regionImports.length === 0, `the region imports nothing (an import inside it would be hoisted past every consumer's surface check): ${regionImports.map(([n, l]) => `${n}: ${l.slice(0, 50)}`).join(' ; ')}`);

// ---- the pinned zone: exactly the named declarations, and nothing else
const KW = /\b(?:const|let|var|function|class)\s+[A-Za-z_$]/g;
const DECL = /^(?:export\s+)?(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)/;
function unitEnd(i) {
  let depth = 0;
  for (let e = i; e < lines.length && e < i + 400; e += 1) {
    for (const ch of stripped[e]) { if ('([{'.includes(ch)) depth += 1; else if (')]}'.includes(ch)) depth -= 1; }
    if (depth <= 0 && /[;}\]]\s*$/.test(stripped[e])) return e;
  }
  return i;
}
const declared = []; const exported = []; const zoneStray = [];
for (let i = marker + 1; i < start; i += 1) {
  const l = stripped[i];
  if (l === '') continue;
  const m = DECL.exec(l);
  if (!m) { zoneStray.push(`${i + 1}: ${l.slice(0, 60)}`); continue; }
  if ((l.match(KW) || []).length !== 1) { zoneStray.push(`${i + 1}: line opening ${m[1]} holds ${(l.match(KW) || []).length} declaration keywords`); }
  if (lines[i] !== lines[i].trimStart()) zoneStray.push(`${i + 1}: ${m[1]} is indented — a pinned declaration is top-level`);
  declared.push(m[1]);
  if (/^export\s/.test(l)) exported.push(m[1]);
  i = unitEnd(i);
}
ok(JSON.stringify([...declared].sort()) === JSON.stringify([...jr.pinnedDeclarations].sort()),
   `pinned zone declares exactly the manifest's ${jr.pinnedDeclarations.length} names (found ${declared.length}: ${declared.join(', ')})`);
ok(zoneStray.length === 0, `pinned zone holds only the counted declarations: ${zoneStray.join(' ; ')}`);

// ---- the module really exports what the pinned zone says it exports
const mod = await import(pathToFileURL(SEAM).href);
const notExported = exported.filter((n) => !(n in mod));
ok(notExported.length === 0, `every pinned \`export\` is an export of the module (missing: ${notExported.join(', ')})`);

// ---- nothing above the marker is code but the node: imports
const stray = []; let inImport = false;
for (let i = 0; i < marker; i += 1) {
  const l = stripped[i];
  if (l === '') continue;
  if (/^import\b/.test(l)) {
    if (/\bfrom\s+'node:[a-z]+';$/.test(l)) continue;                // one-line import from node:
    if (/\bfrom\s+'/.test(l)) { stray.push(`${i + 1}: import from somewhere other than node: — ${l.slice(0, 60)}`); continue; }
    inImport = true; continue;                                        // an import that continues below
  }
  if (inImport) {
    if (/^\}\s+from\s+'node:[a-z]+';$/.test(l)) { inImport = false; continue; }
    if (/^\}\s+from\s+'/.test(l)) { stray.push(`${i + 1}: import from somewhere other than node: — ${l.slice(0, 60)}`); inImport = false; continue; }
    if (/^[A-Za-z_$][\w$]*(\s+as\s+[A-Za-z_$][\w$]*)?(\s*,\s*[A-Za-z_$][\w$]*(\s+as\s+[A-Za-z_$][\w$]*)?)*\s*,?$/.test(l)) continue;
  }
  stray.push(`${i + 1}: ${l.slice(0, 60)}`);
}
ok(stray.length === 0, `nothing above the pinned marker is code except the node: imports: ${stray.join(' ; ')}`);

// ---- after the end marker: one footer export, and nothing else
const footer = stripped.slice(end + 1).map((l, k) => [end + 1 + k, l]).filter(([, l]) => l !== '');
ok(footer.length === 1 && /^export \{ [\w$]+ \};$/.test(footer[0][1]), `after the end marker there is exactly one footer export (found ${footer.length}: ${footer.map(([n, l]) => `${n}: ${l.slice(0, 40)}`).join(' ; ')})`);
if (footer.length === 1) {
  const name = /^export \{ ([\w$]+) \};$/.exec(footer[0][1])?.[1];
  ok(name && name in mod, `the footer export ${name} is an export of the module`);
}

// ---- the JS runner covers what the manifest says it covers
const impl = M.implementations.find((x) => x.lang === 'js');
ok(impl && impl.dir === 'js' && impl.run.includes('js/conformance/run.mjs'), 'manifest names the JS runner');

if (fails.length) { console.log(`\nFAILED — ${fails.length} of ${pass + fails.length} checks`); process.exit(1); }
console.log(`OK — ${pass} checks: tools/manifest.json describes js/seam.mjs exactly (region ${region.length} lines, ${banners.length} sections, ${declared.length} pinned declarations, ${exported.length} of them exported).`);
