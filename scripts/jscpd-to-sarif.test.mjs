#!/usr/bin/env node
// Self-check for jscpd-to-sarif.mjs. Run with: node scripts/jscpd-to-sarif.test.mjs
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { toSarif } from "./jscpd-to-sarif.mjs";
import { collect } from "./report.mjs";

const CONVERT = fileURLToPath(new URL("./jscpd-to-sarif.mjs", import.meta.url));
const only = (report) => toSarif(report).runs[0].results;

// --- The shape jscpd actually emits ---
{
  const [r] = only({
    duplicates: [{
      format: "javascript",
      lines: 12,
      tokens: 84,
      firstFile: { name: "src/a.js", startLoc: { line: 10 }, endLoc: { line: 22 } },
      secondFile: { name: "src/b.js", startLoc: { line: 30 }, endLoc: { line: 42 } },
    }],
  });
  assert.equal(r.ruleId, "duplication");
  // note, not warning: fed in as an ordinary report this must land in Info
  // rather than invent a severity for a smell.
  assert.equal(r.level, "note");
  assert.deepEqual(r.locations[0].physicalLocation.artifactLocation, { uri: "src/a.js" });
  assert.deepEqual(r.locations[0].physicalLocation.region, { startLine: 10, endLine: 22 });
  // The other half of the pair has to be reachable and named — our report only
  // renders locations[0], so the message is where the reader learns the pair.
  assert.equal(r.relatedLocations[0].physicalLocation.artifactLocation.uri, "src/b.js");
  assert.equal(r.message.text, "12 duplicated lines, also at src/b.js:30");
}

// --- Windows separators become URI separators ---
// Not cosmetic: `scope: changed` compares against `git diff --name-only`, which
// always emits forward slashes, so a backslash path would be scoped away and
// the finding would vanish without a word.
{
  const [r] = only({
    duplicates: [{
      lines: 10,
      firstFile: { name: "src\\a.js", start: 1, end: 10 },
      secondFile: { name: "src\\nested\\b.js", start: 4 },
    }],
  });
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, "src/a.js");
  assert.equal(r.relatedLocations[0].physicalLocation.artifactLocation.uri, "src/nested/b.js");
  assert.equal(r.message.text, "10 duplicated lines, also at src/nested/b.js:4");
}

// --- Older jscpd: plain start/end, no *Loc ---
{
  const [r] = only({
    duplicates: [{ lines: 5, firstFile: { name: "a.py", start: 3, end: 8 }, secondFile: { name: "b.py", start: 40 } }],
  });
  assert.deepEqual(r.locations[0].physicalLocation.region, { startLine: 3, endLine: 8 });
  assert.equal(r.message.text, "5 duplicated lines, also at b.py:40");
}

// --- Missing pieces must degrade, not throw ---
assert.deepEqual(only({}), [], "no duplicates key");
assert.deepEqual(only({ duplicates: [] }), []);
assert.deepEqual(only({ duplicates: null }), []);
assert.deepEqual(only(null), []);
// A `duplicates` that is present but not a list must not be iterated
assert.deepEqual(only({ duplicates: "oops" }), [], "a string is not a list");
assert.deepEqual(only({ duplicates: { a: 1 } }), [], "an object is not a list");
assert.deepEqual(only({ duplicates: 7 }), []);

// A line number that is absent, zero, or not a number yields no region at all —
// never `startLine: undefined`, which is not valid SARIF.
for (const start of [undefined, 0, -1, "12", 1.5, null]) {
  const [r] = only({ duplicates: [{ firstFile: { name: "a.js", start } }] });
  assert.ok(r, `a nameable finding survives a start of ${String(start)}`);
  assert.equal(r.locations[0].physicalLocation.region, undefined, `no region for start=${String(start)}`);
  assert.deepEqual(Object.keys(r.locations[0].physicalLocation), ["artifactLocation"]);
}
// A duplicate with no usable first location is dropped: a finding that points
// nowhere is noise.
assert.deepEqual(only({ duplicates: [{ lines: 4, secondFile: { name: "b.js", start: 1 } }] }), []);
assert.deepEqual(only({ duplicates: [{ firstFile: { start: 1 } }] }), [], "no filename");

{
  // No second file, no line count
  const [r] = only({ duplicates: [{ firstFile: { name: "a.js", start: 7 } }] });
  assert.equal(r.message.text, "Duplicated code");
  assert.equal(r.relatedLocations, undefined);
  assert.deepEqual(r.locations[0].physicalLocation.region, { startLine: 7 });
}

{
  // An end before the start is not a range
  const [r] = only({ duplicates: [{ firstFile: { name: "a.js", start: 9, end: 2 } }] });
  assert.deepEqual(r.locations[0].physicalLocation.region, { startLine: 9 });
}

// --- The envelope has to be SARIF that other tools accept ---
{
  const doc = toSarif({ duplicates: [] });
  assert.equal(doc.version, "2.1.0");
  assert.equal(doc.runs[0].tool.driver.name, "jscpd");
  assert.equal(doc.runs[0].tool.driver.rules[0].id, "duplication");
}

// --- End to end: the file it writes must be readable by report.mjs ---
const dir = mkdtempSync(join(tmpdir(), "apr-jscpd-"));
try {
  const input = join(dir, "jscpd-report.json");
  writeFileSync(input, JSON.stringify({
    duplicates: [{
      lines: 12,
      firstFile: { name: "src/a.js", startLoc: { line: 10 }, endLoc: { line: 22 } },
      secondFile: { name: "src/b.js", startLoc: { line: 30 } },
    }],
  }));
  const sarif = execFileSync(process.execPath, [CONVERT, input], { encoding: "utf8" });
  writeFileSync(join(dir, "duplication.sarif"), sarif);

  const { findings, problems } = collect(dir);
  assert.deepEqual(problems, [], "the SARIF it writes must parse");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].tool, "jscpd");
  assert.equal(findings[0].location, "src/a.js:10");
  assert.equal(findings[0].severity, "Info", "a smell must not be graded as a vulnerability");
  assert.match(findings[0].message, /also at src\/b\.js:30/);

  // Unreadable input fails loudly rather than emitting empty SARIF, which would
  // pass for "no duplication found".
  writeFileSync(join(dir, "broken.json"), "{ not json");
  let code = 0;
  try {
    execFileSync(process.execPath, [CONVERT, join(dir, "broken.json")], { stdio: "pipe" });
  } catch (err) {
    code = err.status;
  }
  assert.equal(code, 2, "broken input must exit 2");

  // No argument must say so. Without the explicit check it would still exit 2,
  // but complaining that "undefined could not be read" helps nobody.
  code = 0;
  let stderr = "";
  try {
    execFileSync(process.execPath, [CONVERT], { stdio: "pipe" });
  } catch (err) {
    code = err.status;
    stderr = String(err.stderr ?? "");
  }
  assert.equal(code, 2, "no argument must exit 2");
  assert.match(stderr, /^usage:/m, "and must print usage, not a read error");
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log("jscpd-to-sarif.mjs: all checks passed");
