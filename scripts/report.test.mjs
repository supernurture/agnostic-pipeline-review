#!/usr/bin/env node
// Self-check for report.mjs. Run with: node scripts/report.test.mjs
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  band, severity, location, collect, gate, counts, missingReports, readChanged, scopeTo, STYLE_DIR,
} from "./report.mjs";

const REPORT = fileURLToPath(new URL("./report.mjs", import.meta.url));
const ctx = (tool) => ({ tool, driverRules: [], byId: new Map() });

// --- CVSS bands: the boundaries are what matter, not the middles ---
assert.equal(band(10.0), "Critical");
assert.equal(band(9.0), "Critical");
assert.equal(band(8.9), "High");
assert.equal(band(7.0), "High");
assert.equal(band(6.9), "Medium");
assert.equal(band(4.0), "Medium");
assert.equal(band(3.9), "Low");
assert.equal(band(0.1), "Low");
assert.equal(band(0.0), "Info");
assert.equal(band(NaN), "Info");

// --- Resolution priority: security-severity beats the SARIF level ---
assert.equal(
  severity({ level: "note", properties: { "security-severity": "9.8" } }, ctx("trivy")),
  "Critical",
);

// --- Score from rule metadata, matched via ruleId ---
{
  const rules = [{ id: "CVE-2021-1", properties: { "security-severity": "7.5" } }];
  const c = { tool: "Trivy", driverRules: rules, byId: new Map(rules.map((r) => [r.id, r])) };
  assert.equal(severity({ ruleId: "CVE-2021-1", level: "warning" }, c), "High");
}

// --- ...and via ruleIndex when there is no ruleId ---
{
  const rules = [{ id: "a" }, { id: "b", properties: { "security-severity": "5.0" } }];
  const c = { tool: "Semgrep", driverRules: rules, byId: new Map() };
  assert.equal(severity({ ruleIndex: 1, level: "error" }, c), "Medium");
  // An out-of-range ruleIndex must not throw, just fall through to the fallback
  assert.equal(severity({ ruleIndex: 99, level: "error" }, c), "High");
}

// --- Per-tool fallback when there is no score at all ---
assert.equal(severity({ level: "error" }, ctx("gitleaks")), "Critical");
assert.equal(severity({ level: "note" }, ctx("gitleaks")), "Critical");
assert.equal(severity({ level: "error" }, ctx("Semgrep OSS")), "High");
assert.equal(severity({ level: "warning" }, ctx("Semgrep OSS")), "Medium");
assert.equal(severity({ level: "note" }, ctx("Semgrep OSS")), "Info");
assert.equal(severity({ level: "error" }, ctx("Trivy Vulnerability Scanner")), "High");

// --- An unknown tool falls back to the SARIF level ---
assert.equal(severity({ level: "error" }, ctx("some-new-linter")), "High");
assert.equal(severity({ level: "warning" }, ctx("some-new-linter")), "Medium");
assert.equal(severity({ level: "none" }, ctx("some-new-linter")), "Info");
assert.equal(severity({}, ctx("some-new-linter")), "Medium"); // default level = warning

// --- Keys read from a file must not reach through to the prototype ---
assert.equal(severity({ level: "constructor" }, ctx("some-new-linter")), "Info");
assert.equal(severity({ level: "constructor" }, ctx("Semgrep OSS")), "Info");

// --- A result without locations must not crash ---
assert.equal(location({}), null);
assert.equal(location({ locations: [] }), null);
assert.equal(location({ locations: [{ physicalLocation: {} }] }), null);
assert.equal(
  location({ locations: [{ physicalLocation: { artifactLocation: { uri: "a.py" } } }] }),
  "a.py",
);
assert.equal(
  location({
    locations: [{ physicalLocation: { artifactLocation: { uri: "a.py" }, region: { startLine: 42 } } }],
  }),
  "a.py:42",
);

// --- The gate respects its threshold ---
const found = [{ severity: "Medium" }, { severity: "Info" }];
assert.equal(gate(found, "Critical"), false);
assert.equal(gate(found, "High"), false);
assert.equal(gate(found, "Medium"), true);
assert.equal(gate(found, "Low"), true);
assert.equal(gate([{ severity: "Critical" }], "High"), true);
assert.equal(gate([{ severity: "Critical" }], "none"), false);
assert.equal(gate([], "Info"), false);

// --- Scoping to the files a change touches ---
{
  const f = (location) => ({ severity: "Critical", location });
  const changed = new Set(["src/db.py"]);
  assert.equal(scopeTo([f("src/db.py:7")], changed).length, 1);
  assert.equal(scopeTo([f("src/other.py:7")], changed).length, 0);
  // No line number, and no location at all
  assert.equal(scopeTo([f("src/db.py")], changed).length, 1);
  assert.equal(scopeTo([f(null)], changed).length, 1, "an unlocatable finding must not be hidden");
  // A colon inside the path must not be mistaken for a line number
  assert.equal(scopeTo([f("a:b.py")], new Set(["a:b.py"])).length, 1);
  // Without a change list nothing is filtered
  assert.equal(scopeTo([f("src/other.py:7")], null).length, 1);
}

// --- Reading a directory: broken SARIF is reported, not swallowed ---
const dir = mkdtempSync(join(tmpdir(), "apr-"));
try {
  writeFileSync(
    join(dir, "ok.sarif"),
    JSON.stringify({
      runs: [
        {
          tool: { driver: { name: "gitleaks" } },
          results: [
            {
              ruleId: "aws-key",
              message: { text: "AWS  key\nfound" },
              locations: [
                { physicalLocation: { artifactLocation: { uri: "db.py" }, region: { startLine: 7 } } },
              ],
            },
          ],
        },
      ],
    }),
  );
  writeFileSync(join(dir, "broken.sarif"), "{ not json");

  const { findings, problems } = collect(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "Critical");
  assert.equal(findings[0].location, "db.py:7");
  assert.equal(findings[0].message, "AWS key found"); // whitespace flattened
  assert.equal(problems.length, 1);
  assert.match(problems[0], /broken\.sarif/);

  assert.deepEqual(counts(findings), { Critical: 1, High: 0, Medium: 0, Low: 0, Info: 0 });

  // A missing directory means empty, not a crash
  assert.deepEqual(collect(join(dir, "nope")).findings, []);

  // Reports that were expected but are missing / empty
  writeFileSync(join(dir, "empty.sarif"), "   ");
  assert.deepEqual(missingReports(dir, ["ok.sarif"]), []);
  assert.deepEqual(missingReports(dir, ["gone.sarif"]), ["gone.sarif"]);
  assert.deepEqual(missingReports(dir, ["empty.sarif"]), ["empty.sarif"]);

  // --- CLI: exit code and --fail-on ---
  const run = (args) => {
    try {
      const stdout = execFileSync(process.execPath, [REPORT, ...args], { encoding: "utf8" });
      return { code: 0, stdout };
    } catch (err) {
      return { code: err.status, stdout: err.stdout ?? "" };
    }
  };

  const clean = mkdtempSync(join(tmpdir(), "apr-clean-"));
  writeFileSync(join(clean, "ok.sarif"), JSON.stringify({ runs: [] }));

  let r = run([clean, "--fail-on", "high"]);
  assert.equal(r.code, 0, "no findings -> pass");
  assert.match(r.stdout, /No findings/);

  // The main test dir holds broken.sarif -> always fails, even under fail-on none
  r = run([dir, "--fail-on", "none"]);
  assert.equal(r.code, 1, "broken SARIF must fail the build");

  // A Critical finding with the gate off -> passes, but the report stays complete
  const onlyOk = mkdtempSync(join(tmpdir(), "apr-ok-"));
  writeFileSync(join(onlyOk, "ok.sarif"), JSON.stringify({
    runs: [{ tool: { driver: { name: "gitleaks" } }, results: [{ ruleId: "k", message: { text: "leaked" } }] }],
  }));
  r = run([onlyOk, "--fail-on", "none"]);
  assert.equal(r.code, 0, "fail-on none must pass");
  assert.match(r.stdout, /Critical \(1\)/, "report is still produced when the gate is off");
  assert.match(r.stdout, /no severity fails the build/i);
  // A finding without a location must not render an empty backticked placeholder.
  assert.doesNotMatch(r.stdout, /`—`/);
  assert.match(r.stdout, /^- gitleaks\/k$/m);
  // The report is also written to disk so it can be uploaded as an artifact.
  // Compare against the run that produced it — a later run overwrites the file.
  const reportFile = join(onlyOk, "review-report.md");
  assert.ok(existsSync(reportFile), "review-report.md must be written");
  assert.equal(readFileSync(reportFile, "utf8").trim(), r.stdout.trim());
  // Writing it must not make the next run treat it as an input
  assert.equal(collect(onlyOk).findings.length, 1, "the .md must not be parsed as SARIF");
  assert.equal(run([onlyOk, "--fail-on", "critical"]).code, 1);

  // --- Scoping end to end: an out-of-scope Critical must not gate ---
  const scoped = mkdtempSync(join(tmpdir(), "apr-scope-"));
  writeFileSync(join(scoped, "ok.sarif"), JSON.stringify({
    runs: [{
      tool: { driver: { name: "gitleaks" } },
      results: [{
        ruleId: "k",
        message: { text: "leaked" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "db.py" }, region: { startLine: 7 } } }],
      }],
    }],
  }));
  const changedFile = join(scoped, "changed.txt");

  writeFileSync(changedFile, "other.py\n");
  r = run([scoped, "--fail-on", "critical", "--changed", changedFile]);
  assert.equal(r.code, 0, "a finding outside the diff must not gate");
  assert.match(r.stdout, /Not listed: 1 finding/, "hidden findings must still be announced");
  assert.match(r.stdout, /on changed files only/);

  writeFileSync(changedFile, "db.py\n");
  assert.equal(run([scoped, "--fail-on", "critical", "--changed", changedFile]).code, 1);

  // An empty or missing list must fail open — scoping to nothing would hide
  // every finding in the repo.
  writeFileSync(changedFile, "\n  \n");
  assert.equal(readChanged(changedFile), null);
  assert.equal(run([scoped, "--fail-on", "critical", "--changed", changedFile]).code, 1);
  assert.equal(readChanged(join(scoped, "nope.txt")), null);
  assert.equal(run([scoped, "--fail-on", "critical"]).code, 1, "no --changed means no scoping");
  rmSync(scoped, { recursive: true, force: true });

  // --- Coding standard findings: own section, no gate, still scoped ---
  const styled = mkdtempSync(join(tmpdir(), "apr-style-"));
  mkdirSync(join(styled, STYLE_DIR));
  writeFileSync(join(styled, "clean.sarif"), JSON.stringify({ runs: [] }));
  writeFileSync(join(styled, STYLE_DIR, "0-ruff.sarif"), JSON.stringify({
    runs: [{
      tool: { driver: { name: "Ruff" } },
      results: [{
        ruleId: "E501",
        level: "error",
        message: { text: "Line too long" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 10 } } }],
      }],
    }],
  }));

  r = run([styled, "--fail-on", "critical"]);
  assert.equal(r.code, 0, "style findings must not gate");
  assert.match(r.stdout, /### Coding Standard \(1\)/);
  assert.match(r.stdout, /`app\.py:10` — Ruff\/E501/);
  // level: error must not become High in the CVSS table — that is the whole point
  assert.match(r.stdout, /\| \*\*Total\*\* \| \*\*0\*\* \|/);
  assert.doesNotMatch(r.stdout, /### High/);
  assert.doesNotMatch(r.stdout, /No findings/, "a style finding is still a finding");

  // Scoping applies here too, and the hidden ones are still announced
  const styleChanged = join(styled, "changed.txt");
  writeFileSync(styleChanged, "other.py\n");
  r = run([styled, "--fail-on", "critical", "--changed", styleChanged]);
  assert.equal(r.code, 0);
  assert.doesNotMatch(r.stdout, /### Coding Standard/);
  assert.match(r.stdout, /Not listed: 1 finding/);
  rmSync(styled, { recursive: true, force: true });

  // A missing scanner fails the build even with no findings
  assert.equal(run([onlyOk, "--fail-on", "none", "--expect", "trivy.sarif"]).code, 1);

  // --- A tool that normally scores but stopped ---
  // Its bands move to the fallback table with no error anywhere, so the report
  // has to say so — as a note, not as a build failure.
  const noScore = mkdtempSync(join(tmpdir(), "apr-noscore-"));
  const sarif = (tool, extra) =>
    JSON.stringify({ runs: [{ tool: { driver: { name: tool } }, results: [{ ruleId: "x", ...extra }] }] });

  writeFileSync(join(noScore, "trivy.sarif"), sarif("Trivy Vulnerability Scanner", { level: "error" }));
  assert.equal(collect(noScore).notes.length, 1, "a scoreless Trivy must be flagged");
  // Two runs from the same tool must not repeat the note
  writeFileSync(
    join(noScore, "two-runs.sarif"),
    JSON.stringify({
      runs: [0, 1].map(() => ({
        tool: { driver: { name: "Trivy Vulnerability Scanner" } },
        results: [{ ruleId: "x", level: "error" }],
      })),
    }),
  );
  assert.equal(collect(noScore).notes.length, 1, "the note must be deduplicated");
  rmSync(join(noScore, "two-runs.sarif"));
  assert.match(collect(noScore).notes[0], /security-severity/);
  r = run([noScore, "--fail-on", "none"]);
  assert.equal(r.code, 0, "the note must not fail the build");
  assert.match(r.stdout, /security-severity/);

  // Gitleaks never scores — that is the design, not a regression
  writeFileSync(join(noScore, "trivy.sarif"), sarif("gitleaks", { level: "error" }));
  assert.deepEqual(collect(noScore).notes, []);

  // ...and a Trivy that still scores stays quiet
  writeFileSync(
    join(noScore, "trivy.sarif"),
    sarif("Trivy Vulnerability Scanner", { properties: { "security-severity": "7.5" } }),
  );
  assert.deepEqual(collect(noScore).notes, []);

  // A commit message violation fails, and shows up in its own section.
  // commit.failed is the verdict — the step writes it when commitlint exits
  // non-zero, because output alone does not mean failure.
  writeFileSync(join(onlyOk, "commit.txt"), "subject may not be empty");
  writeFileSync(join(onlyOk, "commit.failed"), "");
  r = run([onlyOk, "--fail-on", "none"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /### Commit Message/);
  assert.match(r.stdout, /subject may not be empty/);

  // commitlint prints warning-level rules and still exits 0: the text must be
  // shown, and it must not fail the build.
  rmSync(join(onlyOk, "commit.failed"));
  writeFileSync(join(onlyOk, "commit.txt"), "found 0 problems, 1 warnings");
  r = run([onlyOk, "--fail-on", "none"]);
  assert.equal(r.code, 0, "warnings must not fail the build");
  assert.match(r.stdout, /1 warnings/);
  assert.match(r.stdout, /does not fail the build/);

  // A bogus --fail-on exits 2 rather than silently falling back to the default
  r = run([clean, "--fail-on", "bogus"]);
  assert.equal(r.code, 2);

  rmSync(clean, { recursive: true, force: true });
  rmSync(onlyOk, { recursive: true, force: true });
  rmSync(noScore, { recursive: true, force: true });
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log("report.mjs: all checks passed");
