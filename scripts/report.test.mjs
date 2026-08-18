#!/usr/bin/env node
// Self-check for report.mjs. Run with: node scripts/report.test.mjs
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { band, severity, location, collect, gate, counts, missingReports } from "./report.mjs";

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
              message: { text: "AWS  key\nditemukan" },
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
  assert.equal(findings[0].message, "AWS key ditemukan"); // whitespace flattened
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
  assert.match(r.stdout, /Tidak ada temuan/);

  // The main test dir holds broken.sarif -> always fails, even under fail-on none
  r = run([dir, "--fail-on", "none"]);
  assert.equal(r.code, 1, "broken SARIF must fail the build");

  // A Critical finding with the gate off -> passes, but the report stays complete
  const onlyOk = mkdtempSync(join(tmpdir(), "apr-ok-"));
  writeFileSync(join(onlyOk, "ok.sarif"), JSON.stringify({
    runs: [{ tool: { driver: { name: "gitleaks" } }, results: [{ ruleId: "k", message: { text: "bocor" } }] }],
  }));
  r = run([onlyOk, "--fail-on", "none"]);
  assert.equal(r.code, 0, "fail-on none must pass");
  assert.match(r.stdout, /Critical \(1\)/, "report is still produced when the gate is off");
  assert.match(r.stdout, /tidak ada severity yang menggagalkan/i);
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

  // A missing scanner fails the build even with no findings
  assert.equal(run([onlyOk, "--fail-on", "none", "--expect", "trivy.sarif"]).code, 1);

  // A commit message violation fails, and shows up in its own section
  writeFileSync(join(onlyOk, "commit.txt"), "subject may not be empty");
  r = run([onlyOk, "--fail-on", "none"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /### Commit Message/);
  assert.match(r.stdout, /subject may not be empty/);

  // A bogus --fail-on exits 2 rather than silently falling back to the default
  r = run([clean, "--fail-on", "ngawur"]);
  assert.equal(r.code, 2);

  rmSync(clean, { recursive: true, force: true });
  rmSync(onlyOk, { recursive: true, force: true });
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log("report.mjs: semua check lolos");
