#!/usr/bin/env node
// Self-check untuk report.mjs. Jalankan: node scripts/report.test.mjs
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { band, severity, location, collect, gate, counts, missingReports } from "./report.mjs";

const REPORT = fileURLToPath(new URL("./report.mjs", import.meta.url));
const ctx = (tool) => ({ tool, driverRules: [], byId: new Map() });

// --- Band CVSS: batasnya yang penting, bukan tengahnya ---
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

// --- Prioritas resolusi: security-severity menang atas level SARIF ---
assert.equal(
  severity({ level: "note", properties: { "security-severity": "9.8" } }, ctx("trivy")),
  "Critical",
);

// --- Skor dari metadata rule, dicocokkan lewat ruleId ---
{
  const rules = [{ id: "CVE-2021-1", properties: { "security-severity": "7.5" } }];
  const c = { tool: "Trivy", driverRules: rules, byId: new Map(rules.map((r) => [r.id, r])) };
  assert.equal(severity({ ruleId: "CVE-2021-1", level: "warning" }, c), "High");
}

// --- ...dan lewat ruleIndex saat ruleId tidak ada ---
{
  const rules = [{ id: "a" }, { id: "b", properties: { "security-severity": "5.0" } }];
  const c = { tool: "Semgrep", driverRules: rules, byId: new Map() };
  assert.equal(severity({ ruleIndex: 1, level: "error" }, c), "Medium");
  // ruleIndex di luar rentang tidak boleh melempar, cukup jatuh ke fallback
  assert.equal(severity({ ruleIndex: 99, level: "error" }, c), "High");
}

// --- Fallback per tool saat tidak ada skor sama sekali ---
assert.equal(severity({ level: "error" }, ctx("gitleaks")), "Critical");
assert.equal(severity({ level: "note" }, ctx("gitleaks")), "Critical");
assert.equal(severity({ level: "error" }, ctx("Semgrep OSS")), "High");
assert.equal(severity({ level: "warning" }, ctx("Semgrep OSS")), "Medium");
assert.equal(severity({ level: "note" }, ctx("Semgrep OSS")), "Info");
assert.equal(severity({ level: "error" }, ctx("Trivy Vulnerability Scanner")), "High");

// --- Tool tak dikenal jatuh ke level SARIF ---
assert.equal(severity({ level: "error" }, ctx("some-new-linter")), "High");
assert.equal(severity({ level: "warning" }, ctx("some-new-linter")), "Medium");
assert.equal(severity({ level: "none" }, ctx("some-new-linter")), "Info");
assert.equal(severity({}, ctx("some-new-linter")), "Medium"); // default level = warning

// --- Kunci dari file tidak boleh menembus ke prototype ---
assert.equal(severity({ level: "constructor" }, ctx("some-new-linter")), "Info");
assert.equal(severity({ level: "constructor" }, ctx("Semgrep OSS")), "Info");

// --- Result tanpa locations tidak boleh bikin crash ---
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

// --- Gate menghormati ambang ---
const found = [{ severity: "Medium" }, { severity: "Info" }];
assert.equal(gate(found, "Critical"), false);
assert.equal(gate(found, "High"), false);
assert.equal(gate(found, "Medium"), true);
assert.equal(gate(found, "Low"), true);
assert.equal(gate([{ severity: "Critical" }], "High"), true);
assert.equal(gate([{ severity: "Critical" }], "none"), false);
assert.equal(gate([], "Info"), false);

// --- Baca direktori: SARIF rusak dilaporkan, bukan ditelan diam-diam ---
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
  writeFileSync(join(dir, "broken.sarif"), "{ bukan json");

  const { findings, problems } = collect(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "Critical");
  assert.equal(findings[0].location, "db.py:7");
  assert.equal(findings[0].message, "AWS key ditemukan"); // whitespace diratakan
  assert.equal(problems.length, 1);
  assert.match(problems[0], /broken\.sarif/);

  assert.deepEqual(counts(findings), { Critical: 1, High: 0, Medium: 0, Low: 0, Info: 0 });

  // Direktori tidak ada = kosong, bukan crash
  assert.deepEqual(collect(join(dir, "nope")).findings, []);

  // Laporan yang diharapkan tapi hilang / kosong
  writeFileSync(join(dir, "empty.sarif"), "   ");
  assert.deepEqual(missingReports(dir, ["ok.sarif"]), []);
  assert.deepEqual(missingReports(dir, ["hilang.sarif"]), ["hilang.sarif"]);
  assert.deepEqual(missingReports(dir, ["empty.sarif"]), ["empty.sarif"]);

  // --- CLI: exit code & --fail-on ---
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
  assert.equal(r.code, 0, "tidak ada temuan -> lulus");
  assert.match(r.stdout, /Tidak ada temuan/);

  // Direktori uji utama punya broken.sarif -> selalu gagal, bahkan fail-on none
  r = run([dir, "--fail-on", "none"]);
  assert.equal(r.code, 1, "SARIF rusak harus menggagalkan build");

  // Temuan Critical, gate none -> lulus tapi report tetap lengkap
  const onlyOk = mkdtempSync(join(tmpdir(), "apr-ok-"));
  writeFileSync(join(onlyOk, "ok.sarif"), JSON.stringify({
    runs: [{ tool: { driver: { name: "gitleaks" } }, results: [{ ruleId: "k", message: { text: "bocor" } }] }],
  }));
  r = run([onlyOk, "--fail-on", "none"]);
  assert.equal(r.code, 0, "fail-on none harus lulus");
  assert.match(r.stdout, /Critical \(1\)/, "report tetap tergenerate saat gate mati");
  assert.match(r.stdout, /tidak ada severity yang menggagalkan/i);
  // Temuan tanpa lokasi tidak boleh merender placeholder kosong berbacktick.
  assert.doesNotMatch(r.stdout, /`—`/);
  assert.match(r.stdout, /^- gitleaks\/k$/m);
  assert.equal(run([onlyOk, "--fail-on", "critical"]).code, 1);

  // Scanner hilang -> gagal walau tidak ada temuan
  assert.equal(run([onlyOk, "--fail-on", "none", "--expect", "trivy.sarif"]).code, 1);

  // Commit message gagal -> gagal, dan muncul di sectionnya sendiri
  writeFileSync(join(onlyOk, "commit.txt"), "subject may not be empty");
  r = run([onlyOk, "--fail-on", "none"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /### Commit Message/);
  assert.match(r.stdout, /subject may not be empty/);

  // --fail-on ngawur -> exit 2, bukan diam-diam dianggap default
  r = run([clean, "--fail-on", "ngawur"]);
  assert.equal(r.code, 2);

  rmSync(clean, { recursive: true, force: true });
  rmSync(onlyOk, { recursive: true, force: true });
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log("report.mjs: semua check lolos");
