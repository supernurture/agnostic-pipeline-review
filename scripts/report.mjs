#!/usr/bin/env node
// Gabungkan SARIF dari beberapa scanner jadi satu report bertingkat severity.
//
// Severity mengikuti standar yang sudah ada, bukan skala buatan sendiri:
// SARIF 2.1.0 untuk formatnya, dan properties.security-severity (skor CVSS)
// untuk band Critical/High/Medium/Low/Info.
//
// Dipakai: node scripts/report.mjs reports/ --fail-on high --expect a.sarif,b.sarif

import { existsSync, readFileSync, readdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

// Fallback saat SARIF tidak membawa security-severity sama sekali. Tambah
// entri di sini hanya kalau scanner barunya memang tidak security-aware.
const TOOL_FALLBACK = {
  // Kredensial hidup yang bocor bersifat kritis; gitleaks tidak memberi skor.
  gitleaks: () => "Critical",
  semgrep: (level) => pick({ error: "High", warning: "Medium" }, level, "Info"),
  trivy: () => "High",
};

const LEVEL_FALLBACK = { error: "High", warning: "Medium", note: "Info", none: "Info" };

// Kunci datang dari file SARIF, jadi jangan pernah pakai map[key] telanjang:
// level "constructor" akan mengembalikan fungsi, bukan default.
function pick(map, key, dflt) {
  return Object.hasOwn(map, key) ? map[key] : dflt;
}

/** Skor CVSS -> band, mengikuti pembagian GitHub code scanning. */
export function band(score) {
  if (!Number.isFinite(score)) return "Info";
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score > 0.0) return "Low";
  return "Info";
}

function score(props) {
  const raw = props?.["security-severity"];
  if (raw === undefined || raw === null || raw === "") return NaN;
  return Number(raw);
}

function findRule(result, ctx) {
  if (result.ruleId && ctx.byId.has(result.ruleId)) return ctx.byId.get(result.ruleId);
  // ruleIndex menunjuk ke driver.rules, bukan gabungannya dengan extensions.
  const i = result.ruleIndex;
  if (Number.isInteger(i) && i >= 0 && i < ctx.driverRules.length) return ctx.driverRules[i];
  return null;
}

/** Urutan resolusi: result -> rule -> fallback per tool -> level SARIF. */
export function severity(result, ctx) {
  let s = score(result.properties);
  if (!Number.isFinite(s)) {
    const rule = findRule(result, ctx);
    if (rule) s = score(rule.properties);
  }
  if (Number.isFinite(s)) return band(s);

  const level = String(result.level ?? "warning").toLowerCase();
  const tool = String(ctx.tool ?? "").toLowerCase();
  const key = Object.keys(TOOL_FALLBACK).find((k) => tool.includes(k));
  return key ? TOOL_FALLBACK[key](level) : pick(LEVEL_FALLBACK, level, "Info");
}

/** Sebagian result sah-sah saja tidak punya lokasi — null, bukan placeholder. */
export function location(result) {
  for (const loc of result.locations ?? []) {
    const phys = loc.physicalLocation ?? {};
    const uri = phys.artifactLocation?.uri;
    if (!uri) continue;
    const line = phys.region?.startLine;
    return line ? `${uri}:${line}` : uri;
  }
  return null;
}

function message(result) {
  const text = result.message?.text ?? "";
  // Satu baris, supaya list markdown tidak rusak.
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > 300 ? `${flat.slice(0, 297)}...` : flat;
}

export function collect(dir) {
  const findings = [];
  const problems = [];
  const files = existsSync(dir)
    ? readdirSync(dir).filter((f) => f.endsWith(".sarif")).sort()
    : [];

  for (const file of files) {
    let doc;
    try {
      doc = JSON.parse(readFileSync(join(dir, file), "utf8"));
    } catch (err) {
      problems.push(`\`${file}\` tidak bisa dibaca: ${err.message}`);
      continue;
    }
    for (const run of doc.runs ?? []) {
      const driver = run.tool?.driver ?? {};
      const driverRules = driver.rules ?? [];
      const byId = new Map();
      const extRules = (run.tool?.extensions ?? []).flatMap((e) => e.rules ?? []);
      for (const rule of [...driverRules, ...extRules]) {
        if (rule?.id) byId.set(rule.id, rule);
      }
      const ctx = { tool: driver.name ?? file, driverRules, byId };
      for (const result of run.results ?? []) {
        findings.push({
          severity: severity(result, ctx),
          tool: ctx.tool,
          rule: result.ruleId ?? "—",
          location: location(result),
          message: message(result),
        });
      }
    }
  }
  return { findings, problems };
}

/** Scanner yang diaktifkan tapi tidak meninggalkan laporan = gagal, bukan lulus. */
export function missingReports(dir, expected) {
  return expected.filter((name) => {
    const path = join(dir, name);
    if (!existsSync(path)) return true;
    try {
      return readFileSync(path, "utf8").trim() === "";
    } catch {
      return true;
    }
  });
}

export function counts(findings) {
  const out = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) out[f.severity] += 1;
  return out;
}

export function gate(findings, failOn) {
  if (failOn === "none") return false;
  const idx = SEVERITIES.indexOf(failOn);
  const blocking = new Set(SEVERITIES.slice(0, idx + 1));
  return findings.some((f) => blocking.has(f.severity));
}

// ponytail: tanpa dedup lintas-tool. Gitleaks & Semgrep bisa menandai secret
// yang sama dua kali. Tambahkan kunci (location, message ternormalisasi) kalau
// duplikatnya mulai mengganggu.
const MAX_PER_BAND = 50;

export function render({ findings, problems, commitLog, failOn, missing }) {
  const c = counts(findings);
  const out = ["## Review Report", ""];

  if (missing.length) {
    out.push("> **Scanner tidak menghasilkan laporan:** " + missing.map((m) => `\`${m}\``).join(", "));
    out.push("> Hasil di bawah ini tidak lengkap.", "");
  }
  for (const p of problems) out.push(`> ${p}`, "");

  out.push("| Severity | Jumlah |", "|---|---:|");
  for (const s of SEVERITIES) out.push(`| ${s} | ${c[s]} |`);
  out.push(`| **Total** | **${findings.length}** |`, "");
  out.push(
    failOn === "none"
      ? "Gate: tidak ada severity yang menggagalkan build."
      : `Gate: gagal pada **${failOn}** ke atas.`,
    "",
  );

  for (const s of SEVERITIES) {
    const items = findings.filter((f) => f.severity === s);
    if (!items.length) continue;
    out.push(`### ${s} (${items.length})`, "");
    for (const f of items.slice(0, MAX_PER_BAND)) {
      out.push(f.location ? `- \`${f.location}\` — ${f.tool}/${f.rule}` : `- ${f.tool}/${f.rule}`);
      if (f.message) out.push(`  ${f.message}`);
    }
    if (items.length > MAX_PER_BAND) {
      out.push(`- _...dan ${items.length - MAX_PER_BAND} temuan ${s} lainnya._`);
    }
    out.push("");
  }

  if (commitLog !== null) {
    out.push("### Commit Message", "");
    // Gaya penulisan commit bukan temuan keamanan, jadi ia tidak masuk skala CVSS.
    out.push(commitLog ? "```\n" + commitLog + "\n```" : "Semua pesan commit lolos.", "");
  }

  if (!findings.length && !missing.length && !problems.length) {
    out.push("Tidak ada temuan.", "");
  }
  return out.join("\n");
}

function normalizeFailOn(raw) {
  const value = String(raw).trim().toLowerCase();
  if (value === "none") return "none";
  const match = SEVERITIES.find((s) => s.toLowerCase() === value);
  if (!match) {
    throw new Error(`--fail-on tidak dikenal: ${raw} (pilihan: ${SEVERITIES.join(", ").toLowerCase()}, none)`);
  }
  return match;
}

function main(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      "fail-on": { type: "string", default: "high" },
      expect: { type: "string", default: "" },
    },
  });

  const dir = positionals[0] ?? "reports";
  const failOn = normalizeFailOn(values["fail-on"]);
  const expected = values.expect.split(",").map((s) => s.trim()).filter(Boolean);

  const { findings, problems } = collect(dir);
  const missing = missingReports(dir, expected);
  const commitPath = join(dir, "commit.txt");
  const commitLog = existsSync(commitPath) ? readFileSync(commitPath, "utf8").trim() : null;

  const markdown = render({ findings, problems, commitLog, failOn, missing });
  process.stdout.write(markdown + "\n");
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + "\n");
  }

  // Scanner yang gagal jalan adalah error infrastruktur, bukan "tidak ada temuan",
  // jadi ia menggagalkan build bahkan saat --fail-on none.
  if (missing.length || problems.length) return 1;
  if (commitLog) return 1;
  return gate(findings, failOn) ? 1 : 0;
}

// pathToFileURL, bukan `file://${argv[1]}`: yang terakhir tidak pernah cocok di
// Windows dan salah untuk path berspasi.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (err) {
    console.error(err.message);
    process.exit(2);
  }
}
