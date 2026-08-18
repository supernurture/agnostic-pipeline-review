#!/usr/bin/env node
// Merge SARIF from several scanners into a single severity-ranked report.
//
// Severity follows existing standards rather than a home-grown scale:
// SARIF 2.1.0 for the format, and properties.security-severity (a CVSS score)
// for the Critical/High/Medium/Low/Info bands.
//
// Usage: node scripts/report.mjs reports/ --fail-on high --expect a.sarif,b.sarif

import { existsSync, readFileSync, readdirSync, appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

// Fallback for SARIF that carries no security-severity at all. Only add an
// entry here when the new scanner genuinely isn't security-aware.
const TOOL_FALLBACK = {
  // A leaked live credential is critical; gitleaks does not assign a score.
  gitleaks: () => "Critical",
  semgrep: (level) => pick({ error: "High", warning: "Medium" }, level, "Info"),
  trivy: () => "High",
};

const LEVEL_FALLBACK = { error: "High", warning: "Medium", note: "Info", none: "Info" };

// Tools that normally do carry security-severity. When one of them stops, every
// band it produces shifts to TOOL_FALLBACK and the gate changes without any
// error — so the report says it out loud. Gitleaks is absent on purpose: it
// never scores, and its fallback is the intended behaviour.
const EXPECT_SCORE = ["trivy", "semgrep"];

// Keys come from a SARIF file, so never index the map bare: a level of
// "constructor" would return a function instead of the default.
function pick(map, key, dflt) {
  return Object.hasOwn(map, key) ? map[key] : dflt;
}

/** CVSS score -> band, following the GitHub code scanning split. */
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
  // ruleIndex points into driver.rules, not into the merge with extensions.
  const i = result.ruleIndex;
  if (Number.isInteger(i) && i >= 0 && i < ctx.driverRules.length) return ctx.driverRules[i];
  return null;
}

/** Whether a CVSS score was available at all — on the result or on its rule. */
function hasScore(result, ctx) {
  if (Number.isFinite(score(result.properties))) return true;
  const rule = findRule(result, ctx);
  return Boolean(rule) && Number.isFinite(score(rule.properties));
}

/** Resolution order: result -> rule -> per-tool fallback -> SARIF level. */
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

/** Some results legitimately have no location — null, not a placeholder. */
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
  // Flatten to one line so the markdown list does not break.
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > 300 ? `${flat.slice(0, 297)}...` : flat;
}

export function collect(dir) {
  // ponytail: no cross-tool dedup. Gitleaks and Semgrep can flag the same
  // secret twice. Add a (location, normalized message) key if the duplicates
  // start getting in the way.
  const findings = [];
  const problems = [];
  const notes = [];
  const files = existsSync(dir)
    ? readdirSync(dir).filter((f) => f.endsWith(".sarif")).sort()
    : [];

  for (const file of files) {
    let doc;
    try {
      doc = JSON.parse(readFileSync(join(dir, file), "utf8"));
    } catch (err) {
      problems.push(`\`${file}\` could not be read: ${err.message}`);
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
      const results = run.results ?? [];
      let scored = 0;
      for (const result of results) {
        if (hasScore(result, ctx)) scored += 1;
        findings.push({
          severity: severity(result, ctx),
          tool: ctx.tool,
          rule: result.ruleId ?? "—",
          location: location(result),
          message: message(result),
        });
      }
      const name = String(ctx.tool).toLowerCase();
      if (results.length && !scored && EXPECT_SCORE.some((k) => name.includes(k))) {
        notes.push(
          `\`${ctx.tool}\` emitted no \`security-severity\` — its bands came from the fallback table, not from CVSS.`,
        );
      }
    }
  }
  return { findings, problems, notes };
}

/** An enabled scanner that left no report is a failure, not a pass. */
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

// The GitHub Job Summary is capped at 1 MiB — truncate the list ourselves so
// GitHub does not cut the report off mid-way.
const MAX_PER_BAND = 50;

export function render({ findings, problems, notes, commitLog, failOn, missing }) {
  const c = counts(findings);
  const out = ["## Review Report", ""];

  if (missing.length) {
    out.push("> **Scanner produced no report:** " + missing.map((m) => `\`${m}\``).join(", "));
    out.push("> The results below are incomplete.", "");
  }
  for (const p of problems) out.push(`> ${p}`, "");
  for (const n of notes) out.push(`> ${n}`, "");

  out.push("| Severity | Count |", "|---|---:|");
  for (const s of SEVERITIES) out.push(`| ${s} | ${c[s]} |`);
  out.push(`| **Total** | **${findings.length}** |`, "");
  out.push(
    failOn === "none"
      ? "Gate: no severity fails the build."
      : `Gate: fails at **${failOn}** and above.`,
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
      out.push(`- _...and ${items.length - MAX_PER_BAND} more ${s} findings._`);
    }
    out.push("");
  }

  if (commitLog !== null) {
    out.push("### Commit Message", "");
    // Commit style is not a security finding, so it stays off the CVSS scale.
    out.push(commitLog ? "```\n" + commitLog + "\n```" : "All commit messages passed.", "");
  }

  if (!findings.length && !missing.length && !problems.length) {
    out.push("No findings.", "");
  }
  return out.join("\n");
}

function normalizeFailOn(raw) {
  const value = String(raw).trim().toLowerCase();
  if (value === "none") return "none";
  const match = SEVERITIES.find((s) => s.toLowerCase() === value);
  if (!match) {
    throw new Error(`unknown --fail-on: ${raw} (choices: ${SEVERITIES.join(", ").toLowerCase()}, none)`);
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

  const { findings, problems, notes } = collect(dir);
  const missing = missingReports(dir, expected);
  const commitPath = join(dir, "commit.txt");
  const commitLog = existsSync(commitPath) ? readFileSync(commitPath, "utf8").trim() : null;

  const markdown = render({ findings, problems, notes, commitLog, failOn, missing });
  process.stdout.write(markdown + "\n");
  // Also written as a file so the report can be uploaded as an artifact and
  // handed to a teammate or a tool — the Job Summary alone cannot be exported.
  if (existsSync(dir)) writeFileSync(join(dir, "review-report.md"), markdown + "\n");
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + "\n");
  }

  // A scanner that failed to run is an infrastructure error, not "no findings",
  // so it fails the build even under --fail-on none.
  if (missing.length || problems.length) return 1;
  if (commitLog) return 1;
  return gate(findings, failOn) ? 1 : 0;
}

// pathToFileURL, not `file://${argv[1]}`: the latter never matches on Windows
// and is wrong for paths containing spaces.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (err) {
    console.error(err.message);
    process.exit(2);
  }
}
