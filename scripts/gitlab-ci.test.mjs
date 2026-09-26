#!/usr/bin/env node
// Self-check for presets/gitlab-ci.yml. Run with: node scripts/gitlab-ci.test.mjs
//
// Text, not YAML: the template uses GitLab's !reference tag, which no stdlib
// parser reads, and a dependency for this would cost more than it catches.
// What it catches is the drift a reader would miss — a variable that is used
// but never declared, and a scanner that reached only one of the two lanes.

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");
const gitlab = read("presets/gitlab-ci.yml");
const action = read("action.yml");
const steps = read("scripts/steps.sh");

let fails = 0;
function check(label, ok, detail = "") {
  if (ok) return;
  console.log(`FAIL ${label}${detail ? `\n  ${detail}` : ""}`);
  fails++;
}

// --- variables ---
const declared = new Set();
let inVars = false;
for (const line of gitlab.split("\n")) {
  if (line.startsWith("variables:")) { inVars = true; continue; }
  if (inVars && /^\S/.test(line)) break;
  const m = inVars && line.match(/^ {2}([A-Z][A-Z0-9_]*):/);
  if (m) declared.add(m[1]);
}
check("the variables block is readable", declared.size > 5, `found ${declared.size}`);

// Names the scripts set themselves — steps.sh reads SCOPE, EXTRA, BASE and so on.
const assigned = new Set([...gitlab.matchAll(/(?:^|\s)(?:export )?([A-Z][A-Z0-9_]*)=/gm)].map((m) => m[1]));
// REVIEW_TOKEN is deliberately undeclared: unset means "post no note".
const supplied = (name) => name.startsWith("CI_") || name === "REVIEW_TOKEN" || assigned.has(name);
const used = new Set([...gitlab.matchAll(/\$\{?([A-Z][A-Z0-9_]*)/g)].map((m) => m[1]));
for (const name of used) {
  check(`$${name} is declared or set by the job`, declared.has(name) || supplied(name));
}
for (const name of declared) {
  check(`${name} is actually used`, used.has(name));
}

// --- both lanes run the same scanners ---
// The filenames expected_reports demands, which is what the gate checks for.
const fn = steps.slice(steps.indexOf("expected_reports()"));
const expected = [...new Set([...fn.matchAll(/([a-z]+\.sarif)/g)].map((m) => m[1]))];
check("expected_reports names some SARIF", expected.length > 0, expected.join(","));
for (const name of expected) {
  check(`${name} is written on the GitLab lane`, gitlab.includes(name));
  check(`${name} is written on the Actions lane`, action.includes(name));
}

// --- pinned versions match ---
// Dependabot reaches neither file's pin, so this is the only thing keeping them in step.
for (const [input, variable] of [["semgrep-version", "REVIEW_SEMGREP_IMAGE"],
                                 ["gitleaks-version", "REVIEW_GITLEAKS_IMAGE"]]) {
  const want = action.match(new RegExp(`${input}:[\\s\\S]*?default: "([^"]+)"`))?.[1];
  const tag = gitlab.match(new RegExp(`${variable}: \\S+:v?(\\S+)`))?.[1];
  check(`${variable} matches the ${input} default`, want && want === tag, `${tag} vs ${want}`);
}

// --- jobs ---
// One top-level block, so an assertion cannot leak into the job below it.
const lines = gitlab.split("\n");
function block(name) {
  const start = lines.indexOf(`${name}:`);
  if (start < 0) return "";
  let end = start + 1;
  while (end < lines.length && (lines[end] === "" || /^\s/.test(lines[end]))) end++;
  return lines.slice(start, end).join("\n");
}
const scanners = ["review:code", "review:trivy", "review:gitleaks", "review:commit-message"];
for (const job of [...scanners, "review:report"]) {
  check(`${job} exists`, block(job) !== "");
}
// The report has to run after a scanner died, or a broken pipeline goes green.
const report = block("review:report");
// .post runs after deploy, so a gate there could not hold a deploy back.
check("the report job gates the stages after test", report.includes("stage: test"));
for (const job of scanners) {
  check(`the report job waits for ${job}`,
    report.includes(`{ job: "${job}", optional: true }`));
}
// Its own rules, not the `when: always` further down under artifacts.
const rules = report.slice(report.indexOf("rules:"), report.indexOf("artifacts:"));
check("the report job runs even after a failed scanner",
  report.includes("rules:") && rules.includes("when: always"));
// Whatever the scanners produce has to survive a failed job to reach it.
check("scanner artifacts are kept on failure", block(".review-job").includes("when: always"));

console.log(fails === 0 ? "gitlab-ci.yml: all checks passed" : `gitlab-ci.yml: ${fails} check(s) failed`);
process.exitCode = fails === 0 ? 0 : 1;
