#!/usr/bin/env node
// Turn a jscpd JSON report into SARIF, so clone detection can join the review
// like everything else. No linter detects duplication, and no free duplication
// tool emits SARIF — this is the whole bridge, and it is deliberately small.
//
// Usage:
//   jscpd --reporters json --output .jscpd .
//   node scripts/jscpd-to-sarif.mjs .jscpd/jscpd-report.json > duplication.sarif
//
// Then hand duplication.sarif to the action's `extra-sarif` input.
//
// Run it from the repository root scanning `.`: jscpd reports paths relative
// to whatever it was told to scan, so `jscpd src` yields `a.js` where the rest
// of the pipeline — `scope: changed` above all — expects `src/a.js`.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const RULE_ID = "duplication";

/** jscpd has changed this shape between versions; take whichever it gives. */
function region(side) {
  const start = side?.startLoc?.line ?? side?.start;
  const end = side?.endLoc?.line ?? side?.end;
  if (!Number.isInteger(start) || start < 1) return null;
  // endLine is only valid when it does not precede startLine.
  return Number.isInteger(end) && end >= start ? { startLine: start, endLine: end } : { startLine: start };
}

/** SARIF wants a URI, and on Windows jscpd hands back `src\a.js`. Left alone it
 *  also never matches `git diff --name-only`, which always uses forward slashes
 *  — the finding would then be scoped away without a word. */
function uriOf(name) {
  return typeof name === "string" ? name.replace(/\\/g, "/") : undefined;
}

function place(side) {
  const uri = uriOf(side?.name);
  if (!uri) return null;
  const reg = region(side);
  return { physicalLocation: { artifactLocation: { uri }, ...(reg ? { region: reg } : {}) } };
}

function describe(dup, second) {
  const lines = Number.isFinite(dup.lines) ? `${dup.lines} duplicated lines` : "Duplicated code";
  if (!second?.name) return lines;
  const at = region(second)?.startLine;
  return `${lines}, also at ${uriOf(second.name)}${at ? `:${at}` : ""}`;
}

export function toSarif(report) {
  const duplicates = Array.isArray(report?.duplicates) ? report.duplicates : [];
  const results = [];

  for (const dup of duplicates) {
    // The first side is the primary location; without it there is nothing to
    // point at, and a finding with no location helps no one.
    const first = place(dup?.firstFile);
    if (!first) continue;
    const second = place(dup?.secondFile);
    results.push({
      ruleId: RULE_ID,
      // `note`, not `warning`: duplication is a smell, not a defect. This SARIF
      // is meant for the coding standard section, which is off the CVSS scale
      // — but if someone feeds it in as a normal scanner report instead, `note`
      // lands it in Info rather than inventing a severity for it.
      level: "note",
      message: { text: describe(dup ?? {}, dup?.secondFile) },
      locations: [first],
      ...(second ? { relatedLocations: [second] } : {}),
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "jscpd",
          informationUri: "https://github.com/kucherenko/jscpd",
          rules: [{
            id: RULE_ID,
            shortDescription: { text: "Duplicated code" },
            help: { text: "The same fragment appears in more than one place." },
          }],
        },
      },
      results,
    }],
  };
}

function main(argv) {
  const path = argv[0];
  if (!path) throw new Error("usage: jscpd-to-sarif.mjs <jscpd-report.json>");
  let report;
  try {
    report = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`${path} could not be read: ${err.message}`);
  }
  process.stdout.write(JSON.stringify(toSarif(report), null, 2) + "\n");
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    process.exitCode = 2;
  }
}
