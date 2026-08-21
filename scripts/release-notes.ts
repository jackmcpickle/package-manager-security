import { readFileSync } from "node:fs";
import path from "node:path";

const escapeRegExp = (value: string): string =>
  value.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&");

export const extractChangelogNotes = (
  changelog: string,
  version: string
): string | null => {
  const header = new RegExp(
    `^## (?:\\[${escapeRegExp(version)}\\]|${escapeRegExp(version)})(?:[\\s(\\[]|$)`,
    "u"
  );
  const body: string[] = [];
  let collecting = false;

  for (const line of changelog.split(/\r?\n/u)) {
    if (collecting) {
      if (line.startsWith("## ")) {
        break;
      }
      body.push(line);
      continue;
    }
    if (header.test(line)) {
      collecting = true;
    }
  }

  if (!collecting) {
    return null;
  }
  const notes = body.join("\n").trim();
  return notes === "" ? null : notes;
};

const isMain = import.meta.main === true;
if (isMain) {
  const version = process.argv[2]?.replace(/^v/u, "");
  if (version === undefined || version === "") {
    process.stderr.write("usage: bun scripts/release-notes.ts <version>\n");
    process.exit(1);
  }
  const changelogPath =
    process.argv[3] ?? path.join(import.meta.dir, "..", "CHANGELOG.md");
  const notes = extractChangelogNotes(
    readFileSync(changelogPath, "utf-8"),
    version
  );
  if (notes === null) {
    process.exit(2);
  }
  process.stdout.write(`${notes}\n`);
}
