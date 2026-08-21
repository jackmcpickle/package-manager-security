export type ConfigSourceKind = "user" | "scan" | "repo";

export interface ConfigSource {
  kind: ConfigSourceKind;
  path: string;
}

const SEARCH_ORDER =
  "Looks for a user/tool config, then .mailclad.toml in the scan directory and each project. Closer wins; flags win over files.";

const padEnd = (text: string, width: number): string =>
  text.length >= width ? text : `${text}${" ".repeat(width - text.length)}`;

const colWidth = (cells: readonly string[]): number => {
  let width = 0;
  for (const cell of cells) {
    if (cell.length > width) {
      width = cell.length;
    }
  }
  return width;
};

export const formatConfigSources = (
  sources: readonly ConfigSource[],
  readFile: (filePath: string) => string | null
): string => {
  const kindWidth = colWidth(sources.map((source) => source.kind));
  const pathWidth = colWidth(sources.map((source) => source.path));
  const rows = sources.map((source) => {
    const status = readFile(source.path) === null ? "missing" : "found";
    return `  ${padEnd(source.kind, kindWidth)}  ${padEnd(source.path, pathWidth)}  ${status}`;
  });
  return ["Configuration:", `  ${SEARCH_ORDER}`, "", ...rows, ""].join("\n");
};
