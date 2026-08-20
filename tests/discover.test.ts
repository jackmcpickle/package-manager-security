import { expect, test } from "bun:test";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { discoverProjects } from "../src/discover";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";

const FIX = join(import.meta.dir, "fixtures/discover");

for (const rel of [
  "many-repos/alpha",
  "many-repos/beta",
  "monorepo",
  "nested-npmrc",
  "poetry-app",
]) {
  mkdirSync(join(FIX, rel, ".git"), { recursive: true });
}

test("a folder of git repos yields one project per repo", () => {
  const projects = discoverProjects(join(FIX, "many-repos"));
  const roots = projects.map((p) => p.root.split("/").at(-1)).sort();
  expect(roots).toEqual(["alpha", "beta"]);
});

test("leftover package-lock beside pnpm is leftover npm not a second apply target", () => {
  const beta = discoverProjects(join(FIX, "many-repos")).find((p) => p.root.endsWith("beta"));
  expect(beta?.managers.some((m) => m.name === "pnpm" && m.role === "primary")).toBe(true);
  expect(beta?.managers.some((m) => m.name === "npm" && m.role === "leftover")).toBe(true);
});

test("monorepo workspace packages without their own config are not separate projects", () => {
  const projects = discoverProjects(join(FIX, "monorepo"));
  expect(projects).toHaveLength(1);
  expect(projects[0]?.managers.some((m) => m.name === "pnpm" && m.role === "primary")).toBe(true);
});

test("nested package with its own .npmrc is a separate PM root", () => {
  const projects = discoverProjects(join(FIX, "nested-npmrc"));
  expect(projects).toHaveLength(2);
  const names = projects.map((p) => p.root.split("/").at(-1)).sort();
  expect(names).toEqual(["app", "nested-npmrc"]);
  const app = projects.find((p) => p.root.endsWith("app"));
  expect(app?.gitRoot?.endsWith("nested-npmrc")).toBe(true);
  expect(app?.managers.some((m) => m.name === "npm" && m.role === "primary")).toBe(true);
});

test("yarn berry is primary and yarn classic is unsupported", () => {
  const berry = discoverProjects(
    "/berry",
    memoryFs(
      {
        "/berry/package.json": `{"name":"berry","packageManager":"yarn@4.5.0"}`,
        "/berry/yarn.lock": "# yarn\n",
        "/berry/.yarnrc.yml": "nodeLinker: node-modules\n",
      },
      ["/berry/.git"],
    ),
  );
  expect(berry).toHaveLength(1);
  expect(berry[0]?.managers).toEqual([
    {
      name: "yarn",
      role: "primary",
      manifestPath: "/berry/package.json",
      lockfilePath: "/berry/yarn.lock",
      configPath: "/berry/.yarnrc.yml",
    },
  ]);

  const classic = discoverProjects(
    "/classic",
    memoryFs(
      {
        "/classic/package.json": `{"name":"classic"}`,
        "/classic/yarn.lock": "# yarn lockfile v1\n",
      },
      ["/classic/.git"],
    ),
  );
  expect(classic[0]?.managers.some((m) => m.name === "yarn" && m.role === "unsupported")).toBe(
    true,
  );
});

test("bun and uv markers are primary managers", () => {
  const bun = discoverProjects(
    "/bun",
    memoryFs({
      "/bun/package.json": `{"name":"bun-app"}`,
      "/bun/bun.lock": "x\n",
      "/bun/bunfig.toml": "[install]\n",
    }),
  );
  expect(bun[0]?.gitRoot).toBeNull();
  expect(bun[0]?.managers.some((m) => m.name === "bun" && m.role === "primary")).toBe(true);

  const uv = discoverProjects(
    "/uv",
    memoryFs({
      "/uv/pyproject.toml": "[project]\nname = \"uv-app\"\n[tool.uv]\n",
      "/uv/uv.lock": "x\n",
    }),
  );
  expect(uv[0]?.managers.some((m) => m.name === "uv" && m.role === "primary")).toBe(true);
});

test("a .git file marks a worktree as a git root", () => {
  const projects = discoverProjects(
    "/many",
    memoryFs({
      "/many/alpha/.git": "gitdir: /original/.git/worktrees/alpha\n",
      "/many/alpha/package.json": `{"name":"alpha"}`,
      "/many/alpha/package-lock.json": `{"lockfileVersion":3}`,
      "/many/beta/.git": "gitdir: /original/.git/worktrees/beta\n",
      "/many/beta/package.json": `{"name":"beta"}`,
      "/many/beta/package-lock.json": `{"lockfileVersion":3}`,
    }),
  );
  const roots = projects.map((p) => p.root.split("/").at(-1)).sort();
  expect(roots).toEqual(["alpha", "beta"]);
  expect(projects.every((p) => p.gitRoot === p.root)).toBe(true);
});

test("yarnrc without yarn.lock is not yarn and does not hide npm", () => {
  const projects = discoverProjects(
    "/proj",
    memoryFs({
      "/proj/package.json": `{"name":"proj"}`,
      "/proj/.yarnrc.yml": "nodeLinker: node-modules\n",
    }),
  );
  expect(projects[0]?.managers.some((m) => m.name === "yarn")).toBe(false);
  expect(projects[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")).toBe(true);
});

test("standalone uv.toml is not a uv primary", () => {
  const projects = discoverProjects(
    "/only-uvtoml",
    memoryFs({
      "/only-uvtoml/uv.toml": "prerelease = \"if-necessary\"\n",
    }),
  );
  expect(projects.some((p) => p.managers.some((m) => m.name === "uv"))).toBe(false);
});

test("poetry project is detected and flagged as not using uv", () => {
  const projects = discoverProjects(join(FIX, "poetry-app"));
  expect(projects[0]?.managers.some((m) => m.name === "poetry" && m.role === "primary")).toBe(true);
  const findings = auditSettings(projects[0]!, loadPolicy({}), {
    readFile: (p) => (p.endsWith("pyproject.toml") ? `[tool.poetry]\nname = "x"\n` : null),
  });
  expect(findings.some((f) => f.code === "python.not-uv")).toBe(true);
});

test("nested poetry.lock is a separate PM root", () => {
  const projects = discoverProjects(
    "/mono",
    memoryFs(
      {
        "/mono/package.json": `{"name":"mono"}`,
        "/mono/package-lock.json": `{"lockfileVersion":3}`,
        "/mono/services/api/pyproject.toml": `[tool.poetry]\nname = "api"\n`,
        "/mono/services/api/poetry.lock": "# poetry\n",
      },
      ["/mono/.git"],
    ),
  );
  const api = projects.find((p) => p.root.endsWith("api"));
  expect(api?.gitRoot?.endsWith("mono")).toBe(true);
  expect(api?.managers.some((m) => m.name === "poetry" && m.role === "primary")).toBe(true);
});

test("pipenv stays primary when uv is also present", () => {
  const projects = discoverProjects(
    "/both",
    memoryFs({
      "/both/pyproject.toml": "[project]\nname = \"x\"\n[tool.uv]\n",
      "/both/uv.lock": "x\n",
      "/both/Pipfile": "[packages]\n",
      "/both/Pipfile.lock": "{}\n",
    }),
  );
  expect(projects[0]?.managers.some((m) => m.name === "uv" && m.role === "primary")).toBe(true);
  expect(projects[0]?.managers.some((m) => m.name === "pipenv" && m.role === "primary")).toBe(true);
});

test("commented [tool.poetry] is not poetry", () => {
  const projects = discoverProjects(
    "/commented",
    memoryFs({
      "/commented/pyproject.toml": "# [tool.poetry]\n# [project]\nname = \"x\"\n",
    }),
  );
  expect(projects.some((p) => p.managers.some((m) => m.name === "poetry"))).toBe(false);
  expect(projects.some((p) => p.managers.some((m) => m.name === "pip"))).toBe(false);
});

test("scalar project key is not pip", () => {
  const projects = discoverProjects(
    "/scalar-project",
    memoryFs({
      "/scalar-project/pyproject.toml": `project = "x"\n`,
    }),
  );
  expect(projects.some((p) => p.managers.some((m) => m.name === "pip"))).toBe(false);
});

test("scalar tool.poetry key is not poetry", () => {
  const projects = discoverProjects(
    "/scalar-poetry",
    memoryFs({
      "/scalar-poetry/pyproject.toml": `[tool]\npoetry = "x"\n`,
    }),
  );
  expect(projects.some((p) => p.managers.some((m) => m.name === "poetry"))).toBe(false);
});

test("TOML date scalar tool.poetry is not poetry", () => {
  const projects = discoverProjects(
    "/date-poetry",
    memoryFs({
      "/date-poetry/pyproject.toml": `[tool]\npoetry = 1979-05-27T07:32:00Z\n`,
    }),
  );
  expect(projects.some((p) => p.managers.some((m) => m.name === "poetry"))).toBe(false);
});

test("skip directories are not walked for repos or PM roots", () => {
  const projects = discoverProjects(
    "/root",
    memoryFs(
      {
        "/root/package.json": `{"name":"root"}`,
        "/root/package-lock.json": `{"lockfileVersion":3}`,
        "/root/node_modules/evil/package.json": `{"name":"evil"}`,
        "/root/node_modules/evil/.npmrc": "registry=https://example.com/\n",
        "/root/dist/app/package.json": `{"name":"dist-app"}`,
        "/root/dist/app/.npmrc": "registry=https://example.com/\n",
      },
      ["/root/.git", "/root/node_modules/evil/.git"],
    ),
  );
  expect(projects.map((p) => p.root)).toEqual(["/root"]);
});

function memoryFs(
  files: Record<string, string>,
  extraDirs: string[] = [],
): {
  readDir: (dir: string) => string[];
  readFile: (path: string) => string | null;
  isDir: (path: string) => boolean;
} {
  const dirs = new Set<string>(["/", ...extraDirs]);
  const addDir = (dir: string) => {
    let current = dir;
    while (current && current !== "/") {
      dirs.add(current);
      current = dirname(current);
    }
  };
  for (const file of Object.keys(files)) addDir(dirname(file));
  for (const dir of extraDirs) addDir(dir);

  return {
    readDir(dir: string): string[] {
      const prefix = dir.endsWith("/") ? dir : `${dir}/`;
      const names = new Set<string>();
      for (const path of [...dirs, ...Object.keys(files)]) {
        if (!path.startsWith(prefix)) continue;
        const name = path.slice(prefix.length).split("/")[0];
        if (name) names.add(name);
      }
      return [...names];
    },
    readFile(path: string): string | null {
      return files[path] ?? null;
    },
    isDir(path: string): boolean {
      return dirs.has(path);
    },
  };
}
