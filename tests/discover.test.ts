import { expect, test } from "bun:test";
import { mkdirSync } from "node:fs";
import path from "node:path";

import { discoverProjects } from "../src/discover";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";
import { memoryFs } from "./helpers/memory-fs";

const FIX = path.join(import.meta.dir, "fixtures/discover");

for (const rel of [
  "many-repos/alpha",
  "many-repos/beta",
  "monorepo",
  "nested-npmrc",
  "poetry-app",
]) {
  mkdirSync(path.join(FIX, rel, ".git"), { recursive: true });
}

test("a folder of git repos yields one project per repo", () => {
  const projects = discoverProjects(path.join(FIX, "many-repos"));
  const roots = projects.map((p) => p.root.split("/").at(-1)).toSorted();
  expect(roots).toEqual(["alpha", "beta"]);
});

test("leftover package-lock beside pnpm is leftover npm not a second apply target", () => {
  const beta = discoverProjects(path.join(FIX, "many-repos")).find((p) =>
    p.root.endsWith("beta")
  );
  expect(
    beta?.managers.some((m) => m.name === "pnpm" && m.role === "primary")
  ).toBe(true);
  expect(
    beta?.managers.some((m) => m.name === "npm" && m.role === "leftover")
  ).toBe(true);
});

test("monorepo workspace packages without their own config are not separate projects", () => {
  const projects = discoverProjects(path.join(FIX, "monorepo"));
  expect(projects).toHaveLength(1);
  expect(
    projects[0]?.managers.some((m) => m.name === "pnpm" && m.role === "primary")
  ).toBe(true);
});

test("nested package with its own .npmrc is a separate PM root", () => {
  const projects = discoverProjects(path.join(FIX, "nested-npmrc"));
  expect(projects).toHaveLength(2);
  const names = projects.map((p) => p.root.split("/").at(-1)).toSorted();
  expect(names).toEqual(["app", "nested-npmrc"]);
  const app = projects.find((p) => p.root.endsWith("app"));
  expect(app?.gitRoot?.endsWith("nested-npmrc")).toBe(true);
  expect(
    app?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
});

test("yarn berry is primary and yarn classic is unsupported", () => {
  const berry = discoverProjects(
    "/berry",
    memoryFs(
      {
        "/berry/.yarnrc.yml": "nodeLinker: node-modules\n",
        "/berry/package.json": `{"name":"berry","packageManager":"yarn@4.5.0"}`,
        "/berry/yarn.lock": "# yarn\n",
      },
      ["/berry/.git"]
    )
  );
  expect(berry).toHaveLength(1);
  expect(berry[0]?.managers).toEqual([
    {
      configPath: "/berry/.yarnrc.yml",
      lockfilePath: "/berry/yarn.lock",
      manifestPath: "/berry/package.json",
      name: "yarn",
      role: "primary",
    },
  ]);

  const classic = discoverProjects(
    "/classic",
    memoryFs(
      {
        "/classic/package.json": `{"name":"classic"}`,
        "/classic/yarn.lock": "# yarn lockfile v1\n",
      },
      ["/classic/.git"]
    )
  );
  expect(
    classic[0]?.managers.some(
      (m) => m.name === "yarn" && m.role === "unsupported"
    )
  ).toBe(true);
});

test("cargo.toml is a primary cargo manager and coexists with npm", () => {
  const both = discoverProjects(
    "/app",
    memoryFs({
      "/app/Cargo.lock": "# cargo\n",
      "/app/Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n',
      "/app/package-lock.json": `{"lockfileVersion":3}`,
      "/app/package.json": `{"name":"app","packageManager":"npm@10.9.0"}`,
    })
  );
  expect(
    both[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
  expect(
    both[0]?.managers.some((m) => m.name === "cargo" && m.role === "primary")
  ).toBe(true);
  const cargo = both[0]?.managers.find((m) => m.name === "cargo");
  expect(cargo).toEqual({
    configPath: "/app/.cargo/config.toml",
    lockfilePath: "/app/Cargo.lock",
    manifestPath: "/app/Cargo.toml",
    name: "cargo",
    role: "primary",
  });
});

test("cargo uses .cargo/config when config.toml is absent", () => {
  const projects = discoverProjects(
    "/rust",
    memoryFs({
      "/rust/.cargo/config": '[install]\nminimum-release-age = "1d"\n',
      "/rust/Cargo.lock": "# cargo\n",
      "/rust/Cargo.toml": '[package]\nname = "rust"\nversion = "0.1.0"\n',
    })
  );
  const cargo = projects[0]?.managers.find((m) => m.name === "cargo");
  expect(cargo?.configPath).toBe("/rust/.cargo/config");
});

test("stray Cargo.lock beside npm without Cargo.toml is leftover cargo", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/Cargo.lock": "# cargo\n",
      "/app/package-lock.json": `{"lockfileVersion":3}`,
      "/app/package.json": `{"name":"app","packageManager":"npm@10.9.0"}`,
    })
  );
  expect(
    projects[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "cargo" && m.role === "leftover"
    )
  ).toBe(true);
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "cargo" && m.role === "primary"
    )
  ).toBe(false);
});

test("bun and uv markers are primary managers", () => {
  const bun = discoverProjects(
    "/bun",
    memoryFs({
      "/bun/bun.lock": "x\n",
      "/bun/bunfig.toml": "[install]\n",
      "/bun/package.json": `{"name":"bun-app"}`,
    })
  );
  expect(bun[0]?.gitRoot).toBeNull();
  expect(
    bun[0]?.managers.some((m) => m.name === "bun" && m.role === "primary")
  ).toBe(true);

  const uv = discoverProjects(
    "/uv",
    memoryFs({
      "/uv/pyproject.toml": '[project]\nname = "uv-app"\n[tool.uv]\n',
      "/uv/uv.lock": "x\n",
    })
  );
  expect(
    uv[0]?.managers.some((m) => m.name === "uv" && m.role === "primary")
  ).toBe(true);
});

test("a .git file marks a worktree as a git root", () => {
  const projects = discoverProjects(
    "/many",
    memoryFs({
      "/many/alpha/.git": "gitdir: /original/.git/worktrees/alpha\n",
      "/many/alpha/package-lock.json": `{"lockfileVersion":3}`,
      "/many/alpha/package.json": `{"name":"alpha"}`,
      "/many/beta/.git": "gitdir: /original/.git/worktrees/beta\n",
      "/many/beta/package-lock.json": `{"lockfileVersion":3}`,
      "/many/beta/package.json": `{"name":"beta"}`,
    })
  );
  const roots = projects.map((p) => p.root.split("/").at(-1)).toSorted();
  expect(roots).toEqual(["alpha", "beta"]);
  expect(projects.every((p) => p.gitRoot === p.root)).toBe(true);
});

test("yarnrc without yarn.lock is not yarn and does not hide npm", () => {
  const projects = discoverProjects(
    "/proj",
    memoryFs({
      "/proj/.yarnrc.yml": "nodeLinker: node-modules\n",
      "/proj/package.json": `{"name":"proj"}`,
    })
  );
  expect(projects[0]?.managers.some((m) => m.name === "yarn")).toBe(false);
  expect(
    projects[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
});

test("standalone uv.toml is not a uv primary", () => {
  const projects = discoverProjects(
    "/only-uvtoml",
    memoryFs({
      "/only-uvtoml/uv.toml": 'prerelease = "if-necessary"\n',
    })
  );
  expect(projects.some((p) => p.managers.some((m) => m.name === "uv"))).toBe(
    false
  );
});

test("poetry project is detected and flagged as not using uv", () => {
  const projects = discoverProjects(path.join(FIX, "poetry-app"));
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "poetry" && m.role === "primary"
    )
  ).toBe(true);
  const [poetry] = projects;
  if (poetry === undefined) {
    throw new Error("expected poetry project");
  }
  const findings = auditSettings(poetry, loadPolicy({}), {
    readFile: (p) =>
      p.endsWith("pyproject.toml") ? `[tool.poetry]\nname = "x"\n` : null,
  });
  expect(findings.some((f) => f.code === "python.not-uv")).toBe(true);
});

test("nested poetry.lock is a separate PM root", () => {
  const projects = discoverProjects(
    "/mono",
    memoryFs(
      {
        "/mono/package-lock.json": `{"lockfileVersion":3}`,
        "/mono/package.json": `{"name":"mono"}`,
        "/mono/services/api/poetry.lock": "# poetry\n",
        "/mono/services/api/pyproject.toml": `[tool.poetry]\nname = "api"\n`,
      },
      ["/mono/.git"]
    )
  );
  const api = projects.find((p) => p.root.endsWith("api"));
  expect(api?.gitRoot?.endsWith("mono")).toBe(true);
  expect(
    api?.managers.some((m) => m.name === "poetry" && m.role === "primary")
  ).toBe(true);
});

test("pipenv stays primary when uv is also present", () => {
  const projects = discoverProjects(
    "/both",
    memoryFs({
      "/both/Pipfile": "[packages]\n",
      "/both/Pipfile.lock": "{}\n",
      "/both/pyproject.toml": '[project]\nname = "x"\n[tool.uv]\n',
      "/both/uv.lock": "x\n",
    })
  );
  expect(
    projects[0]?.managers.some((m) => m.name === "uv" && m.role === "primary")
  ).toBe(true);
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "pipenv" && m.role === "primary"
    )
  ).toBe(true);
});

test("commented [tool.poetry] is not poetry", () => {
  const projects = discoverProjects(
    "/commented",
    memoryFs({
      "/commented/pyproject.toml": '# [tool.poetry]\n# [project]\nname = "x"\n',
    })
  );
  expect(
    projects.some((p) => p.managers.some((m) => m.name === "poetry"))
  ).toBe(false);
  expect(projects.some((p) => p.managers.some((m) => m.name === "pip"))).toBe(
    false
  );
});

test("scalar project key is not pip", () => {
  const projects = discoverProjects(
    "/scalar-project",
    memoryFs({
      "/scalar-project/pyproject.toml": `project = "x"\n`,
    })
  );
  expect(projects.some((p) => p.managers.some((m) => m.name === "pip"))).toBe(
    false
  );
});

test("scalar tool.poetry key is not poetry", () => {
  const projects = discoverProjects(
    "/scalar-poetry",
    memoryFs({
      "/scalar-poetry/pyproject.toml": `[tool]\npoetry = "x"\n`,
    })
  );
  expect(
    projects.some((p) => p.managers.some((m) => m.name === "poetry"))
  ).toBe(false);
});

test("TOML date scalar tool.poetry is not poetry", () => {
  const projects = discoverProjects(
    "/date-poetry",
    memoryFs({
      "/date-poetry/pyproject.toml": `[tool]\npoetry = 1979-05-27T07:32:00Z\n`,
    })
  );
  expect(
    projects.some((p) => p.managers.some((m) => m.name === "poetry"))
  ).toBe(false);
});

test("a lone un-git’d tree with package.json and lockfile is one project", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/package-lock.json": `{"lockfileVersion":3}`,
      "/app/package.json": `{"name":"app"}`,
    })
  );
  expect(projects).toHaveLength(1);
  expect(projects[0]?.root).toBe("/app");
  expect(projects[0]?.gitRoot).toBeNull();
  expect(
    projects[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
});

test("requirements.txt without uv is a pip primary", () => {
  const projects = discoverProjects(
    "/reqs",
    memoryFs({
      "/reqs/requirements.txt": "requests==2.0.0\n",
    })
  );
  expect(projects[0]?.managers).toEqual([
    expect.objectContaining({
      manifestPath: "/reqs/requirements.txt",
      name: "pip",
      role: "primary",
    }),
  ]);
});

test("requirements-dev.txt without uv is a pip primary", () => {
  const projects = discoverProjects(
    "/reqs",
    memoryFs({
      "/reqs/requirements-dev.txt": "pytest==8.0.0\n",
    })
  );
  expect(projects[0]?.managers).toEqual([
    expect.objectContaining({
      manifestPath: "/reqs/requirements-dev.txt",
      name: "pip",
      role: "primary",
    }),
  ]);
});

test("nested git repos: parent without a PM is not a project and the child repo is", () => {
  const projects = discoverProjects(
    "/workspace",
    memoryFs(
      {
        "/workspace/parent/README.md": "meta\n",
        "/workspace/parent/child/package-lock.json": `{"lockfileVersion":3}`,
        "/workspace/parent/child/package.json": `{"name":"child"}`,
      },
      ["/workspace/parent/.git", "/workspace/parent/child/.git"]
    )
  );
  expect(projects).toHaveLength(1);
  expect(projects[0]?.root).toBe("/workspace/parent/child");
  expect(projects[0]?.gitRoot).toBe("/workspace/parent/child");
});

test("pyproject [project] table without uv or poetry is pip", () => {
  const projects = discoverProjects(
    "/proj",
    memoryFs({
      "/proj/pyproject.toml": `[project]\nname = "lib"\nversion = "0.1.0"\n`,
    })
  );
  expect(
    projects[0]?.managers.some((m) => m.name === "pip" && m.role === "primary")
  ).toBe(true);
  expect(
    projects[0]?.managers.some((m) => m.name === "uv" || m.name === "poetry")
  ).toBe(false);
});

test("uv plus poetry makes poetry leftover and uv primary", () => {
  const projects = discoverProjects(
    "/both",
    memoryFs({
      "/both/poetry.lock": "# poetry\n",
      "/both/pyproject.toml": `[project]\nname = "x"\n[tool.uv]\n[tool.poetry]\nname = "x"\n`,
      "/both/uv.lock": "x\n",
    })
  );
  expect(
    projects[0]?.managers.some((m) => m.name === "uv" && m.role === "primary")
  ).toBe(true);
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "poetry" && m.role === "leftover"
    )
  ).toBe(true);
});

test("packageManager yarn@4 without .yarnrc.yml is still Berry when yarn.lock exists", () => {
  const projects = discoverProjects(
    "/berry",
    memoryFs({
      "/berry/package.json": `{"name":"berry","packageManager":"yarn@4.5.0"}`,
      "/berry/yarn.lock": "# yarn\n",
    })
  );
  expect(projects[0]?.managers).toEqual([
    expect.objectContaining({
      configPath: null,
      lockfilePath: "/berry/yarn.lock",
      name: "yarn",
      role: "primary",
    }),
  ]);
});

test("yarn.lock beside a pinned npm project is leftover yarn", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/package-lock.json": `{"lockfileVersion":3}`,
      "/app/package.json": `{"name":"app","packageManager":"npm@10.9.0"}`,
      "/app/yarn.lock": "# yarn\n",
    })
  );
  expect(
    projects[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
  expect(
    projects[0]?.managers.some(
      (m) => m.name === "yarn" && m.role === "leftover"
    )
  ).toBe(true);
});

test("bun.lock beside a pinned npm project is leftover bun", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/bun.lock": `{"lockfileVersion":1}`,
      "/app/package-lock.json": `{"lockfileVersion":3}`,
      "/app/package.json": `{"name":"app","packageManager":"npm@10.9.0"}`,
    })
  );
  expect(
    projects[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
  expect(
    projects[0]?.managers.some((m) => m.name === "bun" && m.role === "leftover")
  ).toBe(true);
});

test("stray uv.lock beside npm without a Python project is leftover uv", () => {
  const projects = discoverProjects(
    "/app",
    memoryFs({
      "/app/package-lock.json": `{"lockfileVersion":3}`,
      "/app/package.json": `{"name":"app","packageManager":"npm@10.9.0"}`,
      "/app/uv.lock": "version = 1\n",
    })
  );
  expect(
    projects[0]?.managers.some((m) => m.name === "npm" && m.role === "primary")
  ).toBe(true);
  expect(
    projects[0]?.managers.some((m) => m.name === "uv" && m.role === "leftover")
  ).toBe(true);
  expect(
    projects[0]?.managers.some((m) => m.name === "uv" && m.role === "primary")
  ).toBe(false);
});

test("skip directories are not walked for repos or PM roots", () => {
  const projects = discoverProjects(
    "/root",
    memoryFs(
      {
        "/root/dist/app/.npmrc": "registry=https://example.com/\n",
        "/root/dist/app/package.json": `{"name":"dist-app"}`,
        "/root/node_modules/evil/.npmrc": "registry=https://example.com/\n",
        "/root/node_modules/evil/package.json": `{"name":"evil"}`,
        "/root/package-lock.json": `{"lockfileVersion":3}`,
        "/root/package.json": `{"name":"root"}`,
      },
      ["/root/.git", "/root/node_modules/evil/.git"]
    )
  );
  expect(projects.map((p) => p.root)).toEqual(["/root"]);
});

test("Gemfile without lockfile is a bundler primary", () => {
  const projects = discoverProjects(
    "/ruby",
    memoryFs({
      "/ruby/Gemfile": 'source "https://rubygems.org"\n',
    })
  );
  expect(projects[0]?.managers).toEqual([
    {
      configPath: null,
      lockfilePath: null,
      manifestPath: "/ruby/Gemfile",
      name: "bundler",
      role: "primary",
    },
  ]);
});

test("Gemfile with Gemfile.lock and .bundle/config is detected", () => {
  const projects = discoverProjects(
    "/ruby",
    memoryFs({
      "/ruby/.bundle/config": '---\nBUNDLE_COOLDOWN: "1"\n',
      "/ruby/Gemfile": 'source "https://rubygems.org"\n',
      "/ruby/Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n",
    })
  );
  expect(projects[0]?.managers).toEqual([
    {
      configPath: "/ruby/.bundle/config",
      lockfilePath: "/ruby/Gemfile.lock",
      manifestPath: "/ruby/Gemfile",
      name: "bundler",
      role: "primary",
    },
  ]);
});

test("nested Gemfile is a separate PM root", () => {
  const projects = discoverProjects(
    "/mono",
    memoryFs(
      {
        "/mono/package-lock.json": `{"lockfileVersion":3}`,
        "/mono/package.json": `{"name":"mono"}`,
        "/mono/services/api/Gemfile": 'source "https://rubygems.org"\n',
        "/mono/services/api/Gemfile.lock": "GEM\n",
      },
      ["/mono/.git"]
    )
  );
  const api = projects.find((p) => p.root.endsWith("api"));
  expect(api?.gitRoot?.endsWith("mono")).toBe(true);
  expect(
    api?.managers.some((m) => m.name === "bundler" && m.role === "primary")
  ).toBe(true);
});
