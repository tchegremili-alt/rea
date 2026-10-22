import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

const writeTree = async (root: string, files: Record<string, string>) => {
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content);
  }
};

const testUnknownIncludedGitIgnoreCase = async () => {
  const root = await createTestTempDirectory("rea-reference-ignore-include-");
  const included = join(root, "extra.gitconfig");
  await writeTree(root, {
    "pkg/.gitignore": "generated/\n",
    "pkg/Generated/keep.ts": "retained or excluded according to Git config\n",
  });
  expect(
    spawnSync("git", ["init", "--quiet", root], { encoding: "utf8" }).status,
  ).toBe(0);
  await writeFile(included, "[core]\n\tignoreCase = true\n");
  await writeFile(
    join(root, ".git", "config"),
    `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[includeIf "gitdir:${root}/"]\n\tpath = ${included}\n`,
  );
  const configured = spawnSync(
    "git",
    ["-C", root, "config", "--get", "core.ignoreCase"],
    { encoding: "utf8" },
  );
  expect(configured.status, configured.stderr).toBe(0);
  expect(configured.stdout.trim()).toBe("true");
  const git = spawnSync(
    "git",
    ["-C", root, "check-ignore", "--no-index", "pkg/Generated/keep.ts"],
    { encoding: "utf8" },
  );
  expect(git.status, git.stderr).toBe(0);

  const result = await importReferenceSource({
    root,
    caller: "nested-ignore-include-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  expect(result.value.limitations).toContain(
    "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.",
  );
  expect(result.value.inventory_state).toBe("partial");
  expect(result.value.exclusions).toContainEqual(
    expect.objectContaining({
      path: "pkg/Generated",
      reason: "project-ignored",
      pattern: "generated/",
      policy_path: "pkg/.gitignore",
    }),
  );
};

const testLinkedWorktreeIgnoreCaseOverride = async () => {
  const root = await createTestTempDirectory(
    "rea-reference-worktree-ignore-case-",
  );
  const common = join(root, "common");
  const linked = join(root, "linked");
  const git = (cwd: string, args: string[]) =>
    spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8" });
  const succeeds = (cwd: string, args: string[]) => {
    const result = git(cwd, args);
    expect(result.status, result.stderr).toBe(0);
    return result;
  };
  await mkdir(common);
  await writeTree(common, {
    ".gitignore": "generated/\n",
    "pkg/Generated/keep.ts": "retained according to linked config\n",
  });
  expect(
    spawnSync("git", ["init", "--quiet", "--initial-branch=main", common], {
      encoding: "utf8",
    }).status,
  ).toBe(0);
  succeeds(common, ["add", "--", ".gitignore"]);
  succeeds(common, ["add", "--force", "--", "pkg/Generated/keep.ts"]);
  succeeds(common, [
    "-c",
    "user.name=REA fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "fixture",
  ]);
  succeeds(common, ["config", "core.ignoreCase", "true"]);
  succeeds(common, ["config", "extensions.worktreeConfig", "true"]);
  succeeds(common, ["worktree", "add", "--quiet", "--detach", linked, "HEAD"]);
  succeeds(linked, ["config", "--worktree", "core.ignoreCase", "false"]);

  const effectiveCase = succeeds(linked, [
    "config",
    "--get",
    "core.ignoreCase",
  ]);
  expect(effectiveCase.stdout.trim()).toBe("false");
  expect(
    git(linked, ["check-ignore", "--no-index", "pkg/Generated/keep.ts"]).status,
  ).toBe(1);
  const result = await importReferenceSource({
    root: linked,
    caller: "nested-ignore-worktree-config-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  expect(result.value.limitations).toContain(
    "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.",
  );
  expect(result.value.exclusions).toContainEqual(
    expect.objectContaining({
      path: "pkg/Generated",
      reason: "project-ignored",
      pattern: "generated/",
      policy_path: ".gitignore",
    }),
  );
};

const testMalformedGitIgnoreConfig = async () => {
  const root = await createTestTempDirectory(
    "rea-reference-ignore-malformed-config-",
  );
  await writeTree(root, {
    ".gitignore": "generated/\n",
    "pkg/Generated/keep.ts": "retained only by a case-sensitive config\n",
  });
  expect(
    spawnSync("git", ["init", "--quiet", "--initial-branch=main", root], {
      encoding: "utf8",
    }).status,
  ).toBe(0);
  expect(
    spawnSync("git", ["-C", root, "config", "core.ignoreCase", "false"], {
      encoding: "utf8",
    }).status,
  ).toBe(0);
  const configPath = join(root, ".git", "config");
  await writeFile(
    configPath,
    `${await readFile(configPath, "utf8")}\n[user]\n\tname = "unterminated\n`,
  );
  expect(
    spawnSync("git", ["-C", root, "config", "--get", "core.ignoreCase"], {
      encoding: "utf8",
    }).status,
  ).not.toBe(0);

  const result = await importReferenceSource({
    root,
    caller: "nested-ignore-malformed-config-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  expect(result.value.limitations).toContain(
    "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.",
  );
  expect(result.value.exclusions).toContainEqual(
    expect.objectContaining({
      path: "pkg/Generated",
      reason: "project-ignored",
      pattern: "generated/",
      policy_path: ".gitignore",
    }),
  );
};

const testRepeatedInvalidIgnoreCase = async () => {
  const root = await createTestTempDirectory(
    "rea-reference-ignore-repeated-invalid-config-",
  );
  await writeTree(root, {
    ".gitignore": "generated/\n",
    "Generated/keep.ts": "unknown case semantics must not retain this file\n",
    "generated/keep.ts": "lowercase match\n",
  });
  expect(
    spawnSync("git", ["init", "--quiet", "--initial-branch=main", root], {
      encoding: "utf8",
    }).status,
  ).toBe(0);
  const configPath = join(root, ".git", "config");
  await writeFile(
    configPath,
    `${await readFile(configPath, "utf8")}\n[core]\n\tignoreCase = auto\n\tignoreCase = false\n`,
  );
  const gitConfig = spawnSync(
    "git",
    ["-C", root, "config", "--bool", "--get", "core.ignoreCase"],
    { encoding: "utf8" },
  );
  expect(gitConfig.status).not.toBe(0);
  const gitCheck = spawnSync(
    "git",
    ["-C", root, "check-ignore", "--no-index", "-v", "--", "Generated/keep.ts"],
    { encoding: "utf8" },
  );
  expect(gitCheck.status).not.toBe(0);

  const result = await importReferenceSource({
    root,
    caller: "nested-ignore-repeated-invalid-config-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  expect(result.value.limitations).toContain(
    "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.",
  );
  expect(result.value.exclusions).toContainEqual(
    expect.objectContaining({
      path: "Generated",
      reason: "project-ignored",
      pattern: "generated/",
      policy_path: ".gitignore",
    }),
  );
};

const testCanonicalSymlinkUsesTargetRepository = async () => {
  const root = await createTestTempDirectory("rea-reference-vcs-symlink-");
  const repositoryA = join(root, "repository-a");
  const repositoryB = join(root, "repository-b");
  const selected = join(repositoryA, "selected");
  const target = join(repositoryB, "packages", "chosen");
  await Promise.all([mkdir(repositoryA), mkdir(repositoryB)]);
  await writeTree(repositoryA, { "selected.ts": "repository A\n" });
  await writeTree(repositoryB, {
    "packages/chosen/.gitignore": "generated/\n",
    "packages/chosen/Generated/keep.ts": "repository B source\n",
  });
  const git = (cwd: string, args: string[]) =>
    spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8" });
  const succeeds = (cwd: string, args: string[]) => {
    const result = git(cwd, args);
    expect(result.status, result.stderr).toBe(0);
    return result;
  };
  for (const repository of [repositoryA, repositoryB])
    expect(
      spawnSync(
        "git",
        ["init", "--quiet", "--initial-branch=main", repository],
        {
          encoding: "utf8",
        },
      ).status,
    ).toBe(0);
  succeeds(repositoryA, ["config", "core.ignoreCase", "true"]);
  succeeds(repositoryA, ["add", "--", "selected.ts"]);
  succeeds(repositoryA, [
    "-c",
    "user.name=REA fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "repository A",
  ]);
  succeeds(repositoryB, ["config", "core.ignoreCase", "false"]);
  succeeds(repositoryB, ["add", "--", "packages/chosen/.gitignore"]);
  succeeds(repositoryB, ["add", "--", "packages/chosen/Generated/keep.ts"]);
  succeeds(repositoryB, [
    "-c",
    "user.name=REA fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "repository B",
  ]);
  await symlink(target, selected);

  const expectedHead = succeeds(repositoryB, [
    "rev-parse",
    "HEAD",
  ]).stdout.trim();
  const result = await importReferenceSource({
    root: selected,
    caller: "nested-ignore-symlink-vcs-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  expect(result.value.vcs).toMatchObject({ kind: "git", head: expectedHead });
  expect(result.value.exclusions).not.toContainEqual(
    expect.objectContaining({ path: "Generated", reason: "project-ignored" }),
  );
  expect(result.value.entries).toContainEqual(
    expect.objectContaining({ path: "Generated/keep.ts", kind: "file" }),
  );
};

const testTerminalGlobstarMatchesGit = async (
  nested: boolean,
  pattern: string,
) => {
  const root = await createTestTempDirectory(
    "rea-reference-terminal-globstar-",
  );
  const prefix = nested ? "pkg/" : "";
  const policyPath = nested ? "pkg/.gitignore" : ".gitignore";
  const directPath = `${prefix}foo/direct.ts`;
  const nestedPath = `${prefix}foo/sub/deep.ts`;
  await writeTree(root, {
    [policyPath]: `${pattern}\n`,
    [directPath]: "export const direct = true;\n",
    [nestedPath]: "export const deep = true;\n",
    [`${prefix}keep.ts`]: "export const keep = true;\n",
  });
  const initialized = spawnSync("git", ["init", "--quiet", root], {
    encoding: "utf8",
  });
  expect(initialized.status, initialized.stderr).toBe(0);

  const gitIgnored = (path: string): boolean => {
    const result = spawnSync(
      "git",
      ["-C", root, "check-ignore", "--no-index", "--", path],
      { encoding: "utf8" },
    );
    expect([0, 1], result.stderr).toContain(result.status);
    return result.status === 0;
  };
  const result = await importReferenceSource({
    root,
    caller: "nested-ignore-terminal-globstar-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  const entries = new Set(result.value.entries.map(({ path }) => path));
  for (const path of [directPath, nestedPath]) {
    const ignored = gitIgnored(path);
    expect(entries.has(path)).toBe(!ignored);
    const provenance = result.value.exclusions.some(
      (exclusion) =>
        exclusion.reason === "project-ignored" &&
        exclusion.policy_path === policyPath &&
        exclusion.pattern === pattern &&
        (exclusion.path === path || path.startsWith(`${exclusion.path}/`)),
    );
    expect(provenance).toBe(ignored);
  }
  expect(entries.has(`${prefix}keep.ts`)).toBe(true);
};

const testLiteralWhitespaceIgnoreMatchesGit = async (
  nested: boolean,
  name: string,
  pattern = name,
) => {
  const root = await createTestTempDirectory(
    "rea-reference-literal-whitespace-ignore-",
  );
  const prefix = nested ? "pkg/" : "";
  const policyPath = nested ? "pkg/.gitignore" : ".gitignore";
  const ignoredPath = `${prefix}${name}`;
  await writeTree(root, {
    [policyPath]: `${pattern}\n`,
    [ignoredPath]: "must be excluded by Git's literal whitespace rule\n",
    [`${prefix}keep.ts`]: "retained\n",
  });
  const initialized = spawnSync("git", ["init", "--quiet", root], {
    encoding: "utf8",
  });
  expect(initialized.status, initialized.stderr).toBe(0);
  const git = spawnSync(
    "git",
    ["-C", root, "check-ignore", "--no-index", "-v", "--", ignoredPath],
    { encoding: "utf8" },
  );
  expect(git.status, git.stderr).toBe(0);

  const result = await importReferenceSource({
    root,
    caller: "nested-ignore-literal-whitespace-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  expect(result.value.entries.map(({ path }) => path)).not.toContain(
    ignoredPath,
  );
  expect(result.value.entries.map(({ path }) => path)).toContain(
    `${prefix}keep.ts`,
  );
  expect(result.value.exclusions).toContainEqual(
    expect.objectContaining({
      path: ignoredPath,
      reason: "project-ignored",
      pattern,
      policy_path: policyPath,
    }),
  );
};

const testWhitespaceGlobCardinalityMatchesGit = async (
  nested: boolean,
  whitespace: string,
) => {
  const root = await createTestTempDirectory(
    "rea-reference-whitespace-glob-cardinality-",
  );
  const prefix = nested ? "pkg/" : "";
  const policyPath = nested ? "pkg/.gitignore" : ".gitignore";
  const pattern = "foo?bar";
  const targetPaths = [`${prefix}foo${whitespace}bar`, `${prefix}fooXbar`];
  await writeTree(root, {
    [policyPath]: `${pattern}\n`,
    [targetPaths[0]!]: "literal whitespace match\n",
    [targetPaths[1]!]: "single-character glob match\n",
    [`${prefix}keep.ts`]: "retained\n",
  });
  expect(
    spawnSync("git", ["init", "--quiet", root], { encoding: "utf8" }).status,
  ).toBe(0);
  for (const targetPath of targetPaths) {
    const git = spawnSync(
      "git",
      ["-C", root, "check-ignore", "--no-index", "-v", "--", targetPath],
      { encoding: "utf8" },
    );
    expect(git.status, git.stderr).toBe(0);
  }
  const result = await importReferenceSource({
    root,
    caller: "nested-ignore-whitespace-glob-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  for (const targetPath of targetPaths)
    expect(result.value.entries.map(({ path }) => path)).not.toContain(
      targetPath,
    );
  expect(result.value.entries.map(({ path }) => path)).toContain(
    `${prefix}keep.ts`,
  );
};

const testLiteralWhitespaceSecretPattern = async () => {
  const root = await createTestTempDirectory(
    "rea-reference-literal-whitespace-secret-",
  );
  await writeTree(root, {
    ".gitignore": "",
    "\t": "excluded by the caller's secret rule\n",
    "keep.ts": "retained\n",
  });
  expect(
    spawnSync("git", ["init", "--quiet", root], { encoding: "utf8" }).status,
  ).toBe(0);
  const result = await importReferenceSource({
    root,
    caller: "literal-whitespace-secret-test",
    policy: { secretPatterns: ["\t"] },
  });
  if (!result.ok) throw result.error;
  expect(result.value.entries.map(({ path }) => path)).not.toContain("\t");
  expect(result.value.exclusions).toContainEqual(
    expect.objectContaining({
      path: "\t",
      reason: "configured-secret",
      pattern: "\t",
    }),
  );
};

describe.skipIf(process.platform === "win32")(
  "nested reference ignore rules",
  () => {
    it.each([false, true])(
      "matches Git core.ignoreCase=%s for nested rules",
      async (ignoreCase) => {
        const root = await createTestTempDirectory(
          "rea-reference-ignore-case-",
        );
        await writeTree(root, {
          "pkg/.gitignore": "generated/\n",
          "pkg/Generated/keep.ts": "retained\n",
        });

        const initialized = spawnSync("git", ["init", "--quiet", root], {
          encoding: "utf8",
        });
        expect(initialized.status, initialized.stderr).toBe(0);
        const caseConfig = spawnSync(
          "git",
          ["-C", root, "config", "core.ignoreCase", String(ignoreCase)],
          { encoding: "utf8" },
        );
        expect(caseConfig.status, caseConfig.stderr).toBe(0);

        const ignored = spawnSync(
          "git",
          ["-C", root, "check-ignore", "--no-index", "pkg/generated/drop.ts"],
          { encoding: "utf8" },
        );
        const caseVariant = spawnSync(
          "git",
          ["-C", root, "check-ignore", "--no-index", "pkg/Generated/keep.ts"],
          { encoding: "utf8" },
        );
        expect(ignored.status, ignored.stderr).toBe(0);
        expect(caseVariant.status).toBe(ignoreCase ? 0 : 1);

        const result = await importReferenceSource({
          root,
          caller: "nested-ignore-case-test",
          policy: { secretPatterns: [] },
        });
        if (!result.ok) throw result.error;
        expect(
          result.value.exclusions.some(
            (exclusion) =>
              exclusion.path === "pkg/Generated" &&
              exclusion.reason === "project-ignored" &&
              exclusion.pattern === "generated/" &&
              exclusion.policy_path === "pkg/.gitignore",
          ),
        ).toBe(ignoreCase);
        expect(
          result.value.entries.some(
            ({ path }) => path === "pkg/Generated/keep.ts",
          ),
        ).toBe(!ignoreCase);
      },
    );
    it("preserves literal whitespace in caller secret patterns", async () => {
      await testLiteralWhitespaceSecretPattern();
    });

    it("retains unknown ignore case when Git config uses includes", async () => {
      await testUnknownIncludedGitIgnoreCase();
    });

    it("keeps ignore case unknown when linked worktree config can override common config", async () => {
      await testLinkedWorktreeIgnoreCaseOverride();
    });

    it("does not trust a core setting from a malformed Git config", async () => {
      await testMalformedGitIgnoreConfig();
    });

    it("reads VCS facts and ignore-case rules from the canonical symlink target", async () => {
      await testCanonicalSymlinkUsesTargetRepository();
    });

    it("scopes anchored rules and negations to their directory and descendants", async () => {
      const root = await createTestTempDirectory(
        "rea-reference-nested-ignore-",
      );
      await writeTree(root, {
        ".gitignore": "*.tmp\n",
        "root.tmp": "root rule\n",
        "packages/[widget]/.gitignore": "!*.tmp\n/anchored.tmp\n",
        "packages/[widget]/keep.tmp": "child negation\n",
        "packages/[widget]/anchored.tmp": "child anchored rule\n",
        "packages/[widget]/deep/.gitignore": "again.tmp\n",
        "packages/[widget]/deep/anchored.tmp": "outside anchored rule\n",
        "packages/[widget]/deep/keep.tmp": "inherited negation\n",
        "packages/[widget]/deep/again.tmp": "deeper rule\n",
        "packages/sibling/keep.tmp": "root rule still applies\n",
        "packages/sibling/source.js": "export {};\n",
      });

      const result = await importReferenceSource({
        root,
        caller: "nested-ignore-test",
        policy: { secretPatterns: [] },
      });
      if (!result.ok) throw result.error;
      expect(result.value.exclusions).toEqual([
        {
          path: "packages/[widget]/anchored.tmp",
          entry_kind: "file",
          reason: "project-ignored",
          pattern: "/anchored.tmp",
          policy_path: "packages/[widget]/.gitignore",
        },
        {
          path: "packages/[widget]/deep/again.tmp",
          entry_kind: "file",
          reason: "project-ignored",
          pattern: "again.tmp",
          policy_path: "packages/[widget]/deep/.gitignore",
        },
        {
          path: "packages/sibling/keep.tmp",
          entry_kind: "file",
          reason: "project-ignored",
          pattern: "*.tmp",
          policy_path: ".gitignore",
        },
        {
          path: "root.tmp",
          entry_kind: "file",
          reason: "project-ignored",
          pattern: "*.tmp",
          policy_path: ".gitignore",
        },
      ]);
      expect(
        result.value.entries
          .filter(({ kind }) => kind === "file")
          .map(({ path }) => path),
      ).toEqual([
        ".gitignore",
        "packages/[widget]/.gitignore",
        "packages/[widget]/deep/.gitignore",
        "packages/[widget]/deep/anchored.tmp",
        "packages/[widget]/deep/keep.tmp",
        "packages/[widget]/keep.tmp",
        "packages/sibling/source.js",
      ]);
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "nested reference ignore syntax",
  () => {
    it.each(["a?b", "a*b", "a\\", "[widget]"])(
      "treats the policy directory %s as a literal path",
      async (directory) => {
        const root = await createTestTempDirectory(
          "rea-reference-ignore-literal-",
        );
        await writeTree(root, {
          [`${directory}/.gitignore`]: "ignored.txt\n",
          [`${directory}/ignored.txt`]: "project exclusion\n",
          "sibling/ignored.txt": "outside policy scope\n",
        });
        const result = await importReferenceSource({
          root,
          caller: "nested-ignore-test",
          policy: { secretPatterns: [] },
        });
        if (!result.ok) throw result.error;
        expect(result.value.exclusions).toEqual([
          {
            path: `${directory}/ignored.txt`,
            entry_kind: "file",
            reason: "project-ignored",
            pattern: "ignored.txt",
            policy_path: `${directory}/.gitignore`,
          },
        ]);
        expect(result.value.entries).toContainEqual(
          expect.objectContaining({
            path: "sibling/ignored.txt",
            kind: "file",
            content_state: "hashed",
          }),
        );
      },
    );

    it("preserves escaped names, comments and directory rules with trailing whitespace", async () => {
      const root = await createTestTempDirectory(
        "rea-reference-ignore-syntax-",
      );
      await writeTree(root, {
        "pkg/.gitignore":
          "# comment\n\\#hash\n\\!bang\nliteral\\ \ncache/   \n",
        "pkg/# comment": "comment is not a rule\n",
        "pkg/#hash": "escaped hash\n",
        "pkg/!bang": "escaped bang\n",
        "pkg/literal ": "escaped trailing space\n",
        "pkg/literal": "unmatched control\n",
        "pkg/deeper/cache/output.js": 'import "./missing.js";\n',
      });
      const result = await importReferenceSource({
        root,
        caller: "nested-ignore-test",
        policy: { secretPatterns: [] },
      });
      if (!result.ok) throw result.error;
      expect(result.value.exclusions.map(({ path }) => path)).toEqual([
        "pkg/!bang",
        "pkg/#hash",
        "pkg/deeper/cache",
        "pkg/literal ",
      ]);
      for (const path of ["pkg/# comment", "pkg/literal"])
        expect(result.value.entries).toContainEqual(
          expect.objectContaining({
            path,
            kind: "file",
            content_state: "hashed",
          }),
        );
      expect(result.value.relationships).toEqual([]);
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "nested reference ignore precedence",
  () => {
    it("preserves default, caller, and secret precedence and prunes excluded directories", async () => {
      const root = await createTestTempDirectory(
        "rea-reference-nested-precedence-",
      );
      await writeTree(root, {
        ".gitignore": "pruned/\n",
        "pkg/.gitignore":
          "*.tmp\n!*.log\n!private.txt\n!caller.txt\n!dist/\ngenerated/\nreopened/\n",
        "pkg/keep.tmp": "caller negation\n",
        "pkg/keep.log": "caller negation of default\n",
        "pkg/app.log": "default exclusion\n",
        "pkg/private.txt": "secret exclusion\n",
        "pkg/caller.txt": "caller exclusion\n",
        "pkg/dist/output.js": 'import "./missing-default.js";\n',
        "pkg/reopened/.gitignore": "drop.js\n",
        "pkg/reopened/drop.js": 'import "./missing-reopened.js";\n',
        "pkg/reopened/keep.txt": "caller reopened directory\n",
        "pkg/generated/.gitignore": "!stale.js\n",
        "pkg/generated/stale.js": 'import "./missing-generated.js";\n',
        "pruned/.gitignore": "!stale.js\n",
        "pruned/stale.js": 'import "./missing-pruned.js";\n',
      });
      const result = await importReferenceSource({
        root,
        caller: "nested-ignore-test",
        policy: { secretPatterns: ["private.txt"] },
        excludePaths: [
          "pkg/caller.txt",
          "!pkg/keep.tmp",
          "!pkg/keep.log",
          "!pkg/reopened/",
        ],
      });
      if (!result.ok) throw result.error;
      expect(result.value.exclusions).toEqual([
        {
          path: "pkg/app.log",
          entry_kind: "file",
          reason: "default-ignored",
          pattern: "*.log",
        },
        {
          path: "pkg/caller.txt",
          entry_kind: "file",
          reason: "caller-excluded",
          pattern: "pkg/caller.txt",
        },
        {
          path: "pkg/dist",
          entry_kind: "directory",
          reason: "default-ignored",
          pattern: "dist/",
        },
        {
          path: "pkg/generated",
          entry_kind: "directory",
          reason: "project-ignored",
          pattern: "generated/",
          policy_path: "pkg/.gitignore",
        },
        {
          path: "pkg/private.txt",
          entry_kind: "file",
          reason: "configured-secret",
          pattern: "private.txt",
        },
        {
          path: "pkg/reopened/drop.js",
          entry_kind: "file",
          reason: "project-ignored",
          pattern: "drop.js",
          policy_path: "pkg/reopened/.gitignore",
        },
        {
          path: "pruned",
          entry_kind: "directory",
          reason: "project-ignored",
          pattern: "pruned/",
          policy_path: ".gitignore",
        },
      ]);
      expect(
        result.value.entries
          .filter(({ kind }) => kind === "file")
          .map(({ path }) => path),
      ).toEqual([
        ".gitignore",
        "pkg/.gitignore",
        "pkg/keep.log",
        "pkg/keep.tmp",
        "pkg/reopened/.gitignore",
        "pkg/reopened/keep.txt",
      ]);
      expect(result.value.relationships).toEqual([]);
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "nested directory-only ignore rules",
  () => {
    it.each(["**/", "/**/", "**/**/"])(
      "does not let %s exclude the directory containing the policy",
      async (pattern) => {
        const root = await createTestTempDirectory(
          "rea-reference-ignore-directory-only-",
        );
        await writeTree(root, {
          "packages/pkg/.gitignore": `${pattern}\n`,
          "packages/pkg/direct.ts": "export const retained = true;\n",
          "packages/pkg/generated/output.ts": "export const ignored = true;\n",
          "packages/sibling/direct.ts": "export const sibling = true;\n",
        });
        const result = await importReferenceSource({
          root,
          caller: "nested-ignore-test",
          policy: { secretPatterns: [] },
        });
        if (!result.ok) throw result.error;
        expect(result.value.exclusions).toEqual([
          {
            path: "packages/pkg/generated",
            entry_kind: "directory",
            reason: "project-ignored",
            pattern,
            policy_path: "packages/pkg/.gitignore",
          },
        ]);
        expect(
          result.value.entries
            .filter(({ kind }) => kind === "file")
            .map(({ path }) => path),
        ).toEqual([
          "packages/pkg/.gitignore",
          "packages/pkg/direct.ts",
          "packages/sibling/direct.ts",
        ]);
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "terminal globstar ignore rules",
  () => {
    it.each([
      { nested: false, pattern: "foo/**" },
      { nested: false, pattern: "foo/**/" },
      { nested: true, pattern: "foo/**" },
      { nested: true, pattern: "foo/**/" },
      { nested: false, pattern: "foo/**\n!foo/**" },
      { nested: true, pattern: "foo/**\n!foo/**" },
    ])(
      "preserves Git file and directory semantics for $pattern (nested=$nested)",
      async ({ nested, pattern }) => {
        await testTerminalGlobstarMatchesGit(nested, pattern);
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "literal whitespace in ignore rules",
  () => {
    it.each([
      { nested: false, name: "\t" },
      { nested: false, name: "\u00a0" },
      { nested: true, name: "\t" },
      { nested: true, name: "\u00a0" },
    ])("matches Git for $name (nested=$nested)", async ({ nested, name }) => {
      await testLiteralWhitespaceIgnoreMatchesGit(nested, name);
    });
    it.each([
      { nested: false, whitespace: "\t" },
      { nested: true, whitespace: "\t" },
    ])(
      "preserves one-character glob matching for $whitespace (nested=$nested)",
      async ({ nested, whitespace }) => {
        await testWhitespaceGlobCardinalityMatchesGit(nested, whitespace);
      },
    );
    it.each([
      { nested: false, name: "\t" },
      { nested: true, name: "\t" },
    ])(
      "preserves an existing character class for $name (nested=$nested)",
      async ({ nested, name }) => {
        await testLiteralWhitespaceIgnoreMatchesGit(nested, name, `[${name}]`);
      },
    );
    it.each([false, true])(
      "keeps an escaped opening bracket literal (nested=%s)",
      async (nested) => {
        await testLiteralWhitespaceIgnoreMatchesGit(nested, `[\t`, `\\[\t`);
      },
    );
  },
);

it("keeps repeated invalid Git ignoreCase values unknown", async () => {
  await testRepeatedInvalidIgnoreCase();
});
