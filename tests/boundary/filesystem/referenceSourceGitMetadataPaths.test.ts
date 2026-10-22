import { mkdir, readFile, rename, symlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative } from "node:path";

import { describe, expect, it } from "vitest";

import { readReferenceSourceVcs } from "../../../src/application/ReferenceSourceVcsAdapter.js";
import { execFileOutput } from "../../../src/process/ExecFileOutput.js";
import { withArtifactResourceScope } from "../../fixtures/artifactInventory.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

const UNKNOWN_CASE =
  "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.";
const unknownVcs = { kind: "unknown", head: null, dirty: null };

type RepositoryKind = "ordinary" | "separate" | "linked";

const fixture = async (
  kind: RepositoryKind,
  metadataName = "metadata ",
  ignoreCase = true,
) => {
  const base = await createTestTempDirectory("rea-reference-git-paths-");
  const root = join(base, "selected");
  const initial = kind === "linked" ? join(base, "main") : root;
  const home = join(base, "home");
  await mkdir(initial);
  await mkdir(home);
  const git = async (directory: string, ...args: string[]) =>
    (
      await execFileOutput("git", ["-C", directory, ...args], {
        env: {
          PATH: process.env.PATH,
          HOME: home,
          XDG_CONFIG_HOME: home,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: join(home, "missing-global.config"),
          GIT_CONFIG_COUNT: "0",
          GIT_AUTHOR_NAME: "REA fixture",
          GIT_AUTHOR_EMAIL: "fixture@example.invalid",
          GIT_COMMITTER_NAME: "REA fixture",
          GIT_COMMITTER_EMAIL: "fixture@example.invalid",
        },
      })
    ).stdout;
  const common =
    kind === "ordinary" ? join(root, ".git") : join(base, metadataName);
  await git(
    initial,
    "init",
    "--quiet",
    "--template=",
    "--initial-branch=main",
    ...(kind === "ordinary" ? [] : [`--separate-git-dir=${common}`]),
  );
  const commit = (directory: string) =>
    git(
      directory,
      "-c",
      `core.hooksPath=${join(home, "missing-hooks")}`,
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--quiet",
      "--allow-empty",
      "-m",
      "fixture",
    );
  await commit(initial);
  const initialHead = (await git(initial, "rev-parse", "HEAD")).trim();
  if (kind === "linked") {
    await git(initial, "worktree", "add", "--quiet", "-b", "linked", root);
    await commit(root);
  }
  await git(root, "config", "core.ignoreCase", String(ignoreCase));
  const head = (await git(root, "rev-parse", "HEAD")).trim();
  const gitdir =
    kind === "linked"
      ? (await readFile(join(root, ".git"), "utf8"))
          .slice(8)
          .replace(/[\r\n]+$/u, "")
      : common;
  for (const [path, content] of Object.entries({
    ".gitignore": "/generated/\n",
    "Generated/drop.ts": "export const ignored = true;\n",
    "pkg/.gitignore": "generated/\n",
    "pkg/Generated/drop.ts": "export const nestedIgnored = true;\n",
    "visible.ts": "export const visible = true;\n",
  })) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content);
  }
  return { base, root, common, gitdir, head, initialHead, git };
};

const observe = async (root: string) => {
  const vcs = await withArtifactResourceScope(async (resources) => {
    const result = await readReferenceSourceVcs(root, resources);
    if (!result.ok) throw result.error;
    return result.value;
  });
  const imported = await importReferenceSource({
    root,
    caller: "git-metadata-path-test",
    policy: { secretPatterns: [] },
  });
  if (!imported.ok) throw imported.error;
  return { vcs, graph: imported.value };
};

const expectGitInventory = async (
  repository: Awaited<ReturnType<typeof fixture>>,
  ignoreCase: boolean,
) => {
  const { root, head, git } = repository;
  expect((await git(root, "rev-parse", "HEAD")).trim()).toBe(head);
  expect(
    (await git(root, "config", "--bool", "--get", "core.ignoreCase")).trim(),
  ).toBe(String(ignoreCase));
  const files = (
    await git(root, "ls-files", "--others", "--exclude-standard", "-z")
  )
    .split("\0")
    .filter(Boolean)
    .sort();
  const { vcs, graph } = await observe(root);
  expect(vcs).toEqual({
    info: { kind: "git", head, dirty: null },
    ignoreCase,
  });
  expect(graph.vcs).toEqual(vcs.info);
  expect(graph.limitations).not.toContain(UNKNOWN_CASE);
  expect(
    graph.entries
      .filter(({ kind, path }) => kind === "file" && path !== ".git")
      .map(({ path }) => path)
      .sort(),
  ).toEqual(files);
  for (const path of ["Generated", "pkg/Generated"]) {
    expect(files.includes(`${path}/drop.ts`)).toBe(!ignoreCase);
    expect(
      graph.exclusions.some(
        (exclusion) =>
          exclusion.path === path &&
          exclusion.reason === "project-ignored" &&
          exclusion.pattern ===
            (path.startsWith("pkg/") ? "generated/" : "/generated/") &&
          exclusion.policy_path ===
            (path.startsWith("pkg/") ? "pkg/.gitignore" : ".gitignore"),
      ),
    ).toBe(ignoreCase);
  }
};

describe.skipIf(process.platform === "win32")(
  "reference source Git metadata path identities",
  () => {
    it.each([
      {
        kind: "separate" as const,
        form: "absolute",
        name: "metadata ",
        ending: "\n",
      },
      {
        kind: "separate" as const,
        form: "relative",
        name: "metadata\t",
        ending: "\r\n",
      },
      {
        kind: "separate" as const,
        form: "relative",
        name: "metadata\u00a0",
        ending: "",
      },
      {
        kind: "linked" as const,
        form: "absolute",
        name: "metadata ",
        ending: "\n",
      },
      {
        kind: "linked" as const,
        form: "relative",
        name: "metadata\t",
        ending: "\r\n",
      },
    ])(
      "uses the $kind $form path without selecting a trimmed sibling",
      async ({ kind, form, name, ending }) => {
        const repository = await fixture(kind, name);
        const { root, common, gitdir } = repository;
        const pointer =
          kind === "linked" ? join(gitdir, "commondir") : join(root, ".git");
        const pointerBase = kind === "linked" ? gitdir : root;
        const target =
          form === "absolute"
            ? common
            : `${relative(pointerBase, dirname(common))}/${basename(common)}`;
        await writeFile(
          pointer,
          `${kind === "separate" ? "gitdir: " : ""}${target}${ending}`,
        );
        const sibling = common.trimEnd();
        await mkdir(sibling, { recursive: true });
        await writeFile(join(sibling, "config"), "[core]\nignoreCase=false\n");
        if (kind === "linked")
          expect(repository.head).not.toBe(repository.initialHead);
        await expectGitInventory(repository, true);
      },
    );

    it.each(["ordinary", "separate", "linked"] as const)(
      "preserves %s metadata paths and a case-sensitive setting",
      async (kind) => {
        const repository = await fixture(kind, "metadata", false);
        await expectGitInventory(repository, false);
      },
    );

    it("accepts Git CR/LF record endings for both pointer records", async () => {
      const repository = await fixture("linked", "metadata");
      await writeFile(
        join(repository.root, ".git"),
        `gitdir: ${relative(repository.root, repository.gitdir)}\r\n\n`,
      );
      await writeFile(
        join(repository.gitdir, "commondir"),
        `${relative(repository.gitdir, repository.common)}\r`,
      );
      await expectGitInventory(repository, true);
    });

    it.each([
      "wrong separator",
      "wrong prefix",
      "empty common path",
      "invalid UTF-8",
    ])("retains uncertainty for an invalid %s", async (invalid) => {
      const repository = await fixture(
        invalid === "empty common path" ? "linked" : "separate",
        invalid === "invalid UTF-8" ? "metadata\ufffd" : "metadata",
      );
      const { root, common, gitdir, git } = repository;
      if (invalid === "empty common path") {
        await writeFile(join(gitdir, "commondir"), "\n");
        await writeFile(join(gitdir, "config"), "[core]\nignoreCase=false\n");
      } else if (invalid === "invalid UTF-8") {
        await writeFile(
          join(root, ".git"),
          Buffer.concat([
            Buffer.from(`gitdir: ${common.slice(0, -1)}`),
            Buffer.from([0xff, 0x0a]),
          ]),
        );
      } else {
        await writeFile(
          join(root, ".git"),
          `${invalid === "wrong prefix" ? "GITDIR: " : "gitdir:\t"}${common}\n`,
        );
      }
      await expect(git(root, "rev-parse", "HEAD")).rejects.toMatchObject({
        code: 128,
      });
      const { vcs, graph } = await observe(root);
      expect(vcs).toEqual({ info: unknownVcs, ignoreCase: null });
      expect(graph.vcs).toEqual(unknownVcs);
      expect(graph.limitations).toContain(UNKNOWN_CASE);
      expect(graph.entries.map(({ path }) => path)).toContain("visible.ts");
      expect(graph.entries.map(({ path }) => path)).not.toContain(
        "Generated/drop.ts",
      );
    });

    it("preserves independent config and HEAD uncertainty after resolving the metadata identity", async () => {
      const repository = await fixture("separate", "metadata");
      await writeFile(
        join(repository.common, "config"),
        "[core]\nignoreCase=invalid\n",
      );
      const configUnknown = await observe(repository.root);
      expect(configUnknown.vcs).toEqual({
        info: { kind: "git", head: repository.head, dirty: null },
        ignoreCase: null,
      });
      expect(configUnknown.graph.limitations).toContain(UNKNOWN_CASE);
      await writeFile(
        join(repository.common, "config"),
        "[core]\nignoreCase=true\n",
      );
      await writeFile(join(repository.gitdir, "HEAD"), "invalid\n");
      const headUnknown = await observe(repository.root);
      expect(headUnknown.vcs).toEqual({ info: unknownVcs, ignoreCase: true });
      expect(headUnknown.graph.limitations).not.toContain(UNKNOWN_CASE);
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "reference source Git metadata identity consumers",
  () => {
    it("keeps a Git directory symlink's HEAD and config on the same identity", async () => {
      const repository = await fixture("ordinary");
      const target = join(repository.base, "metadata ");
      await rename(repository.gitdir, target);
      await symlink(target, repository.gitdir, "dir");
      await expectGitInventory(repository, true);
    });

    it("preserves packed, worktree-private and detached refs with a spaced common directory", async () => {
      const repository = await fixture("linked");
      const { root, gitdir, common, git, head, initialHead } = repository;
      await writeFile(join(gitdir, "commondir"), `${common}\n`);
      await git(root, "pack-refs", "--all", "--prune");
      await expectGitInventory(repository, true);
      const ref = "refs/worktree/private";
      await git(root, "update-ref", ref, head);
      await git(root, "symbolic-ref", "HEAD", ref);
      await mkdir(dirname(join(common, ref)), { recursive: true });
      await writeFile(join(common, ref), `${initialHead}\n`);
      await expectGitInventory(repository, true);
      await git(root, "checkout", "--quiet", "--detach", initialHead);
      await expectGitInventory({ ...repository, head: initialHead }, true);
    });
  },
);
