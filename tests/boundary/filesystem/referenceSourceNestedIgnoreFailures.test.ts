import { mkdir, open as fsOpen, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import { importReferenceSource } from "../../../src/application/ReferenceSourceImport.js";
import type { ReferenceSourceImportError } from "../../../src/application/ReferenceSourceImportTypes.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, open: vi.fn(actual.open) };
});

const openMock = vi.mocked(fsOpen);
let actual: typeof import("node:fs/promises");

beforeEach(async () => {
  actual =
    await vi.importActual<typeof import("node:fs/promises")>(
      "node:fs/promises",
    );
  openMock.mockImplementation((...args) => actual.open(...args));
});

afterEach(() => openMock.mockReset());

const fixture = async () => {
  const root = await createTestTempDirectory("rea-reference-nested-policy-");
  const nested = join(root, "nested");
  await mkdir(nested);
  const source = join(root, "source.ts");
  const rootPolicy = join(root, ".gitignore");
  const rootExcluded = join(root, "excluded-before-failure.ts");
  const policy = join(nested, ".gitignore");
  const excluded = join(nested, "excluded.ts");
  const sourceBytes = "export const visible = true;\n";
  await Promise.all([
    writeFile(source, sourceBytes),
    writeFile(rootPolicy, "excluded-before-failure.ts\n"),
    writeFile(rootExcluded, "excluded before traversal failure\n"),
    writeFile(policy, "*\n"),
    writeFile(excluded, "export const mustNotBeRead = true;\n"),
  ]);
  return { root, source, policy, excluded, sourceBytes };
};

const initializeUnknownIgnoreCaseRepository = (root: string): void => {
  const initialized = spawnSync(
    "git",
    ["init", "--quiet", "--initial-branch=main", root],
    { encoding: "utf8" },
  );
  expect(initialized.status, initialized.stderr).toBe(0);
  const unset = spawnSync(
    "git",
    ["-C", root, "config", "--local", "--unset-all", "core.ignoreCase"],
    { encoding: "utf8" },
  );
  expect([0, 5], unset.stderr).toContain(unset.status);
};

const importTree = (
  root: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
) =>
  importReferenceSource(
    {
      root,
      caller: "reference-nested-policy-failure-test",
      policy: { secretPatterns: [] },
      ...(signal === undefined ? {} : { signal }),
    },
    resources,
  );

const expectUnenteredSubtree = (
  error: ReferenceSourceImportError,
  sourceBytes: string,
  excluded: string,
  includesGitMetadata = false,
) => {
  expect(error.partial?.entries).toContainEqual(
    expect.objectContaining({
      status: "read",
      kind: "file",
      path: "source.ts",
      bytes: Buffer.from(sourceBytes),
    }),
  );
  expect(
    error.partial?.entries.filter(({ path }) => path === "nested"),
  ).toEqual([
    {
      status: "failed",
      kind: "directory",
      path: "nested",
      code: error.code,
      message: error.message,
    },
  ]);
  expect(
    error.partial?.entries.some(({ path }) => path.startsWith("nested/")),
  ).toBe(false);
  expect(error.partial?.exclusions).toEqual([
    ...(includesGitMetadata
      ? [
          {
            path: ".git",
            entry_kind: "directory",
            reason: "default-ignored",
            pattern: ".git/",
          },
        ]
      : []),
    {
      path: "excluded-before-failure.ts",
      entry_kind: "file",
      reason: "project-ignored",
      pattern: "excluded-before-failure.ts",
      policy_path: ".gitignore",
    },
  ]);
  expect(
    openMock.mock.calls.some(
      ([path]) => resolve(String(path)) === resolve(excluded),
    ),
  ).toBe(false);
};

describe.skipIf(process.platform === "win32")(
  "nested reference source ignore policy failures",
  () => {
    it("preserves unknown ignore-case limitations in partial nested-policy failures", async () => {
      const { root, policy, sourceBytes } = await fixture();
      initializeUnknownIgnoreCaseRepository(root);
      await writeFile(policy, Buffer.from([0xff, 0xfe]));
      const resources = new ArtifactResourceScope();
      try {
        const result = await importTree(root, resources);
        if (result.ok) throw new Error("Expected nested policy failure");
        expect(result.error.code).toBe("io");
        expect(result.error.partial?.limitations).toContain(
          "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.",
        );
        expect(result.error.partial?.exclusions).toEqual(
          expect.arrayContaining([
            {
              path: "excluded-before-failure.ts",
              entry_kind: "file",
              reason: "project-ignored",
              pattern: "excluded-before-failure.ts",
              policy_path: ".gitignore",
            },
          ]),
        );
        expectUnenteredSubtree(
          result.error,
          sourceBytes,
          join(root, "nested", "excluded.ts"),
          true,
        );
      } finally {
        await resources.close();
      }
    });

    it.each(["invalid UTF-8", "unreadable file", "symbolic link"] as const)(
      "fails closed for a nested %s policy before reading its children",
      async (condition) => {
        const { root, policy, excluded, sourceBytes } = await fixture();
        await symlink("nested/excluded.ts", join(root, "alias.ts"));
        const resources = new ArtifactResourceScope();
        const denied = Object.assign(
          new Error("controlled nested policy EACCES"),
          {
            code: "EACCES",
          },
        );
        let externalReads = 0;
        if (condition === "invalid UTF-8") {
          await writeFile(policy, Buffer.from([0xff, 0xfe]));
        } else if (condition === "unreadable file") {
          openMock.mockImplementation(async (...args) => {
            if (resolve(String(args[0])) === resolve(policy)) throw denied;
            return actual.open(...args);
          });
        } else {
          const outside = await createTestTempDirectory(
            "rea-reference-policy-target-",
          );
          const target = join(outside, "rules");
          await writeFile(target, "*\n");
          await actual.unlink(policy);
          await symlink(target, policy);
          openMock.mockImplementation(async (...args) => {
            const handle = await actual.open(...args);
            if (
              [resolve(policy), resolve(target)].includes(
                resolve(String(args[0])),
              )
            ) {
              const read = handle.read.bind(handle);
              vi.spyOn(handle, "read").mockImplementation((...readArgs) => {
                externalReads += 1;
                return read(...readArgs);
              });
            }
            return handle;
          });
        }

        try {
          const result = await importTree(root, resources);
          if (result.ok)
            throw new Error("Expected nested ignore policy failure");
          expect(result.error.code).toBe("io");
          expect(result.error.message).toContain(policy);
          if (condition === "invalid UTF-8")
            expect(result.error.message).toContain("UTF-8");
          if (condition === "unreadable file")
            expect(result.error.cause).toBe(denied);
          expectUnenteredSubtree(result.error, sourceBytes, excluded);
          expect(result.error.partial?.entries).toContainEqual(
            expect.objectContaining({
              path: "alias.ts",
              status: "failed",
              kind: "symlink",
              code: "io",
              message: expect.stringContaining('directory "nested"'),
            }),
          );
          expect(externalReads).toBe(0);
          expect(resources.hasPending).toBe(false);
        } finally {
          await resources.close();
        }
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "nested reference source ignore policy finalization",
  () => {
    it("keeps unknown ignore-case limitations when cancellation follows nested policy cleanup", async () => {
      const { root, policy, sourceBytes, excluded } = await fixture();
      initializeUnknownIgnoreCaseRepository(root);
      const resources = new ArtifactResourceScope();
      const controller = new AbortController();
      const reason = new Error("cancel after nested Git policy cleanup");
      openMock.mockImplementation(async (...args) => {
        const handle = await actual.open(...args);
        if (resolve(String(args[0])) !== resolve(policy)) return handle;
        const close = handle.close.bind(handle);
        vi.spyOn(handle, "close").mockImplementation(async () => {
          await close();
          controller.abort(reason);
        });
        return handle;
      });

      try {
        const result = await importTree(root, resources, controller.signal);
        if (result.ok) throw new Error("Expected nested policy cancellation");
        expect(result.error.code).toBe("cancelled");
        expect(result.error.cause).toBe(reason);
        expect(result.error.partial?.limitations).toContain(
          "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.",
        );
        expectUnenteredSubtree(result.error, sourceBytes, excluded, true);
      } finally {
        await resources.close();
      }
    });

    it.each([
      { cancel: false, failFirstClose: false },
      { cancel: true, failFirstClose: false },
      { cancel: true, failFirstClose: true },
    ])(
      "observes cancellation after nested policy close (cancel=$cancel, retry=$failFirstClose)",
      async ({ cancel, failFirstClose }) => {
        const { root, policy, excluded, sourceBytes } = await fixture();
        const resources = new ArtifactResourceScope();
        const controller = new AbortController();
        const reason = new Error(
          "caller cancelled during nested policy finalization",
        );
        let policyHandle: Awaited<ReturnType<typeof fsOpen>> | undefined;
        let closes = 0;
        openMock.mockImplementation(async (...args) => {
          const handle = await actual.open(...args);
          if (resolve(String(args[0])) !== resolve(policy)) return handle;
          policyHandle = handle;
          const close = handle.close.bind(handle);
          vi.spyOn(handle, "close").mockImplementation(async () => {
            closes += 1;
            if (failFirstClose && closes === 1)
              throw new Error("controlled first policy close failure");
            await close();
            if (cancel) controller.abort(reason);
          });
          return handle;
        });

        try {
          const result = await importTree(root, resources, controller.signal);
          expect(closes).toBe(failFirstClose ? 2 : 1);
          expect(policyHandle?.fd).toBe(-1);
          expect(resources.hasPending).toBe(false);
          if (cancel) {
            if (result.ok)
              throw new Error("Expected cancellation after policy close");
            expect(result.error.code).toBe("cancelled");
            expect(result.error.cause).toBe(reason);
            expect(result.error.cleanup).toBeUndefined();
            expectUnenteredSubtree(result.error, sourceBytes, excluded);
          } else {
            if (!result.ok) throw result.error;
            expect(result.value.entries).toContainEqual(
              expect.objectContaining({ path: "source.ts", kind: "file" }),
            );
            expect(result.value.exclusions).toContainEqual({
              path: "nested/excluded.ts",
              entry_kind: "file",
              reason: "project-ignored",
              pattern: "*",
              policy_path: "nested/.gitignore",
            });
          }
        } finally {
          await resources.close();
        }
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "nested reference source ignore policy cleanup ownership",
  () => {
    it.each(["physical failure", "cancellation"] as const)(
      "retains nested policy cleanup and the primary %s until its owner can retry",
      async (primary) => {
        const { root, source, policy, excluded, sourceBytes } = await fixture();
        const resources = new ArtifactResourceScope();
        const controller = new AbortController();
        const reason = Object.assign(
          new Error("controlled nested policy read failure"),
          {
            code: "EIO",
          },
        );
        let allowClose = false;
        let policyHandle: Awaited<ReturnType<typeof fsOpen>> | undefined;
        let policyCloses = 0;
        let sourceCloses = 0;
        openMock.mockImplementation(async (...args) => {
          const handle = await actual.open(...args);
          const path = resolve(String(args[0]));
          const close = handle.close.bind(handle);
          if (path === resolve(source)) {
            vi.spyOn(handle, "close").mockImplementation(async () => {
              sourceCloses += 1;
              await close();
            });
          }
          if (path !== resolve(policy)) return handle;
          policyHandle = handle;
          const read = handle.read.bind(handle);
          vi.spyOn(handle, "read").mockImplementation(async (...readArgs) => {
            if (primary === "physical failure") {
              controller.abort(reason);
              throw reason;
            }
            const result = await read(...readArgs);
            controller.abort(reason);
            return result;
          });
          vi.spyOn(handle, "close").mockImplementation(async () => {
            policyCloses += 1;
            if (!allowClose)
              throw new Error("controlled nested policy close failure");
            await close();
          });
          return handle;
        });

        try {
          const result = await importTree(root, resources, controller.signal);
          if (result.ok)
            throw new Error(
              "Expected nested policy failure with retained cleanup",
            );
          expect(result.error.code).toBe(
            primary === "physical failure" ? "io" : "cancelled",
          );
          expect(result.error.cause).toBe(reason);
          expect(result.error.cleanup).toEqual({
            resources: [policy],
            reason: expect.stringContaining(
              "controlled nested policy close failure",
            ),
          });
          expectUnenteredSubtree(result.error, sourceBytes, excluded);
          expect(policyCloses).toBe(2);
          expect(sourceCloses).toBe(1);
          expect(policyHandle?.fd).toBeGreaterThanOrEqual(0);
          expect(resources.hasPending).toBe(true);
          expect(resources.cleanupResources).toEqual([policy]);

          allowClose = true;
          await resources.retryCleanup();
          expect(policyCloses).toBe(3);
          expect(sourceCloses).toBe(1);
          expect(policyHandle?.fd).toBe(-1);
          expect(resources.hasPending).toBe(false);
          expect(resources.cleanupResources).toEqual([]);
        } finally {
          allowClose = true;
          await resources.close();
        }
      },
    );
  },
);
