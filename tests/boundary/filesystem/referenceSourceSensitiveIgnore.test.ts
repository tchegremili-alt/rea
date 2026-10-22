import { chmod, lstat, mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

const createSourceTree = async () => {
  const root = await createTestTempDirectory("rea-reference-sensitive-ignore-");
  await mkdir(join(root, "pkg"));
  await writeFile(join(root, "pkg/source.ts"), "export const value = 1;\n");
  await writeFile(join(root, "pkg/control.ts"), "export const control = 2;\n");
  return root;
};

describe.skipIf(process.platform === "win32")(
  "sensitive nested reference ignore policies",
  () => {
    it.each([
      { name: "valid exclusion rules", content: "s[o]urce.ts\n" },
      { name: "invalid UTF-8", content: new Uint8Array([0xff, 0xfe]) },
    ])(
      "does not read or apply $name from a sensitive policy",
      async ({ content }) => {
        const root = await createSourceTree();
        await writeFile(join(root, "pkg/.gitignore"), content);

        const result = await importReferenceSource({
          root,
          caller: "sensitive-ignore-test",
          policy: { secretPatterns: ["pkg/.gitignore"] },
        });
        if (!result.ok) throw result.error;

        expect(
          result.value.entries
            .filter(({ kind }) => kind === "file")
            .map(({ path }) => path),
        ).toEqual(["pkg/control.ts", "pkg/source.ts"]);
        expect(result.value.exclusions).toEqual([
          {
            path: "pkg/.gitignore",
            entry_kind: "file",
            reason: "configured-secret",
            pattern: "pkg/.gitignore",
          },
        ]);
        expect(JSON.stringify(result.value)).not.toContain("s[o]urce.ts");
      },
    );

    it.each([
      {
        name: "a negated secret pattern",
        secretPatterns: ["**/.gitignore", "!pkg/.gitignore"],
      },
      {
        name: "a directory-only secret pattern",
        secretPatterns: ["**/.gitignore/"],
      },
    ])(
      "still applies a regular policy permitted by $name",
      async ({ secretPatterns }) => {
        const root = await createSourceTree();
        await writeFile(join(root, "pkg/.gitignore"), "source.ts\n");

        const result = await importReferenceSource({
          root,
          caller: "sensitive-ignore-test",
          policy: { secretPatterns },
        });
        if (!result.ok) throw result.error;

        expect(
          result.value.entries
            .filter(({ kind }) => kind === "file")
            .map(({ path }) => path),
        ).toEqual(["pkg/.gitignore", "pkg/control.ts"]);
        expect(result.value.exclusions).toEqual([
          {
            path: "pkg/source.ts",
            entry_kind: "file",
            reason: "project-ignored",
            pattern: "source.ts",
            policy_path: "pkg/.gitignore",
          },
        ]);
      },
    );

    it("does not read a sensitive directory named .gitignore as a policy", async () => {
      const root = await createSourceTree();
      await mkdir(join(root, "pkg/.gitignore"));
      await writeFile(
        join(root, "pkg/.gitignore/private.ts"),
        new Uint8Array([0xff, 0xfe]),
      );

      const result = await importReferenceSource({
        root,
        caller: "sensitive-ignore-test",
        policy: { secretPatterns: ["**/.gitignore/"] },
      });
      if (!result.ok) throw result.error;

      expect(
        result.value.entries
          .filter(({ kind }) => kind === "file")
          .map(({ path }) => path),
      ).toEqual(["pkg/control.ts", "pkg/source.ts"]);
      expect(result.value.exclusions).toEqual([
        {
          path: "pkg/.gitignore",
          entry_kind: "directory",
          reason: "configured-secret",
          pattern: "**/.gitignore/",
        },
      ]);
    });
  },
);

const permissionChecksUnavailable =
  process.platform === "win32" || process.getuid?.() === 0;

describe.skipIf(permissionChecksUnavailable)(
  "sensitive nested policies with unavailable metadata",
  () => {
    it.each([
      {
        name: "a file secret",
        secretPatterns: ["pkg/.gitignore"],
        excluded: true,
      },
      {
        name: "a directory-only secret",
        secretPatterns: ["pkg/.gitignore/"],
        excluded: true,
      },
      { name: "no secret", secretPatterns: [], excluded: false },
      {
        name: "a negated secret",
        secretPatterns: ["**/.gitignore", "!pkg/.gitignore"],
        excluded: false,
      },
    ])(
      "preserves partial facts when policy metadata is denied with $name",
      async ({ secretPatterns, excluded }) => {
        const root = await createSourceTree();
        const nested = join(root, "pkg");
        const policy = join(nested, ".gitignore");
        const kept = "export const kept = 1;\n";
        await writeFile(join(root, "kept.ts"), kept);
        await writeFile(policy, "source.ts\n");
        await chmod(nested, 0o400);
        try {
          expect((await readdir(nested)).sort()).toEqual([
            ".gitignore",
            "control.ts",
            "source.ts",
          ]);
          await expect(lstat(policy)).rejects.toMatchObject({ code: "EACCES" });

          const result = await importReferenceSource({
            root,
            caller: "sensitive-ignore-metadata-test",
            policy: { secretPatterns },
          });
          if (!excluded) {
            if (result.ok)
              throw new Error("Expected unreadable policy failure");
            expect(result.error.code).toBe("io");
            expect(result.error.cause).toMatchObject({ code: "EACCES" });
            expect(result.error.partial?.entries).toContainEqual(
              expect.objectContaining({
                path: "kept.ts",
                kind: "file",
                status: "read",
                bytes: Buffer.from(kept),
              }),
            );
            expect(
              result.error.partial?.entries.some(({ path }) =>
                path.startsWith("pkg/"),
              ),
            ).toBe(false);
            return;
          }
          if (!result.ok) throw result.error;
          expect(result.value.inventory_state).toBe("partial");
          expect(result.value.exclusions).toEqual([
            {
              path: "pkg/.gitignore",
              entry_kind: "unknown",
              reason: "configured-secret",
              pattern: secretPatterns[0],
            },
          ]);
          expect(result.value.entries).toEqual([
            expect.objectContaining({
              path: "kept.ts",
              kind: "file",
              content_state: "hashed",
            }),
            expect.objectContaining({
              path: "pkg",
              kind: "directory",
              tree_state: "enumerated",
            }),
            ...["pkg/control.ts", "pkg/source.ts"].map((path) =>
              expect.objectContaining({
                path,
                kind: "unknown",
                limitations: [expect.stringContaining("EACCES")],
              }),
            ),
          ]);
        } finally {
          await chmod(nested, 0o700);
        }
      },
    );
  },
);
