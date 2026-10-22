import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

describe.skipIf(process.platform === "win32")(
  "reference ignore BOM handling",
  () => {
    it.each([
      {
        directory: "pkg",
        rule: "!keep.tmp",
        name: "keep.tmp",
        excluded: false,
      },
      { directory: "pkg", rule: "#comment", name: "#comment", excluded: false },
      { directory: ".", rule: "#comment", name: "#comment", excluded: false },
      { directory: "pkg", rule: "drop.ts", name: "drop.ts", excluded: true },
    ])(
      "classifies the BOM-prefixed $rule in $directory",
      async ({ directory, rule, name, excluded }) => {
        const root = await createTestTempDirectory("rea-reference-ignore-bom-");
        if (directory !== ".") {
          await mkdir(join(root, directory));
          await writeFile(join(root, ".gitignore"), "*.tmp\n");
        }
        await writeFile(join(root, directory, ".gitignore"), `\uFEFF${rule}\n`);
        await writeFile(join(root, directory, name), "source\n");
        const path = directory === "." ? name : `${directory}/${name}`;
        const result = await importReferenceSource({
          root,
          caller: "bom-test",
          policy: { secretPatterns: [] },
        });
        if (!result.ok) throw result.error;
        expect(
          result.value.entries.some(
            (entry) => entry.path === path && entry.kind === "file",
          ),
        ).toBe(!excluded);
        if (excluded)
          expect(result.value.exclusions).toContainEqual(
            expect.objectContaining({
              path,
              reason: "project-ignored",
              pattern: rule,
            }),
          );
        else
          expect(
            result.value.exclusions.some((entry) => entry.path === path),
          ).toBe(false);
      },
    );

    it.each([".", "pkg"])(
      "preserves literal U+FEFF after the start of %s's policy",
      async (directory) => {
        const root = await createTestTempDirectory(
          "rea-reference-ignore-literal-bom-",
        );
        if (directory !== ".") await mkdir(join(root, directory));
        await writeFile(
          join(root, directory, ".gitignore"),
          "# header\n*.tmp\n!\uFEFFkeep.tmp\n\uFEFFliteral.ts\n\uFEFF\n",
        );
        for (const name of [
          "\uFEFF",
          "keep.tmp",
          "\uFEFFkeep.tmp",
          "literal.ts",
          "\uFEFFliteral.ts",
        ])
          await writeFile(join(root, directory, name), "source\n");
        const path = (name: string) =>
          directory === "." ? name : `${directory}/${name}`;
        const result = await importReferenceSource({
          root,
          caller: "bom-test",
          policy: { secretPatterns: [] },
        });
        if (!result.ok) throw result.error;
        expect(
          result.value.entries
            .filter(({ kind }) => kind === "file")
            .map(({ path }) => path),
        ).toEqual([
          path(".gitignore"),
          path("literal.ts"),
          path("\uFEFFkeep.tmp"),
        ]);
        expect(
          result.value.exclusions.map(({ path, reason, ...rest }) => ({
            path,
            reason,
            pattern: "pattern" in rest ? rest.pattern : undefined,
          })),
        ).toEqual([
          {
            path: path("keep.tmp"),
            reason: "project-ignored",
            pattern: "*.tmp",
          },
          {
            path: path("\uFEFF"),
            reason: "project-ignored",
            pattern: "\uFEFF",
          },
          {
            path: path("\uFEFFliteral.ts"),
            reason: "project-ignored",
            pattern: "\uFEFFliteral.ts",
          },
        ]);
      },
    );
  },
);
