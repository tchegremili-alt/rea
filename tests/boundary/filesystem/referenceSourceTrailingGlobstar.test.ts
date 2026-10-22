import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

const sourcePaths = [
  "direct.ts",
  "foo/direct.ts",
  "foo/child/child.ts",
  "foo/child/bar/bar.ts",
  "foo/bar/bar.ts",
  "foo/**/literal.ts",
  "foo/*wow/literal.ts",
  "foo/ /space.ts",
  "other/foo/direct.ts",
  "other/foo/child/child.ts",
];
const fooChildren = ["foo/ ", "foo/**", "foo/*wow", "foo/bar", "foo/child"];
const directoryPatterns = [
  "foo/**/",
  "/foo/**/",
  "foo/**/   ",
  "foo/**/**/",
  "foo/**/**/**/",
];
const scenarios = [
  ...directoryPatterns.map((pattern) => ({
    name: `descendants of ${JSON.stringify(pattern)}`,
    rules: pattern,
    pattern,
    excluded: fooChildren,
  })),
  ...directoryPatterns.map((pattern) => ({
    name: `a parent excluded before !${JSON.stringify(pattern)}`,
    rules: `foo/\n!${pattern}`,
    pattern: "foo/",
    excluded: ["foo", "other/foo"],
  })),
  {
    name: "leading and trailing globstars",
    rules: "**/foo/**/",
    pattern: "**/foo/**/",
    excluded: [...fooChildren, "other/foo/child"],
  },
  {
    name: "a globstar between named path components",
    rules: "foo/**/bar/",
    pattern: "foo/**/bar/",
    excluded: ["foo/bar", "foo/child/bar"],
  },
  {
    name: "escaped globstar characters",
    rules: "foo/\\*\\*/",
    pattern: "foo/\\*\\*/",
    excluded: ["foo/**"],
  },
  {
    name: "an escaped star followed by a wildcard",
    rules: "foo/\\**/",
    pattern: "foo/\\**/",
    excluded: ["foo/**", "foo/*wow"],
  },
  {
    name: "an escaped space after a globstar separator",
    rules: "foo/**/\\ ",
    pattern: "foo/**/\\ ",
    excluded: ["foo/ "],
  },
];

describe.skipIf(process.platform === "win32")(
  "reference ignore trailing directory globstars",
  () => {
    describe.each([
      { scope: "root", prefix: "" },
      { scope: "nested", prefix: "packages/pkg/" },
    ])("$scope policies", ({ prefix }) => {
      it.each(scenarios)(
        "preserves $name",
        async ({ rules, pattern, excluded }) => {
          const root = await createTestTempDirectory(
            "rea-reference-trailing-globstar-",
          );
          const policyPath = `${prefix}.gitignore`;
          const files = [".gitignore", ...sourcePaths];
          for (const path of files) {
            const absolute = join(root, prefix + path);
            await mkdir(dirname(absolute), { recursive: true });
            await writeFile(
              absolute,
              path === ".gitignore"
                ? `${rules}\n`
                : "export const value = 1;\n",
            );
          }
          const result = await importReferenceSource({
            root,
            caller: "trailing-globstar-test",
            policy: { secretPatterns: [] },
          });
          if (!result.ok) throw result.error;
          expect(result.value.exclusions).toEqual(
            excluded.map((path) => ({
              path: prefix + path,
              entry_kind: "directory",
              reason: "project-ignored",
              pattern,
              policy_path: policyPath,
            })),
          );
          expect(
            result.value.entries
              .filter(({ kind }) => kind === "file")
              .map(({ path }) => path),
          ).toEqual(
            files
              .filter(
                (path) =>
                  !excluded.some((parent) => path.startsWith(`${parent}/`)),
              )
              .map((path) => prefix + path)
              .sort(),
          );
        },
      );
    });
  },
);
