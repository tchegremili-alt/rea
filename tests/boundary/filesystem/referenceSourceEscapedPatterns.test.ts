import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
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

const gitInventory = (root: string): string[] => {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
  );
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  const git = (args: string[]): string => {
    const result = spawnSync(
      "git",
      ["-C", root, "-c", "core.excludesFile=/dev/null", ...args],
      { env, encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    return result.stdout;
  };
  git(["init", "--quiet", "--template="]);
  git(["config", "core.ignorecase", "false"]);
  return git(["ls-files", "--others", "--exclude-standard", "-z"])
    .split("\0")
    .filter(Boolean)
    .sort();
};

const literalCases = [
  {
    pattern: String.raw`foo\*`,
    ignored: "foo*",
    kept: ["foo.ts", "foo/keep.ts"],
  },
  {
    pattern: String.raw`question\?`,
    ignored: "question?",
    kept: ["questionX", "questionDir/inside.ts"],
  },
  {
    pattern: String.raw`opening\[value\]`,
    ignored: "opening[value]",
    kept: ["openingv", "openingDir/keep.ts"],
  },
  {
    pattern: String.raw`slash\\`,
    ignored: "slash\\",
    kept: ["slash", "slashX"],
  },
  {
    pattern: String.raw`odd\\\*`,
    ignored: "odd\\*",
    kept: ["odd\\X", "oddX"],
  },
  {
    pattern: String.raw`even\\*`,
    ignored: "even\\foo",
    kept: ["evenfoo", "even"],
  },
  {
    pattern: String.raw`four\\\\?`,
    ignored: "four\\\\X",
    kept: ["four\\X", "four\\\\", "fourX"],
  },
  {
    pattern: String.raw`plain\a`,
    ignored: "plaina",
    kept: ["plain\\a", "plainb"],
  },
  {
    pattern: String.raw`mix\**`,
    ignored: "mix*more",
    kept: ["mixmore", "mix/keep.ts"],
  },
];

const syntaxCases = [
  {
    pattern: String.raw`mixed[\?-A]`,
    ignored: "mixed@",
    kept: ["mixedF", "mixed0"],
  },
  {
    pattern: String.raw`letters[a-\z]`,
    ignored: "lettersm",
    kept: ["letters1"],
  },
  {
    pattern: String.raw`descending[\?-0]`,
    ignored: "descending?",
    kept: ["descending0", "descendingA"],
  },
  {
    pattern: String.raw`caret[^-\^]`,
    ignored: "careta",
    kept: ["caret^", "caret-"],
  },
  {
    pattern: String.raw`class[\?\*]`,
    ignored: "class?",
    kept: ["classx"],
  },
  {
    pattern: String.raw`rawclass[?*]`,
    ignored: "rawclass*",
    kept: ["rawclassX"],
  },
  {
    pattern: String.raw`range[a-c]\*`,
    ignored: "rangea*",
    kept: ["ranged*", "rangeaX"],
  },
  {
    pattern: String.raw`negclass[!\?]\*`,
    ignored: "negclassa*",
    kept: ["negclass?*", "negclassaX"],
  },
  {
    pattern: String.raw`slashclass\\[a-c]`,
    ignored: "slashclass\\a",
    kept: ["slashclass\\z", "slashclassa"],
  },
  {
    pattern: String.raw`closing[\]]`,
    ignored: "closing]",
    kept: ["closing[", "closingx"],
  },
  {
    pattern: String.raw`dash[\-a]`,
    ignored: "dash-",
    kept: ["dashb"],
  },
  {
    pattern: String.raw`quoted\/file`,
    ignored: "quoted/file",
    kept: ["quoted/other", "deeper/quoted/file"],
  },
  {
    pattern: "trim\\*   ",
    ignored: "trim*",
    kept: ["trim* ", "trimX"],
  },
  {
    pattern: "space\\*\\  ",
    ignored: "space* ",
    kept: ["space*", "spaceX "],
  },
  {
    pattern: "tab\\*\t",
    ignored: "tab*\t",
    kept: ["tabX\t", "tab* "],
  },
  {
    pattern: String.raw`literal/\*\*/`,
    ignored: "literal/**/inside.ts",
    kept: ["literal/*wow/inside.ts", "literal/wow/inside.ts"],
  },
  {
    pattern: String.raw`tree/\**/`,
    ignored: "tree/*wow/inside.ts",
    kept: ["tree/wow/inside.ts"],
  },
  {
    pattern: String.raw`glob\/**/`,
    ignored: "glob/child/inside.ts",
    kept: ["glob/direct.ts"],
  },
];

describe.skipIf(process.platform === "win32")(
  "reference ignore escaped pattern traversal",
  () => {
    describe.each([
      { scope: "root", prefix: "" },
      { scope: "nested", prefix: "packages/[pkg]/" },
    ])("$scope policies", ({ prefix }) => {
      it.each([
        {
          name: "quoted literals and odd/even escape runs",
          cases: literalCases,
        },
        {
          name: "classes, whitespace and terminal globstars",
          cases: syntaxCases,
        },
      ])("matches Git for $name", async ({ cases }) => {
        const root = await createTestTempDirectory("rea-reference-escaped-");
        const policyPath = `${prefix}.gitignore`;
        const files: Record<string, string> = {
          [policyPath]:
            cases.map(({ pattern }) => pattern).join("\n") + "\ndangling\\\n",
          [`${prefix}dangling\\`]: "invalid terminal escape does not match\n",
          [`${prefix}dangling`]: "invalid terminal escape does not match\n",
        };
        for (const { ignored, kept } of cases)
          for (const path of [ignored, ...kept])
            files[prefix + path] = "export const value = 1;\n";
        await writeTree(root, files);

        const expected = gitInventory(root);
        for (const { ignored, kept } of cases) {
          expect(expected).not.toContain(prefix + ignored);
          for (const path of kept) expect(expected).toContain(prefix + path);
        }
        expect(expected).toContain(prefix + "dangling\\");
        expect(expected).toContain(prefix + "dangling");

        const result = await importReferenceSource({
          root,
          caller: "escaped-ignore-test",
          policy: { secretPatterns: [] },
        });
        if (!result.ok) throw result.error;
        expect(
          result.value.entries
            .filter(({ kind }) => kind === "file")
            .map(({ path }) => path)
            .sort(),
        ).toEqual(expected);
        for (const { pattern, ignored } of cases) {
          // A directory rule records the pruned parent, not each unseen child.
          const exclusion = result.value.exclusions.find(
            ({ path }) =>
              path === prefix + ignored ||
              (prefix + ignored).startsWith(`${path}/`),
          );
          expect(exclusion).toMatchObject({
            reason: "project-ignored",
            pattern,
            policy_path: policyPath,
          });
        }
      });
    });

    it("keeps quoted negations literal across inherited and child policies", async () => {
      const root = await createTestTempDirectory(
        "rea-reference-escaped-negation-",
      );
      await writeTree(root, {
        ".gitignore": "root*\n!root\\*\n",
        "root*": "reopened literal star\n",
        rootOther: "still ignored\n",
        "pkg/.gitignore": "child*\n!child\\*\n",
        "pkg/child*": "reopened literal star\n",
        "pkg/childOther": "still ignored\n",
        "pkg/deeper/.gitignore": "!root\\?\n",
        "pkg/deeper/root?": "child overrides the inherited wildcard\n",
        "pkg/deeper/rootX": "child negation must not reopen other names\n",
        "sibling/root?": "negation is scoped to the child\n",
        "sibling/keep.ts": "retained control\n",
      });
      const expected = gitInventory(root);
      expect(expected).toContain("root*");
      expect(expected).toContain("pkg/child*");
      expect(expected).toContain("pkg/deeper/root?");
      for (const path of [
        "rootOther",
        "pkg/childOther",
        "pkg/deeper/rootX",
        "sibling/root?",
      ])
        expect(expected).not.toContain(path);
      const result = await importReferenceSource({
        root,
        caller: "escaped-ignore-negation-test",
        policy: { secretPatterns: [] },
      });
      if (!result.ok) throw result.error;
      expect(
        result.value.entries
          .filter(({ kind }) => kind === "file")
          .map(({ path }) => path)
          .sort(),
      ).toEqual(expected);
      expect(result.value.exclusions).toContainEqual({
        path: "pkg/childOther",
        entry_kind: "file",
        reason: "project-ignored",
        pattern: "child*",
        policy_path: "pkg/.gitignore",
      });
    });
  },
);
