import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

const cases = [
  { name: "terminal CR without LF", text: "foo\r" },
  { name: "CRLF", text: "foo\r\n" },
  { name: "two terminal CRs", text: "foo\r\r" },
  { name: "literal CR before CRLF", text: "foo\r\r\n" },
  { name: "embedded literal CR", text: "foo\rbar\n" },
  { name: "negation ending in CR", text: "foo\n!foo\r" },
  { name: "empty final CR line", text: "\r" },
];

describe.skipIf(process.platform === "win32")(
  "project ignore line endings",
  () => {
    for (const nested of [false, true]) {
      it.each(cases)(
        "matches Git traversal for $name (nested=" + nested + ")",
        async ({ text }) => {
          const root = await createTestTempDirectory(
            "rea-reference-ignore-cr-",
          );
          const directory = nested ? "pkg" : ".";
          const prefix = nested ? "pkg/" : "";
          const names = ["foo", "foo\r", "foo\r\r", "foo\rbar", "keep.ts"];
          const paths = names.map((name) => prefix + name);
          await mkdir(join(root, directory), { recursive: true });
          await writeFile(join(root, directory, ".gitignore"), text);
          for (const name of names)
            await writeFile(join(root, directory, name), "source\n");
          const gitOptions = {
            encoding: "utf8" as const,
            env: {
              ...process.env,
              GIT_CONFIG_NOSYSTEM: "1",
              GIT_CONFIG_GLOBAL: "/dev/null",
            },
          };
          const init = spawnSync(
            "git",
            ["init", "--quiet", "--template=", root],
            gitOptions,
          );
          expect(init.status, init.stderr).toBe(0);
          const git = spawnSync(
            "git",
            ["-C", root, "ls-files", "--others", "--exclude-standard", "-z"],
            gitOptions,
          );
          expect(git.status, git.stderr).toBe(0);
          const retained = git.stdout
            .split("\0")
            .filter((path) => paths.includes(path))
            .sort();

          const result = await importReferenceSource({
            root,
            caller: "ignore-cr-test",
            policy: { secretPatterns: [] },
          });
          if (!result.ok) throw result.error;
          expect(
            result.value.entries
              .filter(
                ({ kind, path }) => kind === "file" && paths.includes(path),
              )
              .map(({ path }) => path)
              .sort(),
          ).toEqual(retained);
          for (const path of paths.filter((path) => !retained.includes(path))) {
            expect(result.value.exclusions).toContainEqual({
              path,
              entry_kind: "file",
              reason: "project-ignored",
              pattern: path.slice(prefix.length),
              policy_path: prefix + ".gitignore",
            });
          }
        },
      );
    }

    it("keeps a caller-selected terminal CR literal", async () => {
      const root = await createTestTempDirectory("rea-reference-caller-cr-");
      await writeFile(join(root, "foo"), "retained\n");
      await writeFile(join(root, "foo\r"), "excluded\n");
      const result = await importReferenceSource({
        root,
        caller: "caller-cr-test",
        policy: { secretPatterns: ["foo\r"] },
      });
      if (!result.ok) throw result.error;
      expect(result.value.entries.map(({ path }) => path)).toContain("foo");
      expect(result.value.entries.map(({ path }) => path)).not.toContain(
        "foo\r",
      );
      expect(result.value.exclusions).toContainEqual({
        path: "foo\r",
        entry_kind: "file",
        reason: "configured-secret",
        pattern: "foo\r",
      });
    });
  },
);
