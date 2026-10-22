import { stat } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

// Host filesystems cannot fail chmod on one new directory on demand; every
// other creation step runs on the real filesystem.
const failChmodFor = vi.hoisted(() => ({
  path: undefined as string | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    chmod: (path: Parameters<typeof actual.chmod>[0], mode: number) =>
      path === failChmodFor.path
        ? Promise.reject(Object.assign(new Error("denied"), { code: "EPERM" }))
        : actual.chmod(path, mode),
  };
});

const { DecompileExport } =
  await import("../../../src/application/decompileDirectory/exportTree.js");

const identity = {
  targetSha256: "ab".repeat(32),
  provider: { id: "fixture", name: "Fixture", version: "1" },
  analysisProfileDigest: "cd".repeat(32),
  layout: "address" as const,
};

afterEach(() => {
  failChmodFor.path = undefined;
});

describe("decompile export creation", () => {
  it("removes the output directory it created when it cannot be made private", async () => {
    const parent = await createTestTempDirectory("rea-decompile-create-");
    const root = join(parent, "out");
    failChmodFor.path = root;

    const opened = await DecompileExport.open({
      placement: { mode: "create", root },
      identity,
    });

    expect(opened.ok).toBe(false);
    if (opened.ok) return;
    expect(opened.error.userMessage).toContain("could not be secured");
    // A fresh export can be retried at the same path.
    await expect(stat(root)).rejects.toMatchObject({ code: "ENOENT" });
    failChmodFor.path = undefined;
    const retried = await DecompileExport.open({
      placement: { mode: "create", root },
      identity,
    });
    expect(retried.ok).toBe(true);
    if (retried.ok) expect((await retried.value.close()).ok).toBe(true);
  });
});
