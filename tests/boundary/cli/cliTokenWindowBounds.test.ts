import { join } from "node:path";
import { expect } from "vitest";

import { workspaceCliTest } from "../../support/cli/workspaceCliFixture.js";

workspaceCliTest(
  "rejects incoherent token windows before success or failure rendering",
  async ({ cli, workspace }) => {
    for (const flags of [
      ["--token-limit", "-5"],
      ["--token-limit", "2.5"],
      ["--token-offset", "-100", "--token-limit", "20"],
      ["--token-offset", "2.5", "--token-limit", "5"],
      ["--token-limit=9007199254740992"],
      ["--token-offset=9007199254740992"],
    ]) {
      const result = await cli.run({
        arguments: ["capabilities", "--format", "toon", ...flags],
      });
      expect(result.exitCode, flags.join(" ")).toBe(1);
      expect(result.json).toMatchObject({
        ok: false,
        error: {
          code: "INVALID_TOKEN_WINDOW",
          message: expect.stringContaining("non-negative safe integer"),
        },
      });
      expect(result.stdout).not.toContain("[truncated:");
      expect(result.stderr).toBe("");
    }
    const absent = await cli.run({
      arguments: [
        "inspect-plist",
        join(workspace.root, "absent.plist"),
        "--full-output",
        "--token-limit=-5",
      ],
    });
    expect(absent.exitCode).toBe(1);
    expect(absent.json).toMatchObject({
      ok: false,
      error: { code: "INVALID_TOKEN_WINDOW" },
    });
    expect(absent.stdout).not.toContain("nextOffset");
  },
  60_000,
);

workspaceCliTest(
  "preserves zero, positive, and effective last-value token windows",
  async ({ cli }) => {
    for (const [flags, end] of [
      [["--token-limit", "0"], "0"],
      [["--token-offset=0", "--token-limit=5"], "5"],
      [["--token-limit", "-5", "--token-limit", "5"], "5"],
    ] as const) {
      const result = await cli.run({
        arguments: ["capabilities", "--format", "toon", ...flags],
      });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain(`showing tokens 0–${end}`);
    }
    const structured = await cli.run({
      arguments: ["capabilities", "--json", "--token-limit", "5"],
    });
    expect(structured.exitCode).toBe(1);
    expect(structured.json).toMatchObject({
      ok: false,
      error: { code: "UNSUPPORTED_OUTPUT_COMBINATION" },
    });
  },
  60_000,
);
