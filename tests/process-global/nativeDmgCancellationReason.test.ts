import { describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  reason: undefined as unknown,
}));

vi.mock("../../src/process/ExecFileOutput.js", async (importOriginal) => {
  const actual =
    await importOriginal<
      typeof import("../../src/process/ExecFileOutput.js")
    >();
  return {
    ...actual,
    execFileOutput: vi.fn(async () => {
      throw new actual.ExecFileOutputCancelledError(state.reason);
    }),
  };
});

import { ArtifactReaderFailure } from "../../src/artifacts/ArtifactReader.js";
import { NativeDmgArtifactReader } from "../../src/artifacts/NativeDmgArtifactReader.js";

describe("NativeDmgArtifactReader cancellation provenance", () => {
  it("retains the caller reason when the command owner observes cancellation", async () => {
    const reason = { requested: "stop DMG" };
    state.reason = reason;
    const reader = new NativeDmgArtifactReader("fixture.dmg", {});
    try {
      const failure: unknown = await reader
        .entries(new AbortController().signal)
        [Symbol.asyncIterator]()
        .next()
        .catch((cause: unknown) => cause);
      expect(failure).toBeInstanceOf(ArtifactReaderFailure);
      if (!(failure instanceof ArtifactReaderFailure))
        throw new Error("Expected DMG cancellation");
      expect(failure.reason).toBe("cancelled");
      expect(failure.cancellation?.reason).toBe(reason);
      expect(failure.cause).toBe(reason);
    } finally {
      await reader.close().catch(() => undefined);
    }
  });
});
