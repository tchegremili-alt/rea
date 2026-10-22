import { describe, expect, it } from "vitest";

import { jsonParts } from "../domain/jsonSerialization.js";

import {
  projectReferenceSourceImportError,
  type ReferenceSourceImportError,
} from "./ReferenceSourceImportTypes.js";
import type { ReferenceSourceRead } from "../reference/ReferenceSourceReaderTypes.js";

describe("reference-source import error projection", () => {
  it("preserves primary evidence with category-specific recovery guidance", () => {
    const expectedCategories = {
      cancelled: "cancelled",
      "invalid-root": "invalid_input",
      unsupported: "unsupported_host",
      io: "execution_failure",
      parse: "execution_failure",
    } as const;
    for (const [code, category] of Object.entries(expectedCategories)) {
      const projected = projectReferenceSourceImportError({
        tag: "reference-source-import",
        code: code as ReferenceSourceImportError["code"],
        message: "EIO while reading /selected/source/src/main.ts",
      });
      expect(projected.category).toBe(category);
      expect(projected.message).toContain(
        "EIO while reading /selected/source/src/main.ts",
      );
      expect(projected.message).toMatch(
        /try again|when ready|Check that|REA on Linux/u,
      );
    }
  });

  it("preserves cancellation, partial facts, and cleanup diagnostics", () => {
    const bytes = Buffer.from("export const observed = true;\n");
    const partial: ReferenceSourceRead = {
      root: "/selected/source",
      entries: [
        {
          status: "read",
          kind: "file",
          path: "src/main.ts",
          bytes,
          size: bytes.length,
        },
      ],
      bytesRead: bytes.length,
      limitations: [],
    };
    const projected = projectReferenceSourceImportError({
      tag: "reference-source-import",
      code: "cancelled",
      message: "Traversal cancelled after reading src/main.ts",
      cleanup: {
        reason: "directory close rejected",
        resources: ["/selected/source"],
      },
      partial,
    });

    expect(projected).toMatchObject({
      category: "cancelled",
      message: expect.stringContaining(
        "Traversal cancelled after reading src/main.ts",
      ),
      cleanup: {
        reason: "directory close rejected",
        resources: ["/selected/source"],
      },
      partial: {
        root: "/selected/source",
        entries: [
          { path: "src/main.ts", bytes: { type: "Buffer", data: [...bytes] } },
        ],
      },
    });
    expect(projected.message).toContain("Cleanup failed during import");
    expect(projected.message).toContain("directory close rejected");
    expect(projected.message).toContain("/selected/source");
    expect(projected.message).not.toContain("remains unconfirmed");
  });
});

it.each([
  { label: "Buffer", bytes: Buffer.from([0, 255, 195, 40, 128]) },
  { label: "Uint8Array", bytes: new Uint8Array([0, 255, 195, 40, 128]) },
  {
    label: "Buffer subarray",
    bytes: Buffer.from([11, 0, 255, 195, 40, 128, 22]).subarray(1, 6),
  },
  {
    label: "Uint8Array subarray",
    bytes: new Uint8Array([11, 0, 255, 195, 40, 128, 22]).subarray(1, 6),
  },
])(
  "serializes exact $label bytes without mutating retained observations",
  ({ bytes }) => {
    const entry = Object.freeze({
      status: "read" as const,
      kind: "file" as const,
      path: "observed.bin",
      bytes,
      size: bytes.length,
    });
    const failedDirectory = Object.freeze({
      status: "failed" as const,
      kind: "directory" as const,
      path: "nested",
      code: "io" as const,
      message: "Nested policy is not valid UTF-8",
    });
    const partial: ReferenceSourceRead = Object.freeze({
      root: "/selected/source",
      rootFailure: {
        code: "io" as const,
        message: "Root enumeration incomplete",
      },
      entries: Object.freeze([entry, failedDirectory]),
      bytesRead: bytes.length,
      limitations: ["Remaining files were not read"],
    });
    const error: ReferenceSourceImportError = Object.freeze({
      tag: "reference-source-import",
      code: "io",
      message: "Nested policy is not valid UTF-8",
      partial,
    });
    const originalOffset = bytes.byteOffset;
    const originalBuffer = bytes.buffer;
    const projected = projectReferenceSourceImportError(error);
    const serialized = [...jsonParts(projected)].join("");

    expect(JSON.parse(serialized)).toEqual(projected);
    expect(projected.partial).toEqual({
      ...partial,
      entries: [
        { ...entry, bytes: { type: "Buffer", data: [0, 255, 195, 40, 128] } },
        failedDirectory,
      ],
    });
    expect(error.partial).toBe(partial);
    expect(partial.entries[0]).toBe(entry);
    expect(entry.bytes).toBe(bytes);
    expect([...bytes]).toEqual([0, 255, 195, 40, 128]);
    expect(bytes.byteOffset).toBe(originalOffset);
    expect(bytes.buffer).toBe(originalBuffer);
  },
);
