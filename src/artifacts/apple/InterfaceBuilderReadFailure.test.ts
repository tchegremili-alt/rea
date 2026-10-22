import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { ArtifactReaderFailure } from "../ArtifactReader.js";
import { DirectoryArtifactReader } from "../DirectoryArtifactReader.js";
import { analyzeInterfaceBuilderBundle } from "./InterfaceBuilderAnalysis.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

const archive = (content: string) =>
  `<?xml version="1.0"?><plist version="1.0"><dict><key>$archiver</key><string>NSKeyedArchiver</string><key>$objects</key><array><string>$null</string><dict><key>$class</key><dict><key>CF$UID</key><integer>2</integer></dict><key>title</key><string>${content}</string></dict><dict><key>$classname</key><string>NSButton</string><key>$classes</key><array><string>NSButton</string><string>NSObject</string></array></dict></array><key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict></dict></plist>`;

const createBundle = async (filename: string, bytes: Buffer) => {
  const root = await createTestTempDirectory("rea-ib-read-failure-");
  const bundle = join(root, "Example.app");
  await mkdir(bundle);
  const path = join(bundle, filename);
  await writeFile(path, bytes);
  return { bundle, path, bytes };
};

const analyze = (bundlePath: string) =>
  analyzeInterfaceBuilderBundle({
    bundlePath,
    targetSha256: "a".repeat(64),
  });

it("decodes a readable document before any failure is injected", async () => {
  const bytes = Buffer.from(archive("Build"));
  const { bundle } = await createBundle("Panel.nib", bytes);

  const result = await analyze(bundle);

  expect(result.documents).toHaveLength(1);
  expect(result.documents[0]?.archive_sha256).toBe(
    createHash("sha256").update(bytes).digest("hex"),
  );
});

it("propagates a changed document instead of reporting an invalid archive", async () => {
  const bytes = Buffer.from(archive("Build"));
  const { bundle, path } = await createBundle("Panel.nib", bytes);
  const open = DirectoryArtifactReader.prototype.open;
  const original = await readFile(path);
  const spy = vi
    .spyOn(DirectoryArtifactReader.prototype, "open")
    .mockImplementation(async function (
      this: DirectoryArtifactReader,
      entry: Parameters<typeof open>[0],
      signal: Parameters<typeof open>[1],
    ) {
      // Replace the selected name with byte-identical content on a new inode so
      // the real reader's identity check fires, without simulating the reader.
      if (entry.path.endsWith("Panel.nib")) {
        await rename(path, `${path}.original`);
        await writeFile(path, original);
      }
      return open.call(this, entry, signal);
    });
  try {
    await expect(analyze(bundle)).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      reason: "integrity",
      message: expect.stringContaining("changed before open"),
    });
  } finally {
    spy.mockRestore();
  }
});

it("propagates an unreadable document instead of reporting an invalid archive", async () => {
  const { bundle } = await createBundle(
    "Panel.nib",
    Buffer.from(archive("Build")),
  );
  const open = DirectoryArtifactReader.prototype.open;
  const spy = vi
    .spyOn(DirectoryArtifactReader.prototype, "open")
    .mockImplementation((entry, signal) => {
      if (entry.path.endsWith("Panel.nib"))
        return Promise.reject(
          new ArtifactReaderFailure(
            "io",
            "Could not open entry at Contents/Resources/Panel.nib (EACCES): permission denied",
          ),
        );
      return open.call(DirectoryArtifactReader.prototype, entry, signal);
    });
  try {
    await expect(analyze(bundle)).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      reason: "io",
      message: expect.stringContaining("EACCES"),
    });
  } finally {
    spy.mockRestore();
  }
});

it("still reports genuinely malformed archive bytes as invalid coverage", async () => {
  const { bundle } = await createBundle(
    "Panel.nib",
    Buffer.from("<plist><dict><key>broken</key><string>unterminated</dict>"),
  );

  const result = await analyze(bundle);

  expect(result.documents).toEqual([]);
  expect(result.graph.truncated).toBe(true);
  expect(result.graph.coverage).toContainEqual(
    expect.objectContaining({
      facet: "archive_decode",
      status: "partial",
      reason: "one_or_more_archives_invalid",
    }),
  );
});
