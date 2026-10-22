import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

import { ArtifactProvider } from "../../../../src/artifacts/ArtifactProvider.js";
import { artifactInventoryResultSchema } from "../../../../src/domain/artifactGraph.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";

describe("artifact directory inventory", () => {
  it("inventories app trees deterministically without following symlinks", async () => {
    const root = await createTestTempDirectory("rea-artifacts-");
    const app = join(root, "Fixture.app");
    await mkdir(join(app, "Contents", "Resources"), { recursive: true });
    await mkdir(join(app, "Contents", "MacOS"), { recursive: true });
    await mkdir(join(app, "Contents", "Frameworks", "Fixture.framework"), {
      recursive: true,
    });
    const machO = Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]);
    await writeFile(join(app, "Contents", "MacOS", "Fixture"), machO, {
      mode: 0o755,
    });
    await writeFile(
      join(app, "Contents", "Frameworks", "Fixture.framework", "Fixture"),
      machO,
    );
    await writeFile(join(app, "Contents", "Resources", "main.js"), "main();\n");
    await writeFile(join(app, "Contents", "Resources", "main.js.MAP"), "{}\n");
    await symlink("/etc/passwd", join(app, "Contents", "Resources", "outside"));
    const client = new ArtifactProvider(process.env).createClient(
      target(app, "directory"),
    );
    const input = {};
    const first = await client.execute("inventory_artifact", input);
    const second = await client.execute("inventory_artifact", input);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    const left = artifactInventoryResultSchema.parse(first.value.result);
    const right = artifactInventoryResultSchema.parse(second.value.result);
    expect(left.manifest).toEqual(right.manifest);
    expect(left.occurrences.map(({ artifact_kind }) => artifact_kind)).toEqual(
      expect.arrayContaining([
        "executable",
        "framework",
        "javascript",
        "source-map",
      ]),
    );
    expect(
      left.occurrences.find(({ logical_path: path }) =>
        path.endsWith("outside"),
      ),
    ).toMatchObject({ artifact_id: null, entry_kind: "symlink" });
    const script = left.occurrences.find(({ logical_path: path }) =>
      path.endsWith("main.js"),
    );
    const sourceMap = left.occurrences.find(({ logical_path: path }) =>
      path.endsWith("main.js.MAP"),
    );
    expect(left.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          relation: "maps-source",
          parent_artifact_id: script?.artifact_id,
          occurrence_id: sourceMap?.occurrence_id,
        }),
      ]),
    );
  });

  it("does not map a source map to a directory container and preserves parent/child containment", async () => {
    const root = await createTestTempDirectory("rea-artifacts-");
    const app = join(root, "Fixture.app");
    const dirNamedJs = join(app, "Contents", "Resources", "main.js");
    await mkdir(dirNamedJs, { recursive: true });
    await writeFile(join(dirNamedJs, "child.js"), "child();\n");
    await writeFile(join(app, "Contents", "Resources", "main.js.map"), "{}\n");

    const client = new ArtifactProvider(process.env).createClient(
      target(app, "directory"),
    );
    const result = await client.execute("inventory_artifact", {});
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const inventory = artifactInventoryResultSchema.parse(result.value.result);
    const dirOccurrence = inventory.occurrences.find(({ logical_path }) =>
      logical_path.endsWith("Resources/main.js"),
    );
    const childOccurrence = inventory.occurrences.find(({ logical_path }) =>
      logical_path.endsWith("Resources/main.js/child.js"),
    );
    const mapOccurrence = inventory.occurrences.find(({ logical_path }) =>
      logical_path.endsWith("Resources/main.js.map"),
    );
    const resourcesOccurrence = inventory.occurrences.find(({ logical_path }) =>
      logical_path.endsWith("Contents/Resources"),
    );

    expect(dirOccurrence?.artifact_kind).toBe("container");
    expect(mapOccurrence?.artifact_kind).toBe("source-map");

    expect(inventory.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          relation: "contains",
          parent_artifact_id: resourcesOccurrence?.artifact_id,
          occurrence_id: dirOccurrence?.occurrence_id,
        }),
      ]),
    );

    expect(inventory.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          relation: "contains",
          parent_artifact_id: dirOccurrence?.artifact_id,
          occurrence_id: childOccurrence?.occurrence_id,
        }),
      ]),
    );

    expect(inventory.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          relation: "contains",
          parent_artifact_id: resourcesOccurrence?.artifact_id,
          occurrence_id: mapOccurrence?.occurrence_id,
        }),
      ]),
    );

    expect(inventory.edges).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          relation: "maps-source",
          parent_artifact_id: dirOccurrence?.artifact_id,
        }),
      ]),
    );
  });
});

const target = (
  path: string,
  format: Extract<BinaryTarget, { kind: "archive" }>["format"] | "directory",
): BinaryTarget => ({
  path,
  sourcePath: path,
  sha256: "0".repeat(64),
  kind: "archive",
  format: format === "directory" ? "asar" : format,
});
