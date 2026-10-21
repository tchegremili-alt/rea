import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { parseBinaryTarget } from "../application/BinaryTargetResolver.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { buildGamecubeDol } from "../domain/gamecubeDol.fixture.js";
import type { DolHeader } from "../domain/gamecubeDol.js";
import type { NativeLoadImageObservation } from "../domain/native/nativeLoadImage.js";
import { attestGhidraDolLoadImage } from "./GhidraDolLoadImage.js";
import type { NativeLoadImage } from "../domain/native/nativeLoadImage.js";
import type { Result } from "../domain/result.js";

type DolTarget = Extract<BinaryTarget, { format: "gamecube-dol" }>;
type DolImage = Extract<NativeLoadImage, { format: "gamecube-dol" }>;

/** Unwrap a successful DOL attestation; the union also admits other formats. */
const attestedDol = (result: Result<NativeLoadImage, string>): DolImage => {
  if (!result.ok) throw new Error(result.error);
  if (result.value.status === "unsupported")
    throw new Error(result.value.reason);
  if (result.value.format !== "gamecube-dol")
    throw new Error("Expected a gamecube-dol attestation");
  return result.value;
};

const sha = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");
const hex = (value: number): string => `0x${value.toString(16)}`;

// Data at 0x80010000 (16 bytes) with BSS 0x8000fff8..0x80010018: the BSS
// overlaps the data, so only the two 8-byte edges are uninitialized gaps.
const DATA_ADDRESS = 0x8001_0000;
const BSS_ADDRESS = 0x8000_fff8;
const BSS_SIZE = 0x20;
const EXPECTED_GAPS = [
  { start: "0x8000fff8", end: "0x8000ffff", length: 8 },
  { start: "0x80010010", end: "0x80010017", length: 8 },
];

const overlappingDol = (): Buffer =>
  buildGamecubeDol({
    data: { address: DATA_ADDRESS, bytes: Buffer.alloc(16, 0x11) },
    bss: { address: BSS_ADDRESS, size: BSS_SIZE },
  });

const dolTarget = async (bytes: Buffer): Promise<DolTarget> => {
  const directory = await createTestTempDirectory("rea-dol-attest-");
  await writeFile(join(directory, "game.dol"), bytes);
  const parsed = await parseBinaryTarget("game.dol", {
    cwd: directory,
    formatHint: "gamecube-dol",
  });
  if (!parsed.ok) throw parsed.error;
  if (parsed.value.format !== "gamecube-dol")
    throw new Error("Expected a gamecube-dol target");
  return parsed.value;
};

/** Observations Ghidra would report for a correct import of `bytes`. */
const observationsFor = (
  bytes: Buffer,
  dol: DolHeader,
  language: { readonly id: string; readonly cspec: string } = {
    id: "PowerPC:BE:32:default",
    cspec: "default",
  },
): NativeLoadImageObservation => ({
  executable_format: "Raw Binary",
  language_id: language.id,
  compiler_spec_id: language.cspec,
  image_base: "0x0",
  default_address_space: "ram",
  source_files: [
    {
      name: "game.dol",
      size: bytes.length,
      original_sha256: sha(bytes),
      modified_sha256: sha(bytes),
    },
  ],
  mappings: [
    ...dol.sections.map((section) => ({
      block: `.${section.kind}${section.index}`,
      start: hex(section.address),
      end: hex(section.address + section.size - 1),
      address_space: "ram",
      initialized: true,
      loaded: true,
      overlay: false,
      length: section.size,
      source_file_index: 0,
      file_offset: section.fileOffset,
      sha256: sha(
        bytes.subarray(section.fileOffset, section.fileOffset + section.size),
      ),
    })),
    ...EXPECTED_GAPS.map((gap) => ({
      block: "bss",
      start: gap.start,
      end: gap.end,
      address_space: "ram",
      initialized: false,
      loaded: true,
      overlay: false,
      length: gap.length,
      source_file_index: null,
      file_offset: null,
      sha256: null,
    })),
  ],
  relocations: [],
  entry_points: [hex(dol.entryPoint)],
  entry_context: [],
});

const checkNamed = (
  checks: readonly { readonly name: string; readonly matched: boolean }[],
  name: string,
) => checks.find((check) => check.name === name);

describe("GameCube DOL load-image attestation", () => {
  it("verifies file-backed sections and only the BSS gaps outside data", async () => {
    const bytes = overlappingDol();
    const target = await dolTarget(bytes);
    expect(target.dol.bssOverlaps).toEqual([0]);

    const result = attestGhidraDolLoadImage(
      bytes,
      target,
      observationsFor(bytes, target.dol),
      undefined,
    );
    expect(result).toMatchObject({
      ok: true,
      value: {
        status: "verified",
        format: "gamecube-dol",
        architecture: "powerpc",
        entry: { address: "0x80003100" },
        bss: { address: "0x8000fff8", size: "0x20" },
      },
    });
    const image = attestedDol(result);
    expect(image.sections).toHaveLength(2);
    expect(image.checks.every((check) => check.matched)).toBe(true);
    expect(checkNamed(image.checks, "bss_mappings")).toMatchObject({
      matched: true,
      expected: EXPECTED_GAPS,
      observed: EXPECTED_GAPS,
    });
    expect(
      checkNamed(image.checks, "initialized_unbacked_mappings"),
    ).toMatchObject({ matched: true, observed: 0 });
  });

  it("flags a file-backed mapping whose sha256 differs from its section bytes", async () => {
    const bytes = overlappingDol();
    const target = await dolTarget(bytes);
    const observations = observationsFor(bytes, target.dol);
    const dataMapping = observations.mappings.find(
      (mapping) => mapping.block === ".data0",
    );
    if (dataMapping === undefined) throw new Error("Missing data mapping");
    dataMapping.sha256 = "0".repeat(64);

    const result = attestGhidraDolLoadImage(
      bytes,
      target,
      observations,
      undefined,
    );
    expect(result).toMatchObject({
      ok: true,
      value: { status: "mismatch" },
    });
    const image = attestedDol(result);
    expect(checkNamed(image.checks, "file_backed_mappings")).toMatchObject({
      matched: false,
    });
    expect(checkNamed(image.checks, "bss_mappings")).toMatchObject({
      matched: true,
    });
  });

  it("flags an initialized BSS mapping that covers the data section", async () => {
    const bytes = overlappingDol();
    const target = await dolTarget(bytes);
    const observations = observationsFor(bytes, target.dol);
    // Ghidra reporting one uninitialized block over the whole BSS, data included.
    observations.mappings = observations.mappings.filter(
      (mapping) => mapping.block !== "bss",
    );
    observations.mappings.push({
      block: "bss",
      start: "0x8000fff8",
      end: "0x80010017",
      address_space: "ram",
      initialized: false,
      loaded: true,
      overlay: false,
      length: BSS_SIZE,
      source_file_index: null,
      file_offset: null,
      sha256: null,
    });

    const result = attestGhidraDolLoadImage(
      bytes,
      target,
      observations,
      undefined,
    );
    expect(result).toMatchObject({ ok: true, value: { status: "mismatch" } });
    const image = attestedDol(result);
    expect(checkNamed(image.checks, "bss_mappings")).toMatchObject({
      matched: false,
      expected: EXPECTED_GAPS,
    });
  });

  it("flags a stock-language import when the caller selected no override", async () => {
    const bytes = overlappingDol();
    const target = await dolTarget(bytes);
    const result = attestGhidraDolLoadImage(
      bytes,
      target,
      observationsFor(bytes, target.dol, {
        id: "PowerPC:BE:32:Gekko_Broadway",
        cspec: "default",
      }),
      undefined,
    );
    expect(result).toMatchObject({ ok: true, value: { status: "mismatch" } });
    const image = attestedDol(result);
    expect(checkNamed(image.checks, "language_id")).toMatchObject({
      matched: false,
      expected: "PowerPC:BE:32:default",
      observed: "PowerPC:BE:32:Gekko_Broadway",
    });
  });

  it("verifies the Broadway override only when the import used that language", async () => {
    const bytes = overlappingDol();
    const target = await dolTarget(bytes);
    const override = { languageId: "PowerPC:BE:32:Gekko_Broadway" };
    const broadway = observationsFor(bytes, target.dol, {
      id: "PowerPC:BE:32:Gekko_Broadway",
      cspec: "default",
    });
    expect(
      attestGhidraDolLoadImage(bytes, target, broadway, override),
    ).toMatchObject({ ok: true, value: { status: "verified" } });

    // Same override, but Ghidra imported with the stock language instead.
    expect(
      attestGhidraDolLoadImage(
        bytes,
        target,
        observationsFor(bytes, target.dol),
        override,
      ),
    ).toMatchObject({ ok: true, value: { status: "mismatch" } });
  });

  it("refuses bytes that do not match the admitted target digest", async () => {
    const bytes = overlappingDol();
    const target = await dolTarget(bytes);
    expect(
      attestGhidraDolLoadImage(
        Buffer.concat([bytes, Buffer.from([0])]),
        target,
        observationsFor(bytes, target.dol),
        undefined,
      ),
    ).toEqual({
      ok: false,
      error: "Ghidra DOL snapshot digest does not match the admitted target",
    });
  });
});
