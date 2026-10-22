import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { DolHeader } from "../domain/gamecubeDol.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  nativeLoadImageSchema,
  type NativeLoadImage,
  type NativeLoadImageCheck,
  type NativeLoadImageObservation,
} from "../domain/native/nativeLoadImage.js";
import { err, ok, type Result } from "../domain/result.js";
import { ghidraDolLanguage } from "./GhidraDolProfile.js";

type DolTarget = Extract<BinaryTarget, { format: "gamecube-dol" }>;
type Range = { readonly start: number; readonly end: number };

/**
 * Digests of the immutable DOL snapshot, streamed by the Ghidra client: whole
 * file identity plus one digest per header section, in `header.sections` order.
 */
export interface DolSnapshotDigests {
  readonly sha256: string;
  readonly bytes: number;
  readonly sectionSha256: readonly string[];
}
const hex = (value: number): string => `0x${value.toString(16)}`;
const byStart = <T extends { readonly start: string }>(left: T, right: T) =>
  Number(BigInt(left.start) - BigInt(right.start));

/** Remove every data range from the BSS range, keeping the uncovered gaps. */
const uncoveredBss = (
  bss: Range,
  dataRanges: readonly Range[],
): readonly Range[] =>
  dataRanges.reduce<readonly Range[]>(
    (gaps, data) =>
      gaps.flatMap((gap) => {
        if (data.end <= gap.start || data.start >= gap.end) return [gap];
        return [
          ...(gap.start < data.start
            ? [{ start: gap.start, end: data.start }]
            : []),
          ...(data.end < gap.end ? [{ start: data.end, end: gap.end }] : []),
        ];
      }),
    bss.end > bss.start ? [bss] : [],
  );

/**
 * Verify the imported DOL against its header: every used section is one
 * initialized, loaded, non-overlay mapping at its load address with the exact
 * file bytes, BSS is only uninitialized gaps outside data sections, and the
 * header entry is an external entry point.
 */
export const attestGhidraDolLoadImage = (
  snapshot: DolSnapshotDigests,
  target: DolTarget,
  observations: NativeLoadImageObservation,
  languageOverride: GhidraLanguageOverride | undefined,
): Result<NativeLoadImage, string> => {
  if (snapshot.sha256 !== target.sha256)
    return err("Ghidra DOL snapshot digest does not match the admitted target");
  const header: DolHeader = target.dol;
  if (snapshot.sectionSha256.length !== header.sections.length)
    return err("Ghidra DOL snapshot section digests do not match the header");
  const language = ghidraDolLanguage(languageOverride);
  const checks: NativeLoadImageCheck[] = [];
  const check = (
    name: string,
    expected: JsonValue,
    observed: JsonValue,
    fileOffset: number | null = null,
    location: string | null = null,
  ): void => {
    checks.push({
      name,
      matched: JSON.stringify(expected) === JSON.stringify(observed),
      expected,
      observed,
      file_offset: fileOffset,
      address: location,
    });
  };

  // Field order is fixed: checks compare serialized values.
  const fileFacts = (mapping: {
    readonly start: string;
    readonly end: string;
    readonly length: number;
    readonly file_offset: number | null;
    readonly sha256: string | null;
    readonly source_file_index: number | null;
    readonly initialized: boolean;
    readonly loaded: boolean;
    readonly overlay: boolean;
    readonly address_space: string;
  }) => ({
    start: mapping.start,
    end: mapping.end,
    length: mapping.length,
    file_offset: mapping.file_offset,
    sha256: mapping.sha256,
    source_file_index: mapping.source_file_index,
    initialized: mapping.initialized,
    loaded: mapping.loaded,
    overlay: mapping.overlay,
    address_space: mapping.address_space,
  });

  const expectedFileMappings = header.sections
    .map((section, index) => {
      return fileFacts({
        start: hex(section.address),
        end: hex(section.address + section.size - 1),
        length: section.size,
        file_offset: section.fileOffset,
        sha256: snapshot.sectionSha256[index] ?? null,
        source_file_index: 0,
        initialized: true,
        loaded: true,
        overlay: false,
        address_space: observations.default_address_space,
      });
    })
    .sort(byStart);
  const observedFileMappings = observations.mappings
    .filter((mapping) => mapping.source_file_index !== null)
    .map((mapping) =>
      fileFacts({
        start: mapping.start,
        end: mapping.end,
        length: mapping.length,
        file_offset: mapping.file_offset,
        sha256: mapping.sha256,
        source_file_index: mapping.source_file_index,
        initialized: mapping.initialized,
        loaded: mapping.loaded,
        overlay: mapping.overlay,
        address_space: mapping.address_space,
      }),
    )
    .sort(byStart);

  const dataRanges = header.sections
    .filter((section) => section.kind === "data")
    .map((section) => ({
      start: section.address,
      end: section.address + section.size,
    }));
  const bssRange = {
    start: header.bss.address,
    end: header.bss.address + header.bss.size,
  };
  const expectedBss = uncoveredBss(bssRange, dataRanges).map((gap) => ({
    start: hex(gap.start),
    end: hex(gap.end - 1),
    length: gap.end - gap.start,
  }));
  const observedBss = observations.mappings
    .filter(
      (mapping) =>
        mapping.source_file_index === null &&
        !mapping.initialized &&
        BigInt(mapping.start) >= BigInt(bssRange.start) &&
        BigInt(mapping.start) < BigInt(bssRange.end),
    )
    .map((mapping) => ({
      start: mapping.start,
      end: mapping.end,
      length: mapping.length,
    }))
    .sort(byStart);

  const source = observations.source_files[0];
  check("executable_format", "Raw Binary", observations.executable_format);
  check("language_id", language.languageId, observations.language_id);
  if (language.compilerSpecId !== undefined)
    check(
      "compiler_spec_id",
      language.compilerSpecId,
      observations.compiler_spec_id,
    );
  check("image_base", "0x0", observations.image_base);
  check("source_file_count", 1, observations.source_files.length);
  check("source_file_size", snapshot.bytes, source?.size ?? null);
  check("original_file_sha256", target.sha256, source?.original_sha256 ?? null);
  check("modified_file_sha256", target.sha256, source?.modified_sha256 ?? null);
  check("file_backed_mappings", expectedFileMappings, observedFileMappings);
  check("bss_mappings", expectedBss, observedBss);
  check(
    "initialized_unbacked_mappings",
    0,
    observations.mappings.filter(
      (mapping) => mapping.initialized && mapping.source_file_index === null,
    ).length,
  );
  check(
    "entry_point",
    hex(header.entryPoint),
    observations.entry_points.find(
      (entry) => entry === hex(header.entryPoint),
    ) ?? null,
  );
  check("relocation_records", [], observations.relocations);
  return ok(
    nativeLoadImageSchema.parse({
      status: checks.every((item) => item.matched) ? "verified" : "mismatch",
      format: "gamecube-dol",
      target_sha256: target.sha256,
      architecture: "powerpc",
      language_id: observations.language_id,
      compiler_spec_id: observations.compiler_spec_id,
      file_bytes: snapshot.bytes,
      entry: { address: hex(header.entryPoint) },
      sections: header.sections.map((section) => ({
        kind: section.kind,
        index: section.index,
        file_offset: hex(section.fileOffset),
        address: hex(section.address),
        size: hex(section.size),
      })),
      bss: { address: hex(header.bss.address), size: hex(header.bss.size) },
      observations,
      checks,
      limitations: [
        "GameCube DOL is a header interpretation explicitly selected by the caller; the format is not identified from file bytes.",
        "Verification covers original/modified FileBytes identity, every used text and data section at its load address with exact file-byte digests, BSS as uninitialized gaps outside data sections, and the header entry. Mapping ends are inclusive.",
        "The 256-byte header and any bytes between sections are not mapped and are not verified. Language-defined uninitialized blocks outside BSS are preserved as observations and not attested.",
        "A mismatching digest identifies its source range, not the first differing byte. No runtime, boot, or hardware state is modeled.",
      ],
    }),
  );
};
