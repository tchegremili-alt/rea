import { expect, it } from "vitest";
import {
  recordedCrashFixture,
  recordedCrashFixtureBytes,
  recordedCrashFileMappingFixture,
} from "../../fixtures/binaryDiagnostics/recordedCrash.js";
import { validateRecordedCrashStructure } from "../../../src/native/pwntools/RecordedCrashStructureBindings.js";
import { validateCoreFileMappingAuthority } from "../../../src/native/pwndbg/CoreFileMappingAuthority.js";
import { validateRecordedCrashSources } from "../../../src/native/pwntools/RecordedCrashSourceBindings.js";
import {
  recordedCrashSchema,
  RECORDED_LINUX_CORE_PROFILES,
} from "../../../src/domain/native/recordedCrash.js";

it.each(["x86_64-little-endian", "aarch64-little-endian"] as const)(
  "admits a %s core whose header carries that profile's e_machine",
  (architecture) => {
    const report = recordedCrashFixture(undefined, architecture);
    expect(() =>
      validateRecordedCrashStructure(
        report,
        recordedCrashFixtureBytes(report),
        report.decoder_diagnostics,
      ),
    ).not.toThrow();
  },
);

it.each([
  ["x86_64-little-endian", "aarch64-little-endian"],
  ["aarch64-little-endian", "x86_64-little-endian"],
] as const)(
  "rejects a %s report whose header carries the other profile's e_machine",
  (reported, embedded) => {
    const report = recordedCrashFixture(undefined, reported);
    const snapshot = recordedCrashFixtureBytes(report);
    snapshot.writeUInt16LE(RECORDED_LINUX_CORE_PROFILES[embedded].machine, 18);
    expect(() =>
      validateRecordedCrashStructure(
        report,
        snapshot,
        report.decoder_diagnostics,
      ),
    ).toThrow(/Reported core structure differs/);
  },
);

it.each([
  [6, 0],
  [6, 2],
  [20, 0],
  [20, 2],
] as const)(
  "rejects non-current ELF version at byte %i: %i",
  (offset, version) => {
    const report = recordedCrashFixture();
    const snapshot = recordedCrashFixtureBytes(report);
    if (offset === 6) snapshot[offset] = version;
    else snapshot.writeUInt32LE(version, offset);
    expect(() =>
      validateRecordedCrashStructure(
        report,
        snapshot,
        report.decoder_diagnostics,
      ),
    ).toThrow(/Reported core structure differs/);
  },
);

it.each(["/usr/bin/fixture", "../../fixture", "/a/../fixture"])(
  "separates valid source evidence from debugger mapping authority: %s",
  (path) => {
    const report = recordedCrashFileMappingFixture([Buffer.from(path)]);
    const snapshot = recordedCrashFixtureBytes(report);
    expect(() => recordedCrashSchema.parse(report)).not.toThrow();
    validateRecordedCrashStructure(
      report,
      snapshot,
      report.decoder_diagnostics,
    );
    validateRecordedCrashSources(report, snapshot, report.decoder_diagnostics);
    const original = Buffer.from(snapshot);
    expect(validateCoreFileMappingAuthority(report, snapshot).ok).toBe(
      path === "/usr/bin/fixture",
    );
    expect(snapshot).toEqual(original);
  },
);

// pyelftools names every ET_CORE note from the CORE table. Owner-qualified
// identity keeps those names on exact Linux CORE notes only (#5700).
const foreignOwnerNote = (type: string | number, rawType: number) => {
  const report = recordedCrashFileMappingFixture([Buffer.from("/usr/bin/app")]);
  const note = report.notes[0];
  if (note === undefined) throw new Error("Expected a source-owned note");
  // A 4-byte owner pads to 4 bytes, so the descriptor starts 4 bytes earlier.
  const shift = (value: string) => `0x${(BigInt(value) - 4n).toString(16)}`;
  note.owner_location = { ...note.owner_location, bytes: "0x4" };
  note.descriptor_location = {
    ...note.descriptor_location,
    offset: shift(note.descriptor_location.offset),
  };
  note.location = { ...note.location, bytes: shift(note.location.bytes) };
  report.segments = report.segments.map((segment) => ({
    ...segment,
    file_size: shift(segment.file_size),
  }));
  note.owner_bytes_base64 = Buffer.from("GNU\0").toString("base64");
  note.owner_display = "GNU";
  note.type = rawType;
  const snapshot = recordedCrashFixtureBytes(report);
  note.type = type;
  return { report, snapshot };
};

it.each([
  [3, 3],
  [0x46494c45, 0x46494c45],
  [0x53494749, 0x53494749],
  [0x12345678, 0x12345678],
] as const)(
  "admits a GNU-owned note only with its original numeric type: %i",
  (type, rawType) => {
    const { report, snapshot } = foreignOwnerNote(type, rawType);
    expect(() => recordedCrashSchema.parse(report)).not.toThrow();
    expect(() =>
      validateRecordedCrashStructure(
        report,
        snapshot,
        report.decoder_diagnostics,
      ),
    ).not.toThrow();
  },
);

it.each([
  ["NT_PRPSINFO", 3],
  ["NT_FILE", 0x46494c45],
  ["NT_SIGINFO", 0x53494749],
] as const)(
  "rejects a GNU-owned note reported with the CORE name %s",
  (type, rawType) => {
    const { report, snapshot } = foreignOwnerNote(type, rawType);
    expect(() => recordedCrashSchema.parse(report)).toThrow(
      /Only Linux CORE notes carry symbolic note types/,
    );
    expect(() =>
      validateRecordedCrashStructure(
        report,
        snapshot,
        report.decoder_diagnostics,
      ),
    ).toThrow(/Reported core structure differs/);
  },
);

it("applies Linux mapping confinement only to CORE-owned NT_FILE notes", () => {
  const empty = recordedCrashFileMappingFixture([]);
  const core = empty.notes[0];
  if (core === undefined) throw new Error("Expected a source-owned note");
  core.descriptor_location = { ...core.descriptor_location, bytes: "0x0" };
  const coreSnapshot = recordedCrashFixtureBytes(empty);
  expect(validateCoreFileMappingAuthority(empty, coreSnapshot)).toMatchObject({
    ok: false,
    error: { message: expect.stringContaining("missing mapping table header") },
  });
  const { report, snapshot } = foreignOwnerNote(0x46494c45, 0x46494c45);
  const note = report.notes[0];
  if (note === undefined) throw new Error("Expected a source-owned note");
  note.descriptor_location = { ...note.descriptor_location, bytes: "0x0" };
  expect(validateCoreFileMappingAuthority(report, snapshot).ok).toBe(true);
  // The guard itself is owner-qualified, independent of upstream naming.
  note.type = "NT_FILE";
  expect(validateCoreFileMappingAuthority(report, snapshot).ok).toBe(true);
});
