import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { normalizeTestTemporaryPrefix } from "../../scripts/lib/test-temporary-ownership.mjs";

const denied = (operation: () => unknown): boolean => {
  try {
    operation();
    return false;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code === "EACCES" || code === "EPERM";
  }
};

const withProbeRoot = <Result>(
  run: (root: string, protect: (directory: string) => void) => Result,
): Result => {
  const root = mkdtempSync(
    join(tmpdir(), normalizeTestTemporaryPrefix("permission-denial-probe-")),
  );
  const directories: string[] = [];
  try {
    return run(root, (directory) => directories.push(directory));
  } finally {
    for (const directory of directories)
      if (existsSync(directory)) chmodSync(directory, 0o700);
    rmSync(root, { recursive: true, force: true });
  }
};

const probeReadDenial = (): boolean => {
  if (process.platform === "win32") return false;
  return withProbeRoot((root, protect) => {
    const file = join(root, "file");
    const unlistable = join(root, "unlistable");
    const writeOnly = join(root, "write-only");
    writeFileSync(file, "x");
    chmodSync(file, 0);
    mkdirSync(unlistable);
    protect(unlistable);
    chmodSync(unlistable, 0);
    mkdirSync(writeOnly);
    protect(writeOnly);
    chmodSync(writeOnly, 0o333);
    return (
      denied(() => readFileSync(file)) &&
      denied(() => readdirSync(unlistable)) &&
      denied(() => readdirSync(writeOnly))
    );
  });
};

const probeWriteDenial = (): boolean => {
  if (process.platform === "win32") return false;
  return withProbeRoot((root, protect) => {
    const readOnly = join(root, "read-only");
    mkdirSync(readOnly);
    protect(readOnly);
    chmodSync(readOnly, 0o500);
    return denied(() => writeFileSync(join(readOnly, "entry"), "x"));
  });
};

/**
 * True only when this process is refused reads by mode bits: an unreadable
 * file stays unreadable, and a directory without read permission cannot be
 * listed. Root, and any process that keeps CAP_DAC_OVERRIDE or
 * CAP_DAC_READ_SEARCH, reads straight through those modes, so tests that
 * depend on a read denial skip when this is false.
 */
export const readDenialEnforced: boolean = probeReadDenial();

/**
 * True only when this process is refused writes by mode bits: a read-only
 * directory refuses new entries. Root, and any process that keeps
 * CAP_DAC_OVERRIDE, writes straight through that mode, so tests that depend on
 * a write denial skip when this is false. CAP_DAC_READ_SEARCH alone does not
 * bypass it.
 */
export const writeDenialEnforced: boolean = probeWriteDenial();
