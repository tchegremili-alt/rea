import { createHash, randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  link,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import {
  DECOMPILE_DIRECTORY_FUNCTIONS_DIRECTORY,
  DECOMPILE_DIRECTORY_INDEX_NAME,
  DECOMPILE_DIRECTORY_JOURNAL_NAME,
  decompileDirectoryFunctionSchema,
  decompileDirectoryIndexSchema,
  decompileJournalHeaderSchema,
  decompileJournalLineSchema,
  isDecompileFunctionRelativePath,
  type DecompileDirectoryFunctionRecord,
  type DecompileJournalHeader,
} from "../../contracts/decompileDirectory.js";
import {
  AnalysisOutputError,
  type AnalysisInputError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { isPathWithinRoot } from "../../domain/localPath.js";
import { err, ok, type Result } from "../../domain/result.js";
import { decompileInputError } from "./inputError.js";
import { compareProcedureAddresses } from "./selection.js";

export interface ExportIdentity {
  readonly targetSha256: string | null;
  readonly provider: DecompileJournalHeader["provider"];
  readonly analysisProfileDigest: string | null;
  readonly layout: DecompileJournalHeader["layout"];
}

export type OutputPlacement =
  | { readonly mode: "create"; readonly root: string }
  | { readonly mode: "resume"; readonly root: string };

/** Refuse a bad path before provider work. This does not create a directory. */
export const classifyOutputPath = async (
  requested: string,
  resume: boolean,
): Promise<Result<OutputPlacement, AnalysisError>> => {
  const stripped = requested.replace(/\/+$/u, "");
  const name = basename(stripped);
  if (stripped.length === 0 || name === "" || name === "." || name === "..")
    return err(
      decompileInputError(
        "output_directory",
        "The output directory name is invalid.",
      ),
    );
  const listed = await lstat(stripped).then(
    (stat) => stat,
    (cause: unknown) => cause,
  );
  if (!isDirectoryStat(listed)) {
    if (resume && nodeCode(listed) === "ENOENT")
      return err(
        decompileInputError(
          "output_directory",
          "Resume requires an existing export directory. Omit resume to start a new export.",
        ),
      );
    return missingOrRejected(stripped, listed);
  }
  if (!resume)
    return err(
      decompileInputError(
        "output_directory",
        "Output directory already exists. Pass resume to continue an export that matches this target and analysis profile.",
      ),
    );
  const root = await realpath(stripped).catch((cause: unknown) => cause);
  return typeof root === "string"
    ? ok({ mode: "resume", root })
    : err(
        decompileInputError(
          "output_directory",
          "The output directory could not be resolved.",
        ),
      );
};

/** Owns one export directory and its append-only journal. */
export class DecompileExport {
  private constructor(
    readonly root: string,
    private readonly journal: FileHandle,
    private readonly records: Map<string, DecompileDirectoryFunctionRecord>,
    private readonly paths: PathReservations,
    private readonly identity: ExportIdentity,
  ) {}

  static open(input: {
    readonly placement: OutputPlacement;
    readonly identity: ExportIdentity;
  }): Promise<Result<DecompileExport, AnalysisError>> {
    return input.placement.mode === "create"
      ? DecompileExport.#create(input.placement.root, input.identity)
      : DecompileExport.#resume(input.placement.root, input.identity);
  }

  record(address: string): DecompileDirectoryFunctionRecord | undefined {
    return this.records.get(address);
  }

  /**
   * Stable relative path for an address. The first path the journal gave this
   * address wins, even when a later failure record names no path.
   */
  pathFor(address: string): string {
    const owned = this.paths.byAddress.get(address);
    if (owned !== undefined) return owned;
    const relativePath = allocateFunctionPath(address, this.paths.byPath);
    reservePath(this.paths, relativePath, address);
    return relativePath;
  }

  async append(
    record: DecompileDirectoryFunctionRecord,
  ): Promise<Result<void, AnalysisError>> {
    const line = decompileJournalLineSchema.safeParse({
      kind: "function",
      ...omitEmpty(record),
    });
    if (!line.success || line.data.kind !== "function")
      return err(
        new AnalysisOutputError(
          "decompile_all",
          "decompile journal record is invalid",
        ),
      );
    const written = await this.journal
      .write(`${JSON.stringify(line.data)}\n`)
      .then(() => this.journal.sync())
      .then(
        () => true,
        () => false,
      );
    if (!written)
      return err(
        new AnalysisOutputError(
          "decompile_all",
          "decompile journal could not be updated",
        ),
      );
    this.records.set(record.address, record);
    if (record.relative_path !== undefined)
      reservePath(this.paths, record.relative_path, record.address);
    return ok(undefined);
  }

  async writeIndex(input: {
    readonly layoutStatus: "address" | "debug_layout_unavailable";
    readonly limitations: readonly string[];
  }): Promise<Result<void, AnalysisError>> {
    // The journal owns the outcomes. Rebuild from disk so a concurrent run's
    // appended records are not dropped by this run's in-memory view.
    const journal = await readJournalBytes(this.root);
    const parsed =
      journal instanceof Buffer ? parseJournal(journal) : undefined;
    if (parsed === undefined || !parsed.ok)
      return err(
        new AnalysisOutputError(
          "decompile_all",
          "decompile index could not be built",
        ),
      );
    const index = decompileDirectoryIndexSchema.safeParse({
      version: 1,
      target_sha256: this.identity.targetSha256,
      provider: this.identity.provider,
      analysis_profile_digest: this.identity.analysisProfileDigest,
      layout: this.identity.layout,
      layout_status: input.layoutStatus,
      limitations: [...input.limitations],
      functions: [...parsed.value.records.values()].sort((left, right) =>
        compareProcedureAddresses(left.address, right.address),
      ),
    });
    if (!index.success)
      return err(
        new AnalysisOutputError(
          "decompile_all",
          "decompile index could not be built",
        ),
      );
    return writeOwnedIndex(
      this.root,
      `${JSON.stringify(index.data, null, 2)}\n`,
    );
  }

  async close(): Promise<Result<void, AnalysisError>> {
    const closed = await this.journal.close().then(
      () => true,
      () => false,
    );
    return closed
      ? ok(undefined)
      : err(
          new AnalysisOutputError(
            "decompile_all",
            "decompile journal could not be closed",
          ),
        );
  }

  static async #create(
    root: string,
    identity: ExportIdentity,
  ): Promise<Result<DecompileExport, AnalysisError>> {
    const created = await createPrivateDirectory(root);
    if (!created.ok) return created;
    const functions = await prepareFunctionsDirectory(root);
    if (!functions.ok) return removeCreatedRoot(root, functions);
    const opened = await seedJournal(root, identity);
    if (!opened.ok) return removeCreatedRoot(root, opened);
    return ok(
      new DecompileExport(
        root,
        opened.value,
        new Map(),
        { byPath: new Map(), byAddress: new Map() },
        identity,
      ),
    );
  }

  static async #resume(
    root: string,
    identity: ExportIdentity,
  ): Promise<Result<DecompileExport, AnalysisError>> {
    const opened = await readJournal(root, identity);
    if (!opened.ok) return opened;
    const functions = await prepareFunctionsDirectory(root);
    if (!functions.ok) return functions;
    await removeStaleTemporaries(root);
    const handle = await openJournal(root, "a");
    if (!handle.ok) return handle;
    // Drop a torn final line left by a crash so the next append starts a line.
    // An intact journal is not truncated, so a concurrent append is kept.
    const repaired =
      opened.value.committedBytes === opened.value.journalBytes ||
      (await handle.value.truncate(opened.value.committedBytes).then(
        () => true,
        () => false,
      ));
    if (!repaired) {
      await handle.value.close().catch(() => undefined);
      return err(
        decompileInputError(
          "output_directory",
          "The decompile journal could not be repaired after an interrupted write.",
        ),
      );
    }
    return ok(
      new DecompileExport(
        root,
        handle.value,
        opened.value.records,
        opened.value.paths,
        identity,
      ),
    );
  }
}

export type FileCommit =
  | { readonly status: "written"; readonly sha256: string }
  | { readonly status: "matched"; readonly sha256: string }
  | { readonly status: "conflict" }
  | { readonly status: "io" };

/**
 * Publish bytes with `link`, which fails when the final name exists.
 * A matching existing file is adopted. A different file is left unchanged.
 */
export const commitFunctionFile = async (
  root: string,
  relativePath: string,
  bytes: Buffer,
): Promise<FileCommit> => {
  if (!isDecompileFunctionRelativePath(relativePath)) return { status: "io" };
  const finalPath = join(root, relativePath);
  if (!isPathWithinRoot(root, finalPath)) return { status: "io" };
  const digest = sha256(bytes);
  const tempPath = join(root, `.tmp-${randomBytes(8).toString("hex")}.c`);
  const handle = await open(tempPath, "wx", 0o600).catch(
    (cause: unknown) => cause,
  );
  if (!isFileHandle(handle)) return { status: "io" };
  const stored = await handle
    .write(bytes)
    .then(() => handle.sync())
    .then(
      () => true,
      () => false,
    );
  await handle.close().catch(() => undefined);
  if (!stored) {
    await unlink(tempPath).catch(() => undefined);
    return { status: "io" };
  }
  await chmod(tempPath, 0o600).catch(() => undefined);
  const linked = await link(tempPath, finalPath).then(
    () => true,
    (cause: unknown) => cause,
  );
  await unlink(tempPath).catch(() => undefined);
  if (linked === true) {
    await chmod(finalPath, 0o600).catch(() => undefined);
    return { status: "written", sha256: digest };
  }
  if (nodeCode(linked) !== "EEXIST") return { status: "io" };
  const existing = await readFile(finalPath).catch((cause: unknown) => cause);
  if (!(existing instanceof Buffer)) return { status: "io" };
  return sha256(existing) === digest
    ? { status: "matched", sha256: digest }
    : { status: "conflict" };
};

const missingOrRejected = async (
  stripped: string,
  listed: unknown,
): Promise<Result<OutputPlacement, AnalysisError>> => {
  if (isSymlinkStat(listed))
    return err(
      decompileInputError(
        "output_directory",
        "The output directory must be a real directory, not a symlink.",
      ),
    );
  if (isPresentStat(listed))
    return err(
      decompileInputError(
        "output_directory",
        "The output path exists and is not a directory.",
      ),
    );
  if (nodeCode(listed) !== "ENOENT")
    return err(
      decompileInputError(
        "output_directory",
        "The output directory could not be inspected.",
      ),
    );
  const parent = await realpath(dirname(stripped)).catch(
    (cause: unknown) => cause,
  );
  if (typeof parent !== "string")
    return err(
      decompileInputError(
        "output_directory",
        "The output directory's parent does not exist.",
      ),
    );
  return ok({ mode: "create", root: join(parent, basename(stripped)) });
};

const createPrivateDirectory = async (
  root: string,
): Promise<Result<void, AnalysisError>> => {
  const created = await mkdir(root, { mode: 0o700 })
    .then(() => chmod(root, 0o700))
    .catch((cause: unknown) => cause);
  if (created === undefined) return ok(undefined);
  return err(
    nodeCode(created) === "EEXIST"
      ? decompileInputError(
          "output_directory",
          "Output directory already exists. Pass resume to continue an export that matches this target and analysis profile.",
        )
      : decompileInputError(
          "output_directory",
          "The output directory could not be created.",
        ),
  );
};

const prepareFunctionsDirectory = async (
  root: string,
): Promise<Result<void, AnalysisError>> => {
  const directory = join(root, DECOMPILE_DIRECTORY_FUNCTIONS_DIRECTORY);
  const created = await mkdir(directory, { mode: 0o700 }).catch(
    (cause: unknown) => cause,
  );
  if (created !== undefined && nodeCode(created) !== "EEXIST")
    return err(
      decompileInputError(
        "output_directory",
        "The functions directory could not be created.",
      ),
    );
  const stat = await lstat(directory).catch((cause: unknown) => cause);
  if (!isDirectoryStat(stat))
    return err(
      decompileInputError(
        "output_directory",
        "The functions directory is not a real directory.",
      ),
    );
  const secured = await chmod(directory, 0o700).catch(
    (cause: unknown) => cause,
  );
  return secured === undefined
    ? ok(undefined)
    : err(
        decompileInputError(
          "output_directory",
          "The functions directory could not be secured.",
        ),
      );
};

const seedJournal = async (
  root: string,
  identity: ExportIdentity,
): Promise<Result<FileHandle, AnalysisError>> => {
  const header = decompileJournalHeaderSchema.safeParse({
    kind: "header",
    version: 1,
    target_sha256: identity.targetSha256,
    provider: identity.provider,
    analysis_profile_digest: identity.analysisProfileDigest,
    layout: identity.layout,
  });
  if (!header.success)
    return err(
      new AnalysisOutputError(
        "decompile_all",
        "decompile journal header is invalid",
      ),
    );
  const opened = await openJournal(root, "wx");
  if (!opened.ok) return opened;
  const seeded = await opened.value
    .write(`${JSON.stringify(header.data)}\n`)
    .then(() => opened.value.sync())
    .then(() => chmod(join(root, DECOMPILE_DIRECTORY_JOURNAL_NAME), 0o600))
    .then(
      () => true,
      () => false,
    );
  if (seeded) return opened;
  await opened.value.close().catch(() => undefined);
  return err(
    decompileInputError(
      "output_directory",
      "The decompile journal could not be created.",
    ),
  );
};

const openJournal = async (
  root: string,
  flag: "wx" | "a",
): Promise<Result<FileHandle, AnalysisError>> => {
  const handle = await open(
    join(root, DECOMPILE_DIRECTORY_JOURNAL_NAME),
    flag,
    0o600,
  ).catch((cause: unknown) => cause);
  return isFileHandle(handle)
    ? ok(handle)
    : err(
        decompileInputError(
          "output_directory",
          "The decompile journal could not be opened.",
        ),
      );
};

interface OpenedJournal {
  readonly records: Map<string, DecompileDirectoryFunctionRecord>;
  readonly paths: PathReservations;
  /** Byte length of the newline-terminated lines. */
  readonly committedBytes: number;
  /** Byte length of the journal file as read. */
  readonly journalBytes: number;
}

const readJournalBytes = (root: string): Promise<unknown> =>
  readFile(join(root, DECOMPILE_DIRECTORY_JOURNAL_NAME)).catch(
    (cause: unknown) => cause,
  );

const readJournal = async (
  root: string,
  identity: ExportIdentity,
): Promise<Result<OpenedJournal, AnalysisError>> => {
  const bytes = await readJournalBytes(root);
  if (!(bytes instanceof Buffer))
    return err(
      nodeCode(bytes) === "ENOENT"
        ? decompileInputError(
            "output_directory",
            "Resume requires decompile-journal.jsonl in the output directory.",
          )
        : decompileInputError(
            "output_directory",
            "The decompile journal could not be read.",
          ),
    );
  const parsed = parseJournal(bytes);
  if (!parsed.ok) return parsed;
  const unknown = unknownIdentity(parsed.value.header, identity);
  if (unknown !== undefined) return err(unknown);
  return sameIdentity(parsed.value.header, identity)
    ? ok({
        records: parsed.value.records,
        paths: parsed.value.paths,
        committedBytes: parsed.value.committedBytes,
        journalBytes: parsed.value.journalBytes,
      })
    : err(
        decompileInputError(
          "output_directory",
          "The decompile journal does not match this target, provider, analysis profile, or layout.",
        ),
      );
};

const parseJournal = (
  bytes: Buffer,
): Result<
  OpenedJournal & { readonly header: DecompileJournalHeader },
  AnalysisError
> => {
  // Every committed line ends with a newline. Bytes after the last newline are
  // an interrupted append and are not part of the journal. Offsets are bytes,
  // so damaged UTF-8 cannot move the truncation point.
  const committedBytes = bytes.lastIndexOf(0x0a) + 1;
  const lines = bytes.subarray(0, committedBytes).toString("utf8").split("\n");
  lines.pop();
  const header = decompileJournalHeaderSchema.safeParse(parseJson(lines[0]));
  if (!header.success) return err(incompatibleJournal());
  const records = new Map<string, DecompileDirectoryFunctionRecord>();
  // A path stays reserved by the first address that used it, even when that
  // address's latest record no longer names it.
  const paths: PathReservations = { byPath: new Map(), byAddress: new Map() };
  for (const line of lines.slice(1)) {
    const parsed = decompileJournalLineSchema.safeParse(parseJson(line));
    if (!parsed.success || parsed.data.kind !== "function")
      return err(incompatibleJournal());
    const { kind: _kind, ...record } = parsed.data;
    const accepted = decompileDirectoryFunctionSchema.safeParse(record);
    if (!accepted.success || !validFunctionRecord(accepted.data))
      return err(incompatibleJournal());
    const path = accepted.data.relative_path;
    if (path !== undefined) {
      const owner = paths.byPath.get(path);
      if (owner !== undefined && owner !== accepted.data.address)
        return err(incompatibleJournal());
      reservePath(paths, path, accepted.data.address);
    }
    records.set(accepted.data.address, accepted.data);
  }
  return ok({
    header: header.data,
    records,
    paths,
    committedBytes,
    journalBytes: bytes.length,
  });
};

const validFunctionRecord = (
  record: DecompileDirectoryFunctionRecord,
): boolean => {
  if (
    record.relative_path !== undefined &&
    !isDecompileFunctionRelativePath(record.relative_path)
  )
    return false;
  return record.status === "written"
    ? record.relative_path !== undefined && record.sha256 !== undefined
    : record.failure !== undefined;
};

/** Resume needs both identities known. Two unknown digests are not a match. */
const unknownIdentity = (
  header: DecompileJournalHeader,
  identity: ExportIdentity,
): AnalysisInputError | undefined => {
  if (header.target_sha256 === null || identity.targetSha256 === null)
    return decompileInputError(
      "output_directory",
      "Resume requires an observed target SHA-256 for both the journal and this target.",
    );
  if (
    header.analysis_profile_digest === null ||
    identity.analysisProfileDigest === null
  )
    return decompileInputError(
      "output_directory",
      "Resume requires an analysis profile digest for both the journal and this provider.",
    );
  return undefined;
};

const sameIdentity = (
  header: DecompileJournalHeader,
  identity: ExportIdentity,
): boolean =>
  header.target_sha256 === identity.targetSha256 &&
  header.analysis_profile_digest === identity.analysisProfileDigest &&
  header.layout === identity.layout &&
  header.provider.id === identity.provider.id &&
  header.provider.name === identity.provider.name &&
  header.provider.version === identity.provider.version;

const incompatibleJournal = (): AnalysisInputError =>
  decompileInputError(
    "output_directory",
    "The decompile journal is not a compatible export.",
  );

const parseJson = (line: string | undefined): unknown => {
  if (line === undefined) return undefined;
  try {
    return JSON.parse(line) as unknown;
  } catch {
    return undefined;
  }
};

const omitEmpty = (
  record: DecompileDirectoryFunctionRecord,
): DecompileDirectoryFunctionRecord => ({
  address: record.address,
  name: record.name,
  status: record.status,
  body: record.body,
  ...(record.relative_path === undefined
    ? {}
    : { relative_path: record.relative_path }),
  ...(record.sha256 === undefined ? {} : { sha256: record.sha256 }),
  ...(record.failure === undefined ? {} : { failure: record.failure }),
});

/** Function file paths: each path has one owning address, each address keeps its first path. */
interface PathReservations {
  readonly byPath: Map<string, string>;
  readonly byAddress: Map<string, string>;
}

const reservePath = (
  paths: PathReservations,
  path: string,
  address: string,
): void => {
  if (!paths.byPath.has(path)) paths.byPath.set(path, address);
  if (!paths.byAddress.has(address)) paths.byAddress.set(address, path);
};

const allocateFunctionPath = (
  address: string,
  used: ReadonlyMap<string, string>,
): string => {
  const base = sanitizeAddress(address);
  const directory = DECOMPILE_DIRECTORY_FUNCTIONS_DIRECTORY;
  const plain = `${directory}/${base}.c`;
  if (!used.has(plain)) return plain;
  const suffix = createHash("sha256").update(address).digest("hex").slice(0, 8);
  let candidate = `${directory}/${base}-${suffix}.c`;
  let discriminator = 0;
  // Terminates: `used` is finite.
  while (used.has(candidate)) {
    discriminator += 1;
    candidate = `${directory}/${base}-${suffix}-${discriminator.toString(16)}.c`;
  }
  return candidate;
};

const sanitizeAddress = (address: string): string => {
  const cleaned = address
    .replace(/[^A-Za-z0-9._-]+/gu, "_")
    .replace(/^\.+/u, "")
    .slice(0, 120);
  return cleaned.length === 0 ? "function" : cleaned;
};

/** Remove a root this call created. A failed removal is reported, not hidden. */
const removeCreatedRoot = async <T>(
  root: string,
  failure: Result<T, AnalysisError>,
): Promise<Result<T, AnalysisError>> => {
  const removed = await rm(root, { recursive: true, force: true }).then(
    () => true,
    () => false,
  );
  return removed
    ? failure
    : err(
        decompileInputError(
          "output_directory",
          "The export could not be started, and its partly created output directory could not be removed. Remove it before retrying.",
        ),
      );
};

const STALE_TEMPORARY =
  /^(?:\.tmp-[0-9a-f]{16}\.c|\.decompile-index\.[0-9a-f]{16}\.tmp)$/u;

/** Remove this export's own temporary files left by an interrupted run. */
const removeStaleTemporaries = async (root: string): Promise<void> => {
  const entries = await readdir(root, { withFileTypes: true }).catch(() => []);
  for (const entry of entries)
    if (entry.isFile() && STALE_TEMPORARY.test(entry.name))
      await unlink(join(root, entry.name)).catch(() => undefined);
};

const writeOwnedIndex = async (
  root: string,
  text: string,
): Promise<Result<void, AnalysisError>> => {
  const tempPath = join(
    root,
    `.decompile-index.${randomBytes(8).toString("hex")}.tmp`,
  );
  const handle = await open(tempPath, "wx", 0o600).catch(
    (cause: unknown) => cause,
  );
  if (!isFileHandle(handle))
    return err(
      new AnalysisOutputError(
        "decompile_all",
        "decompile index could not be written",
      ),
    );
  const stored = await handle
    .write(text)
    .then(() => handle.sync())
    .then(
      () => true,
      () => false,
    );
  await handle.close().catch(() => undefined);
  if (!stored) {
    await unlink(tempPath).catch(() => undefined);
    return err(
      new AnalysisOutputError(
        "decompile_all",
        "decompile index could not be written",
      ),
    );
  }
  const published = await rename(
    tempPath,
    join(root, DECOMPILE_DIRECTORY_INDEX_NAME),
  ).then(
    () => true,
    () => false,
  );
  if (published) return ok(undefined);
  await unlink(tempPath).catch(() => undefined);
  return err(
    new AnalysisOutputError(
      "decompile_all",
      "decompile index could not be written",
    ),
  );
};

export const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const isFileHandle = (value: unknown): value is FileHandle =>
  typeof value === "object" &&
  value !== null &&
  "write" in value &&
  "sync" in value &&
  "close" in value;

const isDirectoryStat = (value: unknown): boolean =>
  isStat(value) && value.isDirectory() && !value.isSymbolicLink();

const isSymlinkStat = (value: unknown): boolean =>
  isStat(value) && value.isSymbolicLink();

const isPresentStat = (value: unknown): boolean => isStat(value);

const isStat = (
  value: unknown,
): value is {
  isDirectory: () => boolean;
  isSymbolicLink: () => boolean;
} =>
  typeof value === "object" &&
  value !== null &&
  "isDirectory" in value &&
  "isSymbolicLink" in value &&
  typeof value.isDirectory === "function" &&
  typeof value.isSymbolicLink === "function";

const nodeCode = (cause: unknown): string | undefined =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  typeof cause.code === "string"
    ? cause.code
    : undefined;
