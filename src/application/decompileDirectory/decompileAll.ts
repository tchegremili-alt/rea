import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

import {
  DECOMPILE_DIRECTORY_INDEX_NAME,
  DECOMPILE_DIRECTORY_INLINE_FAILURE_LIMIT,
  decompileDirectoryManifestSchema,
  type DecompileDirectoryFunctionRecord,
  type DecompileDirectoryInput,
} from "../../contracts/decompileDirectory.js";
import { digestSchema } from "../../domain/digests.js";
import type {
  AnalysisExecution,
  AnalysisOperationPort,
} from "../AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { procedureInfoSchema } from "../../domain/native/procedureInfo.js";
import { addressedValueSchema } from "../../domain/native/nativeInventory.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  classifyOutputPath,
  commitFunctionFile,
  DecompileExport,
  sha256,
  type ExportIdentity,
} from "./exportTree.js";
import {
  bodyRecord,
  functionFileText,
  type FunctionBody,
} from "./functionFile.js";
import {
  selectProcedures,
  validateDecompileBounds,
  type SelectedProcedure,
} from "./selection.js";

const DWARF_LAYOUT_UNAVAILABLE =
  "Debug compilation-unit layout is unavailable. Files are named by canonical address.";
const BODY_UNAVAILABLE =
  "procedure_info is unavailable, so function body ranges are unknown.";
const TARGET_DIGEST_UNAVAILABLE =
  "Target SHA-256 was not observed. Resume can only match another export that also has no target digest.";
const DUPLICATE_ADDRESSES =
  "Duplicate procedure addresses were collapsed to the first inventory row.";

interface FailureReason {
  readonly code: string;
  readonly message: string;
}

interface PublishState {
  written: number;
  failed: number;
  skipped: number;
  readonly failures: {
    readonly address: string;
    readonly name: string | null;
    readonly code: string;
    readonly message: string;
  }[];
  bodyUnavailable: boolean;
}

/**
 * Write one pseudocode file per selected function and return only a manifest.
 * Files already committed stay in place when a later function fails or the
 * caller cancels.
 */
export const decompileAll = async (
  analysis: AnalysisOperationPort,
  input: DecompileDirectoryInput,
  signal?: AbortSignal,
): Promise<Result<JsonValue, AnalysisError>> => {
  const bounds = validateDecompileBounds(input);
  if (!bounds.ok) return bounds;
  const placement = await classifyOutputPath(
    input.output_directory,
    input.resume,
  );
  if (!placement.ok) return placement;
  if (isAborted(signal)) return err(cancelled(signal));
  const loaded = await loadProcedures(analysis, input.layout, signal);
  if (!loaded.ok) return loaded;
  if (isAborted(signal)) return err(cancelled(signal));
  const selection = selectProcedures(
    loaded.value.procedures,
    input,
    bounds.value,
  );
  const opened = await DecompileExport.open({
    placement: placement.value,
    identity: loaded.value.identity,
  });
  if (!opened.ok) return opened;
  const session = opened.value;
  const state: PublishState = {
    written: 0,
    failed: 0,
    skipped: 0,
    failures: [],
    bodyUnavailable: false,
  };
  try {
    const published = await publishSelected({
      analysis,
      session,
      procedures: selection.procedures,
      identity: loaded.value.identity,
      signal,
      limit: input.limit,
      state,
    });
    const limitations = exportLimitations(
      input.layout,
      loaded.value.identity,
      selection.collapsedDuplicates,
      state.bodyUnavailable,
    );
    const indexed = await session.writeIndex({
      layoutStatus: layoutStatus(input.layout),
      limitations,
    });
    if (!published.ok) return published;
    if (!indexed.ok) return indexed;
    const manifest = decompileDirectoryManifestSchema.safeParse(
      manifestOf({
        root: session.root,
        input,
        identity: loaded.value.identity,
        selected: selection.procedures.length,
        excluded: selection.excluded,
        state,
        limitations,
      }),
    );
    return manifest.success
      ? ok(manifest.data)
      : err(
          new AnalysisOutputError(
            "decompile_all",
            "decompile manifest could not be built",
          ),
        );
  } finally {
    await session.close();
  }
};

const loadProcedures = async (
  analysis: AnalysisOperationPort,
  layout: DecompileDirectoryInput["layout"],
  signal: AbortSignal | undefined,
): Promise<
  Result<
    {
      readonly procedures: readonly SelectedProcedure[];
      readonly identity: ExportIdentity;
    },
    AnalysisError
  >
> => {
  const observed = await analysis.execute(
    "list_procedures",
    {},
    executionOptions(signal),
  );
  if (!observed.ok) return observed;
  const parsed = z.array(addressedValueSchema).safeParse(observed.value.result);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "list_procedures",
        "provider returned an invalid procedure inventory",
      ),
    );
  const identity = identityFrom(observed.value, layout);
  if (!identity.ok) return identity;
  return ok({
    procedures: parsed.data.map((row) => ({
      address: row.address,
      name: row.value.length === 0 ? null : row.value,
    })),
    identity: identity.value,
  });
};

const identityFrom = (
  execution: AnalysisExecution,
  layout: DecompileDirectoryInput["layout"],
): Result<ExportIdentity, AnalysisError> => {
  const sha = execution.subject?.sha256 ?? null;
  if (sha !== null && !digestSchema.safeParse(sha).success)
    return err(
      new AnalysisOutputError(
        "list_procedures",
        "provider returned a target digest that is not a SHA-256",
      ),
    );
  const profile = execution.analysisProfile?.digest ?? null;
  if (profile !== null && !digestSchema.safeParse(profile).success)
    return err(
      new AnalysisOutputError(
        "list_procedures",
        "provider returned an analysis profile digest that is not a SHA-256",
      ),
    );
  const provider = execution.provider;
  if (provider.id.length === 0 || provider.name.length === 0)
    return err(
      new AnalysisOutputError(
        "list_procedures",
        "provider identity is incomplete",
      ),
    );
  if (provider.version !== null && provider.version.length === 0)
    return err(
      new AnalysisOutputError(
        "list_procedures",
        "provider identity is incomplete",
      ),
    );
  return ok({
    targetSha256: sha,
    provider: {
      id: provider.id,
      name: provider.name,
      version: provider.version,
    },
    analysisProfileDigest: profile,
    layout,
  });
};

const publishSelected = async (input: {
  readonly analysis: AnalysisOperationPort;
  readonly session: DecompileExport;
  readonly procedures: readonly SelectedProcedure[];
  readonly identity: ExportIdentity;
  readonly signal: AbortSignal | undefined;
  readonly limit: number | undefined;
  readonly state: PublishState;
}): Promise<Result<void, AnalysisError>> => {
  let bodySupport: "unknown" | "unavailable" = "unknown";
  for (const procedure of input.procedures) {
    if (isAborted(input.signal)) return err(cancelled(input.signal));
    const existing = await existingFile(input.session, procedure.address);
    if (existing === "skip") {
      input.state.skipped += 1;
      continue;
    }
    if (
      input.limit !== undefined &&
      input.state.written + input.state.failed >= input.limit
    )
      continue;
    if (existing === "conflict") {
      const reason = {
        code: "output_exists",
        message:
          "The function file already exists and does not match this export.",
      };
      recordFailure(input.state, procedure, reason);
      const appended = await input.session.append(
        failureRecord(
          procedure,
          retainedBody(input.session, procedure.address),
          reason,
          input.session.pathFor(procedure.address),
        ),
      );
      if (!appended.ok) return appended;
      continue;
    }
    if (existing === "io") {
      recordFailure(input.state, procedure, {
        code: "output_io",
        message: "The existing function file could not be read.",
      });
      const appended = await input.session.append(
        failureRecord(procedure, unavailableBody("not read"), {
          code: "output_io",
          message: "The existing function file could not be read.",
        }),
      );
      if (!appended.ok) return appended;
      continue;
    }
    const outcome = await publishOne({
      ...input,
      procedure,
      bodySupport,
    });
    bodySupport = outcome.bodySupport;
    if (!outcome.result.ok) return outcome.result;
  }
  return ok(undefined);
};

const publishOne = async (input: {
  readonly analysis: AnalysisOperationPort;
  readonly session: DecompileExport;
  readonly procedure: SelectedProcedure;
  readonly identity: ExportIdentity;
  readonly signal: AbortSignal | undefined;
  readonly state: PublishState;
  readonly bodySupport: "unknown" | "unavailable";
}): Promise<{
  readonly result: Result<void, AnalysisError>;
  readonly bodySupport: "unknown" | "unavailable";
}> => {
  if (input.procedure.address.length === 0) {
    const reason = {
      code: "unresolved_identity",
      message: "The procedure address is empty.",
    };
    recordFailure(input.state, input.procedure, reason);
    return {
      result: await input.session.append(
        failureRecord(input.procedure, unavailableBody(reason.message), reason),
      ),
      bodySupport: input.bodySupport,
    };
  }
  const body = await readBody(
    input.analysis,
    input.procedure.address,
    input.signal,
    input.bodySupport,
  );
  if (body.kind === "cancelled")
    return { result: err(body.error), bodySupport: input.bodySupport };
  if (body.kind === "unavailable") input.state.bodyUnavailable = true;
  const decompiled = await input.analysis.execute(
    "procedure_pseudo_code",
    { procedure: input.procedure.address },
    executionOptions(input.signal),
  );
  if (isAborted(input.signal))
    return { result: err(cancelled(input.signal)), bodySupport: body.support };
  if (!decompiled.ok) {
    if (decompiled.error instanceof AnalysisCancelledError)
      return { result: decompiled, bodySupport: body.support };
    const reason = failureReason(decompiled.error);
    recordFailure(input.state, input.procedure, reason);
    return {
      result: await input.session.append(
        failureRecord(input.procedure, body.fact, reason),
      ),
      bodySupport: body.support,
    };
  }
  if (!observationMatches(input.identity, decompiled.value)) {
    const reason = {
      code: "profile_changed",
      message:
        "The decompiler observation does not match this export's provider or analysis profile.",
    };
    recordFailure(input.state, input.procedure, reason);
    return {
      result: await input.session.append(
        failureRecord(input.procedure, body.fact, reason),
      ),
      bodySupport: body.support,
    };
  }
  const pseudocode = decompiled.value.result;
  if (typeof pseudocode !== "string" || pseudocode.length === 0) {
    const reason = {
      code:
        typeof pseudocode === "string"
          ? "empty_pseudocode"
          : "invalid_pseudocode",
      message:
        typeof pseudocode === "string"
          ? "The provider returned no pseudocode."
          : "The provider returned pseudocode that is not text.",
    };
    recordFailure(input.state, input.procedure, reason);
    return {
      result: await input.session.append(
        failureRecord(input.procedure, body.fact, reason),
      ),
      bodySupport: body.support,
    };
  }
  const relativePath = input.session.pathFor(input.procedure.address);
  const bytes = Buffer.from(
    functionFileText({
      procedure: input.procedure,
      body: body.fact,
      identity: input.identity,
      limitations: decompiled.value.limitations,
      pseudocode,
    }),
    "utf8",
  );
  const committed = await commitFunctionFile(
    input.session.root,
    relativePath,
    bytes,
  );
  if (committed.status === "conflict" || committed.status === "io") {
    const reason =
      committed.status === "conflict"
        ? {
            code: "output_exists",
            message:
              "The function file already exists and does not match this export.",
          }
        : {
            code: "output_io",
            message: "The function file could not be written.",
          };
    recordFailure(input.state, input.procedure, reason);
    return {
      result: await input.session.append(
        failureRecord(input.procedure, body.fact, reason, relativePath),
      ),
      bodySupport: body.support,
    };
  }
  const appended = await input.session.append({
    address: input.procedure.address,
    name: input.procedure.name,
    status: "written",
    relative_path: relativePath,
    sha256: committed.sha256,
    body: bodyRecord(body.fact),
  });
  if (!appended.ok) return { result: appended, bodySupport: body.support };
  input.state.written += committed.status === "written" ? 1 : 0;
  input.state.skipped += committed.status === "matched" ? 1 : 0;
  return { result: ok(undefined), bodySupport: body.support };
};

const readBody = async (
  analysis: AnalysisOperationPort,
  address: string,
  signal: AbortSignal | undefined,
  support: "unknown" | "unavailable",
): Promise<
  | {
      readonly kind: "body";
      readonly fact: FunctionBody;
      readonly support: "unknown" | "unavailable";
    }
  | {
      readonly kind: "unavailable";
      readonly fact: FunctionBody;
      readonly support: "unavailable";
    }
  | { readonly kind: "cancelled"; readonly error: AnalysisCancelledError }
> => {
  if (support === "unavailable")
    return {
      kind: "unavailable",
      fact: unavailableBody(BODY_UNAVAILABLE),
      support,
    };
  const observed = await analysis.execute(
    "procedure_info",
    { procedure: address },
    executionOptions(signal),
  );
  if (!observed.ok) {
    if (observed.error instanceof AnalysisCancelledError)
      return { kind: "cancelled", error: observed.error };
    if (observed.error instanceof AnalysisCapabilityUnavailableError)
      return {
        kind: "unavailable",
        fact: unavailableBody(BODY_UNAVAILABLE),
        support: "unavailable",
      };
    return {
      kind: "body",
      fact: unavailableBody(failureReason(observed.error).message),
      support,
    };
  }
  const parsed = procedureInfoSchema.safeParse(observed.value.result);
  if (!parsed.success)
    return {
      kind: "body",
      fact: unavailableBody("procedure_info returned an invalid body."),
      support,
    };
  if (!parsed.data.body.available)
    return {
      kind: "body",
      fact: unavailableBody(parsed.data.body.reason),
      support,
    };
  return {
    kind: "body",
    fact: {
      available: true,
      ranges: parsed.data.body.ranges,
      non_contiguous: parsed.data.body.non_contiguous,
    },
    support,
  };
};

type ExistingFile = "skip" | "write" | "conflict" | "io";

const existingFile = async (
  session: DecompileExport,
  address: string,
): Promise<ExistingFile> => {
  const record = session.record(address);
  if (
    record === undefined ||
    record.status !== "written" ||
    record.sha256 === undefined ||
    record.relative_path === undefined
  )
    return "write";
  const bytes = await readFile(join(session.root, record.relative_path)).catch(
    (cause: unknown) => cause,
  );
  if (bytes instanceof Buffer)
    return sha256(bytes) === record.sha256 ? "skip" : "conflict";
  return nodeAbsent(bytes) ? "write" : "io";
};

const observationMatches = (
  identity: ExportIdentity,
  execution: AnalysisExecution,
): boolean => {
  const provider = execution.provider;
  if (
    provider.id !== identity.provider.id ||
    provider.name !== identity.provider.name ||
    provider.version !== identity.provider.version
  )
    return false;
  const digest = execution.analysisProfile?.digest;
  return digest === undefined || digest === identity.analysisProfileDigest;
};

const failureReason = (error: AnalysisError): FailureReason => {
  if (error instanceof AnalysisTimeoutError)
    return { code: "deadline", message: "The decompiler deadline elapsed." };
  const projected = projectAnalysisError(error);
  const message = projected.message.replace(/\s+/gu, " ").trim().slice(0, 300);
  return {
    code: projected.code.slice(0, 80),
    message: message.length === 0 ? projected.code : message,
  };
};

const recordFailure = (
  state: PublishState,
  procedure: SelectedProcedure,
  reason: FailureReason,
): void => {
  state.failed += 1;
  state.failures.push({
    address: procedure.address,
    name: procedure.name,
    code: reason.code,
    message: reason.message,
  });
};

const failureRecord = (
  procedure: SelectedProcedure,
  body: FunctionBody,
  reason: FailureReason,
  relativePath?: string,
): DecompileDirectoryFunctionRecord => ({
  address: procedure.address,
  name: procedure.name,
  status: "failed",
  body: bodyRecord(body),
  failure: reason,
  ...(relativePath === undefined ? {} : { relative_path: relativePath }),
});

const unavailableBody = (reason: string): FunctionBody => ({
  available: false,
  reason: reason.length === 0 ? "unavailable" : reason,
});

/** Keep the journal's body fact when a conflicting file is left unchanged. */
const retainedBody = (
  session: DecompileExport,
  address: string,
): FunctionBody => {
  const body = session.record(address)?.body;
  if (body === undefined) return unavailableBody("not rewritten");
  return body.available
    ? {
        available: true,
        ranges: body.ranges.map((range) => ({
          start: range.start,
          end: range.end,
        })),
        non_contiguous: body.non_contiguous,
      }
    : unavailableBody(body.reason);
};

const exportLimitations = (
  layout: DecompileDirectoryInput["layout"],
  identity: ExportIdentity,
  collapsedDuplicates: boolean,
  bodyUnavailable: boolean,
): readonly string[] => [
  ...(layout === "dwarf" ? [DWARF_LAYOUT_UNAVAILABLE] : []),
  ...(identity.targetSha256 === null ? [TARGET_DIGEST_UNAVAILABLE] : []),
  ...(collapsedDuplicates ? [DUPLICATE_ADDRESSES] : []),
  ...(bodyUnavailable ? [BODY_UNAVAILABLE] : []),
];

const layoutStatus = (
  layout: DecompileDirectoryInput["layout"],
): "address" | "debug_layout_unavailable" =>
  layout === "dwarf" ? "debug_layout_unavailable" : "address";

const manifestOf = (input: {
  readonly root: string;
  readonly input: DecompileDirectoryInput;
  readonly identity: ExportIdentity;
  readonly selected: number;
  readonly excluded: number;
  readonly state: PublishState;
  readonly limitations: readonly string[];
}) => {
  const requested = input.state.written + input.state.failed;
  const shown = input.state.failures.slice(
    0,
    DECOMPILE_DIRECTORY_INLINE_FAILURE_LIMIT,
  );
  return {
    output_directory: input.root,
    index_path: join(input.root, DECOMPILE_DIRECTORY_INDEX_NAME),
    layout: input.input.layout,
    layout_status: layoutStatus(input.input.layout),
    counts: {
      selected: input.selected,
      excluded: input.excluded,
      requested,
      written: input.state.written,
      failed: input.state.failed,
      skipped: input.state.skipped,
      remaining: input.selected - input.state.skipped - requested,
    },
    failures: shown,
    failures_omitted: input.state.failures.length - shown.length,
    provider: input.identity.provider,
    analysis_profile_digest: input.identity.analysisProfileDigest,
    target_sha256: input.identity.targetSha256,
    limitations: [...input.limitations],
    resume: input.input.resume,
  };
};

const executionOptions = (signal: AbortSignal | undefined) => ({
  ...(signal === undefined ? {} : { signal }),
  selectorOrigin: "provider" as const,
});

const cancelled = (signal: AbortSignal | undefined): AnalysisCancelledError =>
  new AnalysisCancelledError("decompile_all", { cause: signal?.reason });

const isAborted = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;

const nodeAbsent = (cause: unknown): boolean =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  cause.code === "ENOENT";
