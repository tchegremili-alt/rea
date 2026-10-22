import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
import {
  createHistoricalSourceGraph,
  historicalSourceExclusionKey,
  historicalSourceInventoryHasPartialFacts,
  historicalSourceLanguages,
  historicalSourceManifests,
  historicalSourceParseFailureKey,
  historicalSourceRelationshipKey,
  type HistoricalSourceGraph,
  type HistoricalSourceGraphInput,
} from "../domain/referenceSourceGraph.js";
import { err, ok, type Result } from "../domain/result.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { AnalysisCleanupObservation } from "../domain/analysisErrorBase.js";
import { readReferenceSource } from "../reference/ReferenceSourceReader.js";
import type {
  ReferenceSourceRead,
  ReferenceSourceReaderError,
} from "../reference/ReferenceSourceReaderTypes.js";
import { parseReferenceSourceEntries } from "./ReferenceSourceImportEntries.js";
import { readReferenceSourceVcs } from "./ReferenceSourceVcsAdapter.js";
import type {
  ReferenceSourceImportError,
  ReferenceSourceImportOptions,
} from "./ReferenceSourceImportTypes.js";
import {
  prepareReferenceSourceImport,
  resolveReferenceSourceRoot,
} from "./ReferenceSourceImportPolicy.js";

const failure = (
  code: ReferenceSourceImportError["code"],
  message: string,
): ReferenceSourceImportError => ({
  tag: "reference-source-import",
  code,
  message,
});

type ReferenceSourceImportPartial = NonNullable<
  ReferenceSourceImportError["partial"]
>;

const withImportExclusions = (
  partial: ReferenceSourceRead | undefined,
  exclusions: HistoricalSourceGraphInput["exclusions"],
  limitations: readonly string[] = [],
): ReferenceSourceImportPartial | undefined =>
  partial === undefined
    ? undefined
    : {
        ...partial,
        exclusions: sortExclusions(exclusions),
        limitations: [
          ...new Set([...partial.limitations, ...limitations]),
        ].sort(compareUnicodeCodePoints),
      };

const cancelled = (
  partial?: ReferenceSourceImportPartial,
): ReferenceSourceImportError => ({
  ...failure("cancelled", "Reference source import cancelled"),
  ...(partial === undefined ? {} : { partial }),
});

const isAborted = (signal?: AbortSignal): boolean => signal?.aborted === true;

const deduplicateRelationships = (
  relationships: HistoricalSourceGraphInput["relationships"],
): HistoricalSourceGraphInput["relationships"] => {
  const seen = new Set<string>();
  const result: HistoricalSourceGraphInput["relationships"] = [];
  for (const relationship of relationships) {
    const key = historicalSourceRelationshipKey(relationship);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(relationship);
  }
  return result;
};

/** Sort parse failures deterministically while retaining distinct reasons. */
export const normalizeHistoricalSourceParseFailures = (
  failures: HistoricalSourceGraphInput["parse_failures"],
): HistoricalSourceGraphInput["parse_failures"] =>
  [...failures]
    .sort((left, right) =>
      compareUnicodeCodePoints(
        historicalSourceParseFailureKey(left),
        historicalSourceParseFailureKey(right),
      ),
    )
    .filter((value, index, array) => {
      if (index === 0) return true;
      const previous = array[index - 1];
      return (
        previous === undefined ||
        historicalSourceParseFailureKey(value) !==
          historicalSourceParseFailureKey(previous)
      );
    });

const buildProvenance = (
  options: ReferenceSourceImportOptions,
): HistoricalSourceGraphInput["provenance"] => ({
  importer: options.importer ?? "rea-reference-source-import",
  importer_version: options.importerVersion ?? null,
  caller: options.caller,
});

const sortExclusions = (
  exclusions: HistoricalSourceGraphInput["exclusions"],
): HistoricalSourceGraphInput["exclusions"] =>
  [...exclusions].sort((left, right) =>
    compareUnicodeCodePoints(
      historicalSourceExclusionKey(left),
      historicalSourceExclusionKey(right),
    ),
  );

/**
 * Import a reference source directory into a committed historical source graph.
 *
 * The import is deterministic, parallel-safe, and never executes source, hooks,
 * git subprocesses, or network requests. Paths explicitly excluded by the
 * caller's reference-source policy are omitted from the graph.
 */
export const importReferenceSource = async (
  options: ReferenceSourceImportOptions,
  resources: ArtifactResourceScope,
): Promise<Result<HistoricalSourceGraph, ReferenceSourceImportError>> => {
  if (isAborted(options.signal)) return err(cancelled());
  const exclusions: HistoricalSourceGraphInput["exclusions"] = [];
  const canonicalRoot = await resolveReferenceSourceRoot(
    options.root,
    options.signal,
  );
  if (!canonicalRoot.ok) return canonicalRoot;
  const vcsResult = await readReferenceSourceVcs(
    canonicalRoot.value,
    resources,
    options.signal,
  );
  const prepared = await prepareReferenceSourceImport(
    options,
    resources,
    exclusions,
    vcsResult.ok ? vcsResult.value.ignoreCase : null,
    canonicalRoot.value,
  );
  if (!prepared.ok) return prepared;
  const { root, policy } = prepared.value;
  if (isAborted(options.signal)) return err(cancelled());

  const readResult = await readReferenceSource(root, resources, {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...policy,
  });

  if (!readResult.ok)
    return err(
      combineReadFailures(
        readResult.error,
        vcsResult.ok ? undefined : vcsResult.error,
        withImportExclusions(
          readResult.error.partial,
          exclusions,
          prepared.value.limitations,
        ),
      ),
    );
  if (!vcsResult.ok)
    return err(
      combineReadFailures(
        vcsResult.error,
        undefined,
        withImportExclusions(
          readResult.value,
          exclusions,
          prepared.value.limitations,
        ),
      ),
    );

  const vcs = vcsResult.value.info;

  if (isAborted(options.signal))
    return err(
      cancelled(
        withImportExclusions(
          readResult.value,
          exclusions,
          prepared.value.limitations,
        ),
      ),
    );

  const read = readResult.value;
  const filePaths = new Set(
    read.entries
      .filter((entry) => entry.status === "read" && entry.kind === "file")
      .map((entry) => entry.path),
  );

  const { entries, relationships, parseFailures, limitations } =
    parseReferenceSourceEntries(read, filePaths, options.signal);

  if (isAborted(options.signal))
    return err(
      cancelled(
        withImportExclusions(read, exclusions, prepared.value.limitations),
      ),
    );

  const uniqueRelationships = deduplicateRelationships(relationships);
  const uniqueFailures = normalizeHistoricalSourceParseFailures(parseFailures);

  const sortedEntries = [...entries].sort((left, right) =>
    compareUnicodeCodePoints(left.path, right.path),
  );
  const sortedExclusions = sortExclusions(exclusions);
  const sortedLimitations = [
    ...limitations,
    ...prepared.value.limitations,
  ].sort(compareUnicodeCodePoints);

  const input: HistoricalSourceGraphInput = {
    schema: "HistoricalSourceGraph",
    authority: "historical-reference",
    root_alias: "$REFERENCE_ROOT",
    inventory_state: historicalSourceInventoryHasPartialFacts({
      entries: sortedEntries,
      relationships: uniqueRelationships,
      parse_failures: uniqueFailures,
      exclusions: sortedExclusions,
      limitations: sortedLimitations,
    })
      ? "partial"
      : "complete",
    entries: sortedEntries,
    relationships: uniqueRelationships.sort((left, right) =>
      compareUnicodeCodePoints(
        historicalSourceRelationshipKey(left),
        historicalSourceRelationshipKey(right),
      ),
    ),
    parse_failures: uniqueFailures,
    exclusions: sortedExclusions,
    languages: historicalSourceLanguages(sortedEntries),
    manifests: historicalSourceManifests(sortedEntries),
    vcs,
    provenance: buildProvenance(options),
    limitations: sortedLimitations,
  };

  try {
    return ok(createHistoricalSourceGraph(input));
  } catch (cause: unknown) {
    return err(
      failure(
        "parse",
        cause instanceof Error ? cause.message : "Graph failed validation",
      ),
    );
  }
};

const combineReadFailures = (
  primary: ReferenceSourceReaderError,
  other: ReferenceSourceReaderError | undefined,
  partial: ReferenceSourceImportError["partial"],
): ReferenceSourceImportError => {
  const cleanup = mergeCleanup(primary.cleanup, other?.cleanup);
  const message =
    other === undefined
      ? primary.message
      : `${primary.message}; additional reference metadata failure: ${other.message}`;
  const cause =
    other === undefined
      ? primary.cause
      : new AggregateError(
          [primary, other],
          "Reference source inventory and metadata both failed",
          { cause: primary },
        );
  return {
    ...failure(primary.code, message),
    ...(cleanup === undefined ? {} : { cleanup }),
    ...(partial === undefined ? {} : { partial }),
    ...(cause === undefined ? {} : { cause }),
  };
};

const mergeCleanup = (
  first: AnalysisCleanupObservation | undefined,
  second: AnalysisCleanupObservation | undefined,
): AnalysisCleanupObservation | undefined => {
  if (first === undefined) return second;
  if (second === undefined) return first;
  return {
    reason: `${first.reason}; ${second.reason}`,
    resources: [...new Set([...first.resources, ...second.resources])],
  };
};
