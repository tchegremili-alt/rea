import {
  REA_WORKFLOW_PROVIDER,
  workflowAnalysisProfile,
} from "./InvestigationProviders.js";
import type {
  AnalysisOperation,
  AnalysisOperationPort,
} from "./AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ok, type Result } from "../domain/result.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { WorkflowSnapshotRecordInput } from "./binary/BinarySessionRecords.js";
import {
  analysisProfileSchema,
  committedProviderSchema,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceLocation,
} from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { UnknownRegistryPort } from "./investigation/InvestigationRecordPort.js";
import { UnknownRegistryError } from "../domain/unknownRegistryError.js";
import { workflowUnknownInput } from "./investigation/WorkflowUnknown.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
import {
  renderSourceLimitations,
  sourceLimitationKey,
  type SourceLimitation,
} from "./SourceLimitations.js";

/**
 * Bound for caveats a workflow observes once per item. Provider caveats can
 * name per-item addresses, so they do not deduplicate and would otherwise grow
 * with the number of items.
 */
export interface ComposedLimitationBudget {
  /** Operations the workflow calls once per item. */
  readonly perItemOperations: ReadonlySet<AnalysisOperation>;
  /**
   * Distinct per-item caveats kept: the most often observed, ties broken by
   * provider and text. Kept lines are then rendered in the usual sorted order.
   */
  readonly maxDistinct: number;
  /** Where the omitted per-item caveats remain, as a clause. */
  readonly retainedIn: string;
}

const DECOMPILE_ALL_LIMITATIONS: ComposedLimitationBudget = {
  perItemOperations: new Set(["procedure_info", "procedure_pseudo_code"]),
  maxDistinct: 8,
  retainedIn:
    "each function's file header or index failure record keeps the caveats of the observations it used",
};

/** The caveat budget for a composed workflow, when it has one. */
export const composedLimitationBudget = (
  operation: string,
): ComposedLimitationBudget | undefined =>
  operation === "decompile_all" ? DECOMPILE_ALL_LIMITATIONS : undefined;

/** Retain the limits of exactly the observations used by one composed call. */
export const executeComposedWorkflow = async (
  analysis: AnalysisOperationPort,
  execute: (
    observed: AnalysisOperationPort,
  ) => Promise<Result<JsonValue, AnalysisError>>,
  budget?: ComposedLimitationBudget,
): Promise<
  Result<
    {
      readonly result: JsonValue;
      readonly limitations: readonly string[];
      readonly cachePolicy?: "live";
    },
    AnalysisError
  >
> => {
  const limitations = new Map<
    string,
    { readonly fact: SourceLimitation; observations: number }
  >();
  let cachePolicy: "live" | undefined;
  const result = await execute({
    execute: async (operation, parameters, options) => {
      const execution = await analysis.execute(operation, parameters, options);
      if (execution.ok && execution.value.cachePolicy === "live")
        cachePolicy = "live";
      if (execution.ok)
        for (const limitation of execution.value.limitations) {
          const fact = {
            provider: execution.value.provider,
            operation,
            limitation,
          } satisfies SourceLimitation;
          const key = sourceLimitationKey(fact);
          const seen = limitations.get(key);
          if (seen === undefined)
            limitations.set(key, { fact, observations: 1 });
          else seen.observations += 1;
        }
      return execution;
    },
  });
  if (!result.ok) return result;
  return ok({
    result: result.value,
    limitations: boundedLimitations([...limitations.values()], budget),
    ...(cachePolicy === undefined ? {} : { cachePolicy }),
  });
};

const boundedLimitations = (
  observed: readonly {
    readonly fact: SourceLimitation;
    readonly observations: number;
  }[],
  budget: ComposedLimitationBudget | undefined,
): string[] => {
  if (budget === undefined)
    return renderSourceLimitations(observed.map(({ fact }) => fact));
  // Group per-item caveats exactly as rendering merges them, by provider and
  // text, so the kept and omitted counts describe rendered lines.
  const groups = new Map<
    string,
    { facts: SourceLimitation[]; observations: number }
  >();
  for (const { fact, observations } of observed) {
    if (!budget.perItemOperations.has(fact.operation)) continue;
    const key = JSON.stringify([
      fact.provider.id,
      fact.provider.name,
      fact.provider.version,
      fact.limitation,
    ]);
    const group = groups.get(key) ?? { facts: [], observations: 0 };
    group.facts.push(fact);
    group.observations += observations;
    groups.set(key, group);
  }
  const ranked = [...groups.entries()].sort(
    ([leftKey, left], [rightKey, right]) =>
      right.observations - left.observations ||
      compareUnicodeCodePoints(leftKey, rightKey),
  );
  const kept = ranked.slice(0, budget.maxDistinct);
  const omitted = ranked.length - kept.length;
  const rendered = renderSourceLimitations([
    ...observed
      .filter(({ fact }) => !budget.perItemOperations.has(fact.operation))
      .map(({ fact }) => fact),
    ...kept.flatMap(([, group]) => group.facts),
  ]);
  return omitted === 0
    ? rendered
    : [
        ...rendered,
        `${omitted} further distinct per-item provider limitation${omitted === 1 ? " was" : "s were"} omitted from this answer; ${budget.retainedIn}.`,
      ];
};

/** Build the shared Evidence record for a successful composed binary workflow. */
export const createWorkflowEvidence = (input: {
  readonly target: BinaryTarget | undefined;
  readonly operation: AnalysisOperation;
  readonly parameters: Readonly<Record<string, JsonValue>>;
  readonly result: JsonValue;
  readonly upstreamProfile: AnalysisProfileCommitment | undefined;
  readonly upstreamLimitations: readonly string[];
}): Evidence =>
  createEvidence(input.target, REA_WORKFLOW_PROVIDER, {
    operation: input.operation,
    parameters: input.parameters,
    result: input.result,
    ...(input.upstreamProfile === undefined
      ? {}
      : {
          analysisProfile: workflowAnalysisProfile(
            input.upstreamProfile,
            input.operation,
          ),
        }),
    confidence: "derived",
    limitations: [
      "Derived by an REA composed workflow.",
      ...input.upstreamLimitations,
    ],
    ...(input.operation === "batch_decompile"
      ? { locations: batchProcedureLocations(input.result) }
      : {}),
  });

const batchProcedureLocations = (result: JsonValue): EvidenceLocation[] => {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result) ||
    !Array.isArray(result.items)
  )
    return [];
  const addresses = new Set<string>();
  for (const item of result.items) {
    if (item === null || typeof item !== "object" || Array.isArray(item))
      continue;
    const procedure = item.procedure;
    if (
      procedure !== null &&
      typeof procedure === "object" &&
      !Array.isArray(procedure) &&
      procedure.status === "resolved" &&
      typeof procedure.address === "string"
    )
      addresses.add(procedure.address);
  }
  return [...addresses].map((address) => ({ kind: "address", address }));
};

/** Convert workflow Evidence into its exact replay binding, when it has a profile. */
export const workflowSnapshotRecord = (
  evidence: Evidence,
  operation: AnalysisOperation,
  bindingProfile: AnalysisProfileCommitment | undefined,
  cachePolicy?: "live",
): WorkflowSnapshotRecordInput | undefined => {
  if (
    evidence.analysis_profile === null ||
    bindingProfile === undefined ||
    cachePolicy === "live"
  )
    return undefined;
  return {
    operation,
    bindingProfile,
    parameters: evidence.parameters,
    execution: {
      result: evidence.normalized_result,
      rawResult: evidence.raw_result,
      provider: committedProviderSchema.parse(evidence.provider),
      analysisProfile: analysisProfileSchema.parse(evidence.analysis_profile),
      limitations: evidence.limitations,
      locations: evidence.locations,
      subject:
        evidence.subject === null
          ? null
          : {
              path: evidence.subject.local_path,
              sha256: evidence.subject.digest.sha256,
              format: evidence.subject.format,
              ...(evidence.subject.architecture === null
                ? {}
                : { architecture: evidence.subject.architecture }),
            },
    },
  };
};

interface WorkflowUnknownInput {
  readonly name: string;
  readonly result: JsonValue;
  readonly evidenceId: string;
  readonly recordUnknown: UnknownRegistryPort["recordUnknown"] | undefined;
}

/** Retain residual workflow questions using the shared investigation policy. */
export const recordWorkflowUnknowns = ({
  name,
  result,
  evidenceId,
  recordUnknown,
}: WorkflowUnknownInput):
  | ReturnType<UnknownRegistryPort["recordUnknown"]>
  | { readonly ok: true; readonly value: null } => {
  if (
    !["trace_feature", "trace_call_path", "inspect_native_api"].includes(
      name,
    ) ||
    recordUnknown === undefined ||
    typeof result !== "object" ||
    result === null ||
    Array.isArray(result) ||
    !Array.isArray(result.residual_unknowns)
  )
    return { ok: true, value: null };
  for (const question of result.residual_unknowns) {
    if (typeof question !== "string") continue;
    const input = workflowUnknownInput(evidenceId, {
      question,
      severity: "medium",
      domain: name === "inspect_native_api" ? "native-api" : "control-flow",
      required_authority: "shipped-artifact",
      required_confidence: "observed",
      required_environment: null,
      recommended_probes: [
        {
          operation: name,
          rationale:
            name === "inspect_native_api"
              ? "Confirm the unsupported boundary with a capable provider or ABI probe."
              : "Continue with a focused query or another available provider.",
        },
      ],
      relationships: [],
    });
    if (!input.ok) return input;
    const recorded = recordUnknown(input.value);
    if (
      !recorded.ok &&
      !(
        recorded.error instanceof UnknownRegistryError &&
        recorded.error.reason === "already-exists"
      )
    )
      return recorded;
  }
  return { ok: true, value: null };
};
