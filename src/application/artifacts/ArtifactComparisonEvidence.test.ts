import { expect, it } from "vitest";

import { inspectAnalysisView } from "../analysisView/AnalysisViewService.js";
import { ARTIFACT_COMPARISON_EXAMPLE } from "../../contracts/artifactComparisonExample.js";
import { artifactInventorySummaryViewResultSchema } from "../../domain/analysisView/analysisView.js";
import { digestCanonicalValue } from "../../domain/canonicalDigest.js";
import {
  createEvidence,
  parseEvidence,
  type Evidence,
} from "../../domain/evidence.js";
import {
  EvidenceIntegrityError,
  EvidenceReferenceError,
} from "../../domain/evidenceErrors.js";
import { resolveArtifactComparisonEvidence } from "./ArtifactComparisonEvidence.js";

const artifactSummary = () => {
  const parent = ARTIFACT_COMPARISON_EXAMPLE.left;
  const summary = inspectAnalysisView(
    {
      source: { kind: "inline", evidence: parent },
      view: { kind: "summary" },
    },
    (evidenceId) => (evidenceId === parent.evidence_id ? parent : undefined),
  );
  if (!summary.ok) throw summary.error;
  return { parent, summary: summary.value };
};

const recreateSummary = (
  summary: Evidence,
  normalizedResult: Evidence["normalized_result"],
  parameters: Evidence["parameters"] = summary.parameters,
): Evidence => {
  if (summary.subject === null)
    throw new Error("artifact summary fixture must identify its subject");
  return createEvidence(
    {
      path: summary.subject.local_path,
      sha256: summary.subject.digest.sha256,
      format: summary.subject.format,
      ...(summary.subject.architecture === null
        ? {}
        : { architecture: summary.subject.architecture }),
    },
    summary.provider,
    {
      predicateType: summary.predicate_type,
      operation: summary.operation,
      parameters,
      result: normalizedResult,
      ...(summary.analysis_profile === null
        ? {}
        : { analysisProfile: summary.analysis_profile }),
      rawResult: summary.raw_result,
      confidence: summary.confidence,
      authority: summary.authority,
      environment: summary.environment,
      limitations: summary.limitations,
      ...(summary.relationship_coverage === null
        ? {}
        : { relationshipCoverage: summary.relationship_coverage }),
      locations: summary.locations,
      evidenceLinks: summary.evidence_links,
    },
  );
};

it("reports a missing retained parent instead of treating summary facts as inventory", () => {
  const { summary } = artifactSummary();
  const resolved = resolveArtifactComparisonEvidence(summary, undefined);
  expect(resolved.ok).toBe(false);
  if (!resolved.ok) {
    expect(resolved.error).toBeInstanceOf(EvidenceReferenceError);
    expect(resolved.error).toMatchObject({ reason: "missing" });
  }
});

it("uses retained Evidence resolution to reject a mismatched parent identity", () => {
  const { summary } = artifactSummary();
  const otherParent = ARTIFACT_COMPARISON_EXAMPLE.right;
  const resolved = resolveArtifactComparisonEvidence(
    summary,
    () => otherParent,
  );
  expect(resolved.ok).toBe(false);
  if (!resolved.ok) {
    expect(resolved.error).toBeInstanceOf(EvidenceReferenceError);
    expect(resolved.error).toMatchObject({ reason: "identity_mismatch" });
  }
});

it("rejects a summary that declares the wrong parent operation", () => {
  const { parent, summary } = artifactSummary();
  const summaryResult = artifactInventorySummaryViewResultSchema.parse(
    summary.normalized_result,
  );
  const normalizedResult = {
    ...summaryResult,
    parent_operation: "inspect_artifact",
  };
  const forged = recreateSummary(summary, normalizedResult);
  const resolved = resolveArtifactComparisonEvidence(forged, (evidenceId) =>
    evidenceId === parent.evidence_id ? parent : undefined,
  );
  expect(resolved.ok).toBe(false);
  if (!resolved.ok)
    expect(resolved.error).toBeInstanceOf(EvidenceIntegrityError);
});

it("rejects summary parameters that do not identify the projected parent", () => {
  const { parent, summary } = artifactSummary();
  const forged = recreateSummary(summary, summary.normalized_result, {
    ...summary.parameters,
    parent_evidence_id: `ev_${"f".repeat(64)}`,
  });
  const resolved = resolveArtifactComparisonEvidence(forged, (evidenceId) =>
    evidenceId === parent.evidence_id ? parent : undefined,
  );
  expect(resolved.ok).toBe(false);
  if (!resolved.ok)
    expect(resolved.error).toBeInstanceOf(EvidenceIntegrityError);
});

it("rejects summary facts that do not reproject from the complete parent", () => {
  const { parent, summary } = artifactSummary();
  const summaryResult = artifactInventorySummaryViewResultSchema.parse(
    summary.normalized_result,
  );
  const normalizedResult = {
    ...summaryResult,
    summary: {
      ...summaryResult.summary,
      available_counts: {
        ...summaryResult.summary.available_counts,
        nodes: summaryResult.summary.available_counts.nodes + 1,
      },
    },
  };
  const forged = recreateSummary(summary, normalizedResult);
  const resolved = resolveArtifactComparisonEvidence(forged, (evidenceId) =>
    evidenceId === parent.evidence_id ? parent : undefined,
  );
  expect(resolved.ok).toBe(false);
  if (!resolved.ok)
    expect(resolved.error).toBeInstanceOf(EvidenceIntegrityError);
});

it("accepts display-only subject changes excluded from Evidence identity", () => {
  const { parent, summary } = artifactSummary();
  if (summary.subject === null)
    throw new Error("artifact summary fixture must identify its subject");
  const displayOnly = parseEvidence({
    ...summary,
    subject: {
      ...summary.subject,
      name: "renamed.app",
      local_path: "/display-only/renamed.app",
    },
  });
  const resolved = resolveArtifactComparisonEvidence(
    displayOnly,
    (evidenceId) => (evidenceId === parent.evidence_id ? parent : undefined),
  );
  expect(resolved).toEqual({ ok: true, value: parent });
});

it("accepts a retained 6.5.0 summary whose legacy ID omits null coverage", () => {
  const { parent, summary } = artifactSummary();
  if (summary.subject === null || summary.relationship_coverage !== null)
    throw new Error("fixture summary must carry explicit null coverage");
  // 6.5.0 projected the summary identity without the null relationship_coverage
  // field, so its retained ID differs from what the current projection emits.
  const legacyProjection = {
    subject: {
      digest: summary.subject.digest,
      format: summary.subject.format,
      architecture: summary.subject.architecture,
    },
    provider: summary.provider,
    analysis_profile: summary.analysis_profile,
    predicate_type: summary.predicate_type,
    operation: summary.operation,
    parameters: summary.parameters,
    raw_result: summary.raw_result,
    normalized_result: summary.normalized_result,
    confidence: summary.confidence,
    authority: summary.authority,
    environment: summary.environment,
    limitations: summary.limitations,
    locations: summary.locations,
    evidence_links: summary.evidence_links,
  };
  const legacy = parseEvidence({
    ...summary,
    evidence_id: `ev_${digestCanonicalValue(legacyProjection, "Evidence")}`,
  });
  const resolved = resolveArtifactComparisonEvidence(legacy, (evidenceId) =>
    evidenceId === parent.evidence_id ? parent : undefined,
  );
  expect(resolved).toEqual({ ok: true, value: parent });
});
