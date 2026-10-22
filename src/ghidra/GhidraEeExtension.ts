import { z } from "zod";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import {
  ghidraProcessorExtensionSchema,
  inspectGhidraProcessorExtension,
  resolveGhidraProcessorExtension,
  type GhidraProcessorExtensionSpec,
} from "./GhidraPspExtension.js";

/** The caller-installed PlayStation 2 extension that registers r5900:LE:32:default. */
export const GHIDRA_EE_EXTENSION: GhidraProcessorExtensionSpec = {
  id: "ghidra-emotionengine-reloaded",
  label: "EE",
  failureCode: "EE_EXTENSION_UNAVAILABLE",
  required: [
    "Module.manifest",
    "extension.properties",
    "data/languages/emotionengine.ldefs",
    "data/languages/r5900.slaspec",
    "data/languages/r5900.pspec",
    "data/languages/r5900.cspec",
  ],
};

export const ghidraEeExtensionSchema = ghidraProcessorExtensionSchema(
  z.literal(GHIDRA_EE_EXTENSION.id),
);
export type GhidraEeExtension = z.infer<typeof ghidraEeExtensionSchema>;

/** Read-only fingerprint of the installed extension; no home scanning or installation. */
export const inspectGhidraEeExtension = (
  root: string,
  ghidraVersion: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<GhidraEeExtension> =>
  inspectGhidraProcessorExtension(
    GHIDRA_EE_EXTENSION,
    root,
    ghidraVersion,
    resources,
    signal,
  ) as Promise<GhidraEeExtension>;

/** Resolve prerequisites before opening or admitting cached EE analysis. */
export const resolveGhidraEeExtension = (
  installation: GhidraInstallationInspection,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<Result<GhidraEeExtension, AnalysisError>> =>
  resolveGhidraProcessorExtension(
    GHIDRA_EE_EXTENSION,
    installation,
    resources,
    signal,
  ) as Promise<Result<GhidraEeExtension, AnalysisError>>;
