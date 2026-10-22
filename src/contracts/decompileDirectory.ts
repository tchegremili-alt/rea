import { z } from "zod";

import { digestSchema } from "../domain/digests.js";
import { absoluteLocalPathStringSchema } from "../domain/localPath.js";

/** On-disk journal. Append-only so a crash keeps committed function files. */
export const DECOMPILE_DIRECTORY_JOURNAL_NAME = "decompile-journal.jsonl";

/** Derived catalog of the journal. It never contains pseudocode. */
export const DECOMPILE_DIRECTORY_INDEX_NAME = "decompile-index.json";

/** Directory of one `.c` file per function, named from the canonical address. */
export const DECOMPILE_DIRECTORY_FUNCTIONS_DIRECTORY = "functions";

/** First supported journal version. */
export const DECOMPILE_DIRECTORY_VERSION = 1;

/** Failure reasons returned inline. The index keeps every reason. */
export const DECOMPILE_DIRECTORY_INLINE_FAILURE_LIMIT = 32;

/** Upper bound for one call's attempt limit. */
export const DECOMPILE_DIRECTORY_MAX_LIMIT = 100_000;

const layoutSchema = z.enum(["address", "dwarf"]);

const exportProviderSchema = z.strictObject({
  id: z.string().min(1),
  name: z.string().min(1),
  version: z.string().min(1).nullable(),
});

const bodySchema = z.discriminatedUnion("available", [
  z.strictObject({
    available: z.literal(false),
    reason: z.string().min(1),
  }),
  z.strictObject({
    available: z.literal(true),
    ranges: z.array(
      z.strictObject({
        start: z.string().min(1),
        end: z
          .string()
          .min(1)
          .describe("Inclusive last address of this body range."),
      }),
    ),
    non_contiguous: z.boolean(),
  }),
]);

const failureSchema = z.strictObject({
  address: z.string().min(1),
  name: z.string().nullable(),
  code: z.string().min(1),
  message: z.string().min(1),
});

const countSchema = (description: string) =>
  z.number().int().min(0).describe(description);

/**
 * Caller input for writing pseudocode to a directory.
 * The workflow parses this once at the CLI and MCP boundaries.
 */
export const decompileDirectoryInputSchema = z.strictObject({
  output_directory: absoluteLocalPathStringSchema.describe(
    "Absolute output directory. The parent must exist. The directory itself must be absent unless resume is true.",
  ),
  layout: layoutSchema
    .default("address")
    .describe(
      "address names files by canonical address. dwarf asks for compilation-unit paths and is reported unavailable when the provider has no such fact.",
    ),
  resume: z
    .boolean()
    .default(false)
    .describe(
      "Continue a journal for the same target SHA-256, provider, analysis profile, and layout. Both digests must be known. Verified files are skipped, conflicting files are left unchanged, and functions not yet tried run before retries of recorded failures.",
    ),
  name: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Case-sensitive literal substring of the provider function name.",
    ),
  namespace: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Case-sensitive prefix of the provider function name, including any separator such as Foo:: or Class.",
    ),
  address_start: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Inclusive lower bound as 0xoffset or space:0xoffset. Must use the same address space as address_end.",
    ),
  address_end: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Inclusive upper bound as 0xoffset or space:0xoffset. Must use the same address space as address_start.",
    ),
  limit: z
    .number()
    .int()
    .min(1)
    .max(DECOMPILE_DIRECTORY_MAX_LIMIT)
    .optional()
    .describe(
      "Maximum functions to attempt on this call after skipping verified files. Further matches remain for a later resume.",
    ),
});

export type DecompileDirectoryInput = z.output<
  typeof decompileDirectoryInputSchema
>;

/** Small tool result. Pseudocode stays in the output files. */
export const decompileDirectoryManifestSchema = z
  .strictObject({
    output_directory: z
      .string()
      .min(1)
      .describe("Absolute directory containing the function files."),
    index_path: z
      .string()
      .min(1)
      .describe(
        "Absolute path of the index. The index lists functions and does not contain pseudocode.",
      ),
    layout: layoutSchema,
    layout_status: z
      .enum(["address", "debug_layout_unavailable"])
      .describe(
        "address when files are named by address on request. debug_layout_unavailable when dwarf was requested and no compilation-unit fact exists.",
      ),
    counts: z.strictObject({
      selected: countSchema("Functions matching the filter."),
      excluded: countSchema("Inventory functions excluded by the filter."),
      requested: countSchema("Functions this call attempted."),
      written: countSchema("Function files created by this call."),
      failed: countSchema("Functions this call could not write."),
      skipped: countSchema(
        "Selected functions whose existing files already hold the same bytes, whether recorded in the journal or found on disk.",
      ),
      remaining: countSchema(
        "Selected functions not attempted because the limit was reached.",
      ),
    }),
    failures: z
      .array(failureSchema)
      .max(DECOMPILE_DIRECTORY_INLINE_FAILURE_LIMIT)
      .describe(
        "Failure reasons for this call. Further reasons are counted by failures_omitted and stored in the index.",
      ),
    failures_omitted: countSchema(
      "Failure records omitted from failures because of the inline cap.",
    ),
    provider: exportProviderSchema.describe(
      "Provider that produced the pseudocode.",
    ),
    analysis_profile_digest: digestSchema
      .nullable()
      .describe(
        "Provider analysis-profile digest, or null when the provider did not commit one.",
      ),
    target_sha256: digestSchema
      .nullable()
      .describe(
        "SHA-256 of the analyzed target, or null when the observation has no file subject.",
      ),
    limitations: z
      .array(z.string())
      .describe("Limits of this export. Pseudocode is not included."),
    resume: z.boolean().describe("Whether this call continued a journal."),
  })
  .superRefine((manifest, context) => {
    const { counts } = manifest;
    if (counts.written + counts.failed !== counts.requested)
      context.addIssue({
        code: "custom",
        path: ["counts", "requested"],
        message: "requested must equal written plus failed",
      });
    if (
      counts.requested + counts.skipped + counts.remaining !==
      counts.selected
    )
      context.addIssue({
        code: "custom",
        path: ["counts", "selected"],
        message: "selected must equal requested plus skipped plus remaining",
      });
    if (manifest.failures.length + manifest.failures_omitted !== counts.failed)
      context.addIssue({
        code: "custom",
        path: ["failures_omitted"],
        message: "failures plus failures_omitted must equal failed",
      });
  });

/** One latest journal outcome, without pseudocode. */
export const decompileDirectoryFunctionSchema = z.strictObject({
  address: z.string().min(1),
  name: z.string().nullable(),
  status: z.enum(["written", "failed"]),
  relative_path: z.string().min(1).optional(),
  sha256: digestSchema.optional(),
  body: bodySchema,
  failure: z
    .strictObject({
      code: z.string().min(1),
      message: z.string().min(1),
    })
    .optional(),
  /** Provider caveats of the observations a failed attempt used. */
  limitations: z.array(z.string().min(1)).min(1).optional(),
});

export type DecompileDirectoryFunctionRecord = z.infer<
  typeof decompileDirectoryFunctionSchema
>;

/** Header of a decompile journal. Identity for resume. */
export const decompileJournalHeaderSchema = z.strictObject({
  kind: z.literal("header"),
  version: z.literal(DECOMPILE_DIRECTORY_VERSION),
  target_sha256: digestSchema.nullable(),
  provider: exportProviderSchema,
  analysis_profile_digest: digestSchema.nullable(),
  layout: layoutSchema,
});

export type DecompileJournalHeader = z.infer<
  typeof decompileJournalHeaderSchema
>;

/** One appended function outcome. */
export const decompileJournalFunctionSchema = z.strictObject({
  kind: z.literal("function"),
  address: z.string().min(1),
  name: z.string().nullable(),
  status: z.enum(["written", "failed"]),
  relative_path: z.string().min(1).optional(),
  sha256: digestSchema.optional(),
  body: bodySchema,
  failure: z
    .strictObject({
      code: z.string().min(1),
      message: z.string().min(1),
    })
    .optional(),
  /** Provider caveats of the observations a failed attempt used. */
  limitations: z.array(z.string().min(1)).min(1).optional(),
});

export const decompileJournalLineSchema = z.discriminatedUnion("kind", [
  decompileJournalHeaderSchema,
  decompileJournalFunctionSchema,
]);

/** Index rewritten from the journal at the end of a call. */
export const decompileDirectoryIndexSchema = z.strictObject({
  version: z.literal(DECOMPILE_DIRECTORY_VERSION),
  target_sha256: digestSchema.nullable(),
  provider: exportProviderSchema,
  analysis_profile_digest: digestSchema.nullable(),
  layout: layoutSchema,
  layout_status: z.enum(["address", "debug_layout_unavailable"]),
  limitations: z.array(z.string()),
  functions: z.array(decompileDirectoryFunctionSchema),
});

/**
 * A function file path owned by this export: `functions/<safe>.c` with one
 * path segment and no traversal.
 */
export const isDecompileFunctionRelativePath = (value: string): boolean => {
  if (value.includes("\\") || value.includes("\0")) return false;
  const [directory, name, extra] = value.split("/");
  return (
    extra === undefined &&
    directory === DECOMPILE_DIRECTORY_FUNCTIONS_DIRECTORY &&
    name !== undefined &&
    /^[A-Za-z0-9._-]+\.c$/u.test(name)
  );
};
