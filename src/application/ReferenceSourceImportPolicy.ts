import type { Stats } from "node:fs";
import { lstat, realpath, stat } from "node:fs/promises";
import { join, resolve } from "node:path";

import ignore from "ignore";
import {
  readRegularFileText,
  RegularFileCleanupFailure,
  RegularFileReadFailure,
  retryRegularFileCleanup,
} from "./RegularFileRead.js";

import { err, ok, type Result } from "../domain/result.js";
import type { HistoricalSourceGraphInput } from "../domain/referenceSourceGraph.js";
import type {
  ReferenceSourceExclusionKind,
  ReferenceSourceExclusionPolicy,
} from "../reference/ReferenceSourceReaderTypes.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  DEFAULT_REFERENCE_SOURCE_IGNORE_PATTERNS,
  type ReferenceSourceImportError,
  type ReferenceSourceImportOptions,
} from "./ReferenceSourceImportTypes.js";
import {
  filesystemFailureDetail,
  rootFilesystemFailure,
} from "../reference/ReferenceSourceReaderErrors.js";
import { regularFileCancellation } from "../filesystem/OwnedRegularFile.js";

/** Validated inputs ready for filesystem traversal. */
export interface PreparedReferenceSourceImport {
  readonly root: string;
  readonly policy: ReferenceSourceExclusionPolicy;
  readonly limitations: readonly string[];
}

const failure = (
  code: ReferenceSourceImportError["code"],
  message: string,
): ReferenceSourceImportError => ({
  tag: "reference-source-import",
  code,
  message,
});

class IgnorePolicyReadCancelled extends Error {
  constructor(readonly reason: unknown) {
    super("Reference source ignore policy read was cancelled", {
      cause: reason,
    });
    this.name = "IgnorePolicyReadCancelled";
  }
}

const isIgnorePolicyCancellation = (cause: unknown): boolean =>
  cause instanceof IgnorePolicyReadCancelled;

const ignorePolicyCause = (cause: unknown): unknown =>
  cause instanceof IgnorePolicyReadCancelled
    ? cause.reason
    : cause instanceof RegularFileReadFailure
      ? cause.operationCause
      : cause;

const isAborted = (signal?: AbortSignal): boolean => signal?.aborted === true;

type IgnoreReason = "project-ignored" | "default-ignored" | "caller-excluded";

// Hex atoms survive ignore's wildcard rewrites, including its terminal-star
// rewrite. Encode both range endpoints with uppercase hex so its textual
// range sanitizer cannot mistake their suffixes for a descending range.
const literalIgnoreAtom = (character: string, inClass: boolean): string => {
  const code = character.charCodeAt(0);
  const atom =
    code < 256
      ? `\\x${code.toString(16).toUpperCase().padStart(2, "0")}`
      : `\\u${code.toString(16).toUpperCase().padStart(4, "0")}`;
  return inClass ? atom : `[${atom}]`;
};

/** Normalize simple classes as members/ranges, never as independent escapes. */
const normalizeGitClass = (pattern: string, start: number) => {
  let index = start + 1;
  const negative = pattern[index] === "!" || pattern[index] === "^";
  if (negative) index += 1;
  let unsupported = pattern[index] === "]";
  const members: { character: string; quoted: boolean }[] = [];
  if (unsupported) {
    members.push({ character: "]", quoted: false });
    index += 1;
  }
  for (; index < pattern.length; index += 1) {
    const character = pattern[index]!;
    if (character === "]") {
      const end = index + 1;
      // POSIX classes and a literal initial ] retain the dependency's existing
      // behavior; they need a broader matcher compatibility decision.
      if (unsupported) return { text: pattern.slice(start, end), end };
      let text = "";
      for (let member = 0; member < members.length; member += 1) {
        const from = members[member]!.character;
        const dash = members[member + 1];
        const to = members[member + 2];
        if (dash?.character === "-" && !dash.quoted && to !== undefined) {
          // Git retains the first member of a descending range. Avoid an
          // invalid encoded range in JavaScript's RegExp constructor.
          if (from.charCodeAt(0) <= to.character.charCodeAt(0))
            text += `${literalIgnoreAtom(from, true)}-${literalIgnoreAtom(to.character, true)}`;
          else text += literalIgnoreAtom(from, true);
          member += 2;
        } else text += literalIgnoreAtom(from, true);
      }
      return { text: `[${negative ? "!" : ""}${text}]`, end };
    }
    if (
      character === "[" &&
      [":", ".", "="].includes(pattern[index + 1] ?? "")
    ) {
      const end = pattern.indexOf(`${pattern[index + 1]}]`, index + 2);
      if (end !== -1) {
        unsupported = true;
        index = end + 1;
        continue;
      }
    }
    if (character === "/") unsupported = true;
    if (character === "\\" && pattern[index + 1] !== undefined) {
      index += 1;
      if (pattern[index] === "/") unsupported = true;
      members.push({ character: pattern[index]!, quoted: true });
    } else members.push({ character, quoted: false });
  }
  return { text: pattern.slice(start), end: pattern.length };
};

/** Project policies normalize Git quoting; caller/secret rules keep their syntax. */
const normalizeIgnorePattern = (
  sourcePattern: string,
  gitEscapes = false,
): string => {
  const pattern = gitEscapes
    ? sourcePattern.replace(
        /((?:\\\\)*?)(\\? +)$/u,
        (_match, pairs: string, trailing: string) =>
          pairs + (trailing.startsWith("\\") ? "\\ " : ""),
      )
    : sourcePattern;
  let result = "";
  let inClass = false;
  let classFirst = false;
  let classAllowsInitialClose = false;
  for (let index = 0; index < pattern.length;) {
    const character = pattern[index]!;
    if (gitEscapes && character === "[") {
      const characterClass = normalizeGitClass(pattern, index);
      result += characterClass.text;
      index = characterClass.end;
      continue;
    }
    if (character === "\\") {
      let end = index;
      while (pattern[end] === "\\") end += 1;
      const count = end - index;
      const next = pattern[end];
      if (gitEscapes) {
        result += literalIgnoreAtom("\\", false).repeat(Math.floor(count / 2));
        if (count % 2 === 1) {
          if (next === undefined) return "";
          // A quoted separator still separates path components in Git.
          result += next === "/" ? "/" : literalIgnoreAtom(next, false);
          index = end + 1;
        } else index = end;
        continue;
      }
      if (next !== undefined && /\s/u.test(next) && next !== " ") {
        result += "\\".repeat(count - (count % 2));
        result += inClass ? next : `[${next}]`;
        index = end + 1;
        continue;
      }
      result += pattern.slice(index, end);
      if (next !== undefined && count % 2 === 1) {
        result += next;
        if (inClass) {
          classFirst = false;
          classAllowsInitialClose = false;
        }
        index = end + 1;
        continue;
      }
      index = end;
      continue;
    }
    if (inClass) {
      if (classFirst && (character === "!" || character === "^")) {
        result += character;
        classFirst = false;
        index += 1;
        continue;
      }
      if (classAllowsInitialClose && character === "]") {
        result += character;
        classFirst = false;
        classAllowsInitialClose = false;
        index += 1;
        continue;
      }
      if (
        character === "[" &&
        [":", ".", "="].includes(pattern[index + 1] ?? "")
      ) {
        const close = `${pattern[index + 1]}]`;
        const end = pattern.indexOf(close, index + 2);
        if (end !== -1) {
          result += pattern.slice(index, end + 2);
          index = end + 2;
          classFirst = false;
          continue;
        }
      }
      if (character === "]") inClass = false;
      else {
        classFirst = false;
        classAllowsInitialClose = false;
      }
      result += character;
      index += 1;
      continue;
    }
    if (character === "[") {
      inClass = true;
      classFirst = true;
      classAllowsInitialClose = true;
    }
    if (!inClass && character !== " " && /\s/u.test(character))
      result += `[${character}]`;
    else result += character;
    index += 1;
  }
  return result;
};

/** Scope Git patterns once while retaining their original text for evidence. */
const scopedPattern = (
  sourcePattern: string,
  prefix: string | undefined,
  projectPolicy: boolean,
): string | undefined => {
  // A terminal directory globstar must consume a descendant. ignore otherwise
  // lets its zero-depth match include the named parent, including for negations.
  const pattern = normalizeIgnorePattern(sourcePattern, projectPolicy).replace(
    /(^!?|\/)\*\*\/(?= *$)/u,
    "$1**/*/",
  );
  if (prefix === undefined) return pattern;
  if (pattern.length === 0 || /^ *$/u.test(pattern) || pattern.startsWith("#"))
    return undefined;
  const negative = pattern.startsWith("!");
  const body = negative ? pattern.slice(1) : pattern;
  if (body === "" || body === "/") return undefined;
  const anchored = body.startsWith("/") || body.slice(0, -1).includes("/");
  return `${negative ? "!" : ""}/${prefix}/${anchored ? "" : "**/"}${body.replace(/^\//u, "")}`;
};

const addMarkedPatterns = (
  matcher: ReturnType<typeof ignore>,
  patterns: readonly string[],
  reason: IgnoreReason,
  directory = ".",
): void => {
  // The reader lends this matcher only to this directory's descendants.
  // Consume that known prefix by depth: literal filenames can contain glob
  // metacharacters that ignore cannot safely escape (notably ? and \\).
  const prefix =
    directory === "."
      ? undefined
      : directory
          .split("/")
          .map(() => "*")
          .join("/");
  const policyPath =
    reason === "project-ignored"
      ? directory === "."
        ? ".gitignore"
        : `${directory}/.gitignore`
      : "";
  for (const pattern of patterns) {
    // Only the start of a policy file can contain an encoding signature.
    const projectPolicy = reason === "project-ignored";
    const text = projectPolicy ? pattern.replace(/^\uFEFF/u, "") : pattern;
    for (const rawLine of text.split(projectPolicy ? /\n/u : /\r?\n/u)) {
      // Git removes one terminal CR even from a final line without LF.
      // Do this only for policy files, before protecting literal whitespace.
      const line = projectPolicy ? rawLine.replace(/\r$/u, "") : rawLine;
      const scoped = scopedPattern(line, prefix, projectPolicy);
      if (scoped !== undefined)
        matcher.add({
          pattern: scoped,
          mark: `${reason}\u0000${policyPath}\u0000${line}`,
        });
    }
  }
  // This directory has already been admitted by the inherited policy.
  // Scoped wildcards must not exclude it retroactively and block descendant
  // negations through ignore's parent checks.
  if (prefix !== undefined) matcher.add(`!/${prefix}/`);
};

export const resolveReferenceSourceRoot = async (
  requestedRoot: string,
  signal?: AbortSignal,
): Promise<Result<string, ReferenceSourceImportError>> => {
  if (isAborted(signal))
    return err(failure("cancelled", "Reference source import cancelled"));
  try {
    const metadata = await stat(requestedRoot);
    if (isAborted(signal))
      return err(failure("cancelled", "Reference source import cancelled"));
    if (!metadata.isDirectory())
      return err(
        failure(
          "invalid-root",
          `Reference source root is not a directory: ${requestedRoot}`,
        ),
      );
    const canonicalRoot = await realpath(resolve(requestedRoot));
    if (isAborted(signal))
      return err(failure("cancelled", "Reference source import cancelled"));
    return ok(canonicalRoot);
  } catch (cause: unknown) {
    if (isAborted(signal))
      return err(failure("cancelled", "Reference source import cancelled"));
    const rootFailure = rootFilesystemFailure(
      cause,
      "Reference source root could not be resolved",
    );
    if (rootFailure === undefined) throw cause;
    return err({ ...failure(rootFailure.code, rootFailure.message), cause });
  }
};

const ignorePolicyMetadata = async (
  path: string,
): Promise<Result<Stats | undefined, ReferenceSourceImportError>> => {
  try {
    return ok(await lstat(path));
  } catch (cause: unknown) {
    if (
      typeof cause === "object" &&
      cause !== null &&
      "code" in cause &&
      cause.code === "ENOENT"
    )
      return ok(undefined);
    const message = filesystemFailureDetail(
      cause,
      `Reference source ignore policy could not be read at ${path}`,
    );
    if (message === undefined) throw cause;
    return err({ ...failure("io", message), cause });
  }
};

interface IgnorePolicyReadOptions {
  readonly signal: AbortSignal | undefined;
  readonly symlinks: "follow" | "reject";
  readonly isSensitive?: (kind: ReferenceSourceExclusionKind) => boolean;
}

const readIgnorePolicy = async (
  root: string,
  resources: ArtifactResourceScope,
  { signal, symlinks, isSensitive }: IgnorePolicyReadOptions,
): Promise<Result<string, ReferenceSourceImportError>> => {
  const policyPath = join(root, ".gitignore");
  try {
    const metadata = await ignorePolicyMetadata(policyPath);
    if (signal?.aborted === true)
      throw new IgnorePolicyReadCancelled(signal.reason);
    // Metadata failures leave kind unknown, just as in ordinary inventory.
    // Only explicitly sensitive policies may bypass this failure.
    if (!metadata.ok) {
      if (isSensitive?.("unknown")) return ok("");
      return metadata;
    }
    // Sensitive policies are omitted before opening or decoding their contents.
    // The reader records the exclusion once, with the observed entry kind.
    if (
      metadata.value === undefined ||
      isSensitive?.(metadata.value.isDirectory() ? "directory" : "file")
    )
      return ok("");
    try {
      return ok(
        await readRegularFileText(policyPath, {
          signal,
          symlinks,
          cancellationFailure: (reason) =>
            new IgnorePolicyReadCancelled(reason),
        }),
      );
    } catch (cause: unknown) {
      if (cause instanceof IgnorePolicyReadCancelled) throw cause;
      if (!(cause instanceof RegularFileCleanupFailure)) throw cause;
      const retry = await retryRegularFileCleanup(cause, resources, signal);
      const operationCancellation =
        cause.outcome.kind === "failed"
          ? regularFileCancellation(cause)
          : undefined;
      if (retry.cleanup !== undefined) {
        const primary =
          retry.outcome.kind === "failed"
            ? retry.outcome.cause
            : cause.cleanupCause;
        const primaryCause = ignorePolicyCause(primary);
        return err({
          ...failure(
            isIgnorePolicyCancellation(primary) ||
              operationCancellation !== undefined
              ? "cancelled"
              : "io",
            `Reference source ignore policy could not be read at ${policyPath}: ${errorMessage(primaryCause)}`,
          ),
          cleanup: retry.cleanup,
          cause: primaryCause,
        });
      }
      if (retry.outcome.kind === "failed") {
        if (operationCancellation !== undefined)
          throw new IgnorePolicyReadCancelled(operationCancellation.reason);
        throw retry.outcome.cause;
      }
      if (isAborted(signal))
        throw new IgnorePolicyReadCancelled(signal?.reason);
      return ok(retry.outcome.value);
    }
  } catch (cause: unknown) {
    const causeValue = ignorePolicyCause(cause);
    return err({
      ...failure(
        isIgnorePolicyCancellation(cause) ? "cancelled" : "io",
        `Reference source ignore policy could not be read at ${policyPath}: ${errorMessage(causeValue)}`,
      ),
      cause: causeValue,
    });
  }
};

/** Resolve the caller-selected directory and build path filters. */
export const prepareReferenceSourceImport = async (
  options: ReferenceSourceImportOptions,
  resources: ArtifactResourceScope,
  exclusions: HistoricalSourceGraphInput["exclusions"] = [],
  ignoreCase: boolean | null = false,
  canonicalRoot?: string,
): Promise<
  Result<PreparedReferenceSourceImport, ReferenceSourceImportError>
> => {
  try {
    return await resources.run(async () => {
      const root =
        canonicalRoot === undefined
          ? await resolveReferenceSourceRoot(options.root, options.signal)
          : ok(canonicalRoot);
      if (!root.ok) return root;
      const policy = await readIgnorePolicy(root.value, resources, {
        signal: options.signal,
        symlinks: "follow",
      });
      if (!policy.ok) return policy;
      // If Git's local setting cannot be read, use the broader matcher and
      // retain that uncertainty in graph limitations below.
      const project = ignore({ ignoreCase: ignoreCase ?? true });
      addMarkedPatterns(project, [policy.value], "project-ignored");
      const overrides = ignore();
      addMarkedPatterns(
        overrides,
        DEFAULT_REFERENCE_SOURCE_IGNORE_PATTERNS,
        "default-ignored",
      );
      for (const path of options.excludePaths ?? [])
        addMarkedPatterns(overrides, [path, `${path}/`], "caller-excluded");
      const secrets = ignore();
      for (const pattern of options.policy.secretPatterns)
        secrets.add({
          pattern: normalizeIgnorePattern(pattern),
          mark: pattern,
        });
      return ok({
        root: root.value,
        limitations:
          ignoreCase === null
            ? [
                "Effective Git core.ignoreCase is unknown; project ignore matching used case-insensitive rules.",
              ]
            : [],
        policy: createExclusionPolicy(project, {
          root: root.value,
          ignoreCase,
          overrides,
          secrets,
          exclusions,
          resources,
          signal: options.signal,
        }),
      });
    });
  } catch (cause: unknown) {
    if (!(cause instanceof ArtifactReaderFailure)) throw cause;
    return err({
      ...failure(
        cause.reason === "cancelled" ? "cancelled" : "io",
        cause.message,
      ),
      ...(cause.cleanup === undefined ? {} : { cleanup: cause.cleanup }),
      cause,
    });
  }
};

const errorMessage = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

interface ExclusionPolicyContext {
  readonly root: string;
  readonly ignoreCase: boolean | null;
  readonly overrides: ReturnType<typeof ignore>;
  readonly secrets: ReturnType<typeof ignore>;
  readonly exclusions: HistoricalSourceGraphInput["exclusions"];
  readonly resources: ArtifactResourceScope;
  readonly signal: AbortSignal | undefined;
}

/** Each pending directory keeps its own inherited rules; siblings never share writes. */
const createExclusionPolicy = (
  project: ReturnType<typeof ignore>,
  context: ExclusionPolicyContext,
): ReferenceSourceExclusionPolicy => {
  const { root, overrides, secrets, exclusions, resources, signal } = context;
  const policy: ReferenceSourceExclusionPolicy = {
    shouldExclude: createShouldExclude(
      exclusions,
      secrets,
      ignore().add(project).add(overrides),
    ),
    prepareDirectory: async (directory) => {
      // Root admission already read its policy before any inventory or VCS work.
      if (directory === ".") return ok(policy);
      const text = await readIgnorePolicy(join(root, directory), resources, {
        signal,
        symlinks: "reject",
        isSensitive: (kind) =>
          matchIgnorePath(secrets, `${directory}/.gitignore`, kind)?.ignored ===
          true,
      });
      if (!text.ok)
        return err({
          ...text.error,
          tag: "reference-source-reader",
          code: text.error.code === "cancelled" ? "cancelled" : "io",
        });
      if (text.value === "") return ok(policy);
      const inherited = ignore({
        ignoreCase: context.ignoreCase ?? true,
      }).add(project);
      addMarkedPatterns(inherited, [text.value], "project-ignored", directory);
      return ok(createExclusionPolicy(inherited, context));
    },
  };
  return policy;
};

/** Use the same kind interpretation for policy admission and inventory. */
const matchIgnorePath = (
  matcher: ReturnType<typeof ignore>,
  path: string,
  kind: ReferenceSourceExclusionKind,
) => {
  // An entry of unknown kind may be a directory, so directory-only rules
  // must still exclude it; this fails closed for caller-marked secrets.
  const patternPaths =
    kind === "directory"
      ? [`${path}/`]
      : kind === "unknown"
        ? [path, `${path}/`]
        : [path];
  const results = patternPaths.map((patternPath) => matcher.test(patternPath));
  return results.find(({ ignored }) => ignored) ?? results[0];
};

const createShouldExclude =
  (
    exclusions: HistoricalSourceGraphInput["exclusions"],
    secrets: ReturnType<typeof ignore>,
    ignored: ReturnType<typeof ignore>,
  ): ((path: string, kind: ReferenceSourceExclusionKind) => boolean) =>
  (path, kind) => {
    const secretMatch = matchIgnorePath(secrets, path, kind);
    if (secretMatch?.ignored === true) {
      if (!secretMatch.rule)
        throw new Error(`Ignored secret path has no matching rule: ${path}`);
      exclusions.push({
        path,
        entry_kind: kind,
        reason: "configured-secret",
        pattern:
          typeof secretMatch.rule.mark === "string"
            ? secretMatch.rule.mark
            : secretMatch.rule.pattern,
      });
      return true;
    }
    const match = matchIgnorePath(ignored, path, kind);
    if (match?.ignored !== true) return false;
    if (!match.rule)
      throw new Error(`Ignored path has no matching rule: ${path}`);
    const mark = match.rule.mark ?? "";
    const separator = mark.indexOf("\u0000");
    const policySeparator = mark.indexOf("\u0000", separator + 1);
    const reason = mark.slice(0, separator);
    if (
      policySeparator === -1 ||
      (reason !== "project-ignored" &&
        reason !== "default-ignored" &&
        reason !== "caller-excluded")
    )
      throw new Error(`Ignored path has unknown rule origin: ${path}`);
    const evidence = {
      path,
      entry_kind: kind,
      pattern: mark.slice(policySeparator + 1),
    };
    exclusions.push(
      reason === "project-ignored"
        ? {
            ...evidence,
            reason,
            policy_path: mark.slice(separator + 1, policySeparator),
          }
        : { ...evidence, reason },
    );
    return true;
  };
