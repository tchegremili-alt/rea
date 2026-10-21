#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile, mkdtemp, mkdir, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { buildGameCubeDolFixture } from "../tests/conformance/ghidra/dol-fixture.mjs";
import {
  GEKKO_LANGUAGE,
  STOCK_LANGUAGE,
  DOL_ENTRY,
  DOL_LEAF,
  DOL_GLOBAL,
  DOL_MARKER,
  assertDolAgainstElf,
  assertDolEntryProcedure,
  assertDolGap,
  assertDolGlobal,
  assertDolLoadImage,
  assertDolTail,
  inspectReadelfDolSource,
  parseDolHeaderIndependent,
} from "../tests/conformance/ghidra/dol-checks.mjs";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Optional cross-target lane. No tool acquisition and no target execution.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-dol.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "GameCube DOL verification requires a supported Linux/macOS Ghidra host",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Missing prerequisite: caller-supplied GHIDRA_INSTALL_DIR");
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `Ghidra prerequisite unavailable: ${JSON.stringify(installation)}`,
  );

const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-dol-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const baseEnv = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: installation.installDir,
  JAVA_HOME: installation.javaHome,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
for (const setting of ["GHIDRA_HEADLESS_MAXMEM", "GHIDRA_MAXMEM"]) {
  if (process.env[setting] !== undefined)
    baseEnv[setting] = process.env[setting];
}

/** True when a language id is declared by an .ldefs file in the Ghidra install or user extensions. */
async function languageInstalled(languageId) {
  const roots = [
    join(installation.installDir, "Ghidra", "Processors"),
    join(installation.installDir, "Ghidra", "Extensions"),
  ];
  const userRoot = join(homedir(), "Library", "ghidra");
  for (const entry of await readdir(userRoot, { withFileTypes: true }).catch(
    () => [],
  )) {
    if (entry.isDirectory())
      roots.push(join(userRoot, entry.name, "Extensions"));
  }
  const walk = async (dir, depth) => {
    for (const entry of await readdir(dir, { withFileTypes: true }).catch(
      () => [],
    )) {
      const path = join(dir, entry.name);
      if (entry.isDirectory() && depth < 6) {
        if (await walk(path, depth + 1)) return true;
      } else if (entry.name.endsWith(".ldefs")) {
        if ((await readFile(path, "utf8")).includes(`id="${languageId}"`))
          return true;
      }
    }
    return false;
  };
  for (const root of roots) if (await walk(root, 0)) return true;
  return false;
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** One MCP session plus CLI check. `languageOverride` is set only for the Gekko pass. */
async function runPass({ fixture, languageOverride, label }) {
  const env = { ...baseEnv };
  if (languageOverride !== undefined)
    env.REA_GHIDRA_LANGUAGE_ID = languageOverride;
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-real-dol-proof", version: "1" });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const call = async (name, args = {}) => {
    const reply = await client.callTool({ name, arguments: args }, undefined, {
      timeout: 180000,
    });
    return requireMcpOperationResult(reply, name);
  };
  const report = { label, language_override: languageOverride ?? null };
  try {
    await client.connect(transport);
    const target = await call("open_binary", {
      path: fixture.path,
      provider_id: "ghidra",
      format: "gamecube-dol",
    });
    assert.equal(target.architecture, "powerpc");
    assert.equal(target.sha256, fixture.sha256);
    const image = await call("inspect_native_load_image");
    const expectedLanguage = languageOverride ?? STOCK_LANGUAGE;
    assertDolLoadImage(image, {
      sha256: fixture.sha256,
      languageId: expectedLanguage,
    });
    report.language_id = image.language_id;
    report.compiler_spec_id = image.compiler_spec_id;
    report.attestation = image.status;
    const procedures = await call("list_procedures");
    const entry = assertDolEntryProcedure(procedures);
    report.entry = entry;
    if (languageOverride === undefined) {
      assert.ok(
        procedures.some((p) => BigInt(p.address) === DOL_LEAF),
        "Leaf function missing from real Ghidra inventory",
      );
      const callees = await call("procedure_callees", {
        procedure: entry.address,
      });
      assert.ok(
        callees.some((address) => BigInt(address) === DOL_LEAF),
        "Direct call to leaf not recovered",
      );
      const dossier = functionDossierSchema.parse(
        await call("analyze_function", { procedure: entry.address }),
      );
      assert.ok(
        dossier.pseudocode.includes("__start"),
        "Decompiled entry lacks __start",
      );
      const global = await call("read_bytes", {
        address: `0x${DOL_GLOBAL.toString(16)}`,
        length: 4,
      });
      assertDolGlobal(global.bytes_hex);
      const marker = await call("read_bytes", {
        address: `0x${DOL_MARKER.toString(16)}`,
        length: 29,
      });
      assert.equal(
        marker.bytes_hex,
        Buffer.from("rea-ppc-source-owned-fixture\0").toString("hex"),
      );
      const tail = await call("read_bytes", {
        address: "0x80013030",
        length: 4,
      });
      assertDolTail(tail.bytes_hex);
      const gap = await call("read_bytes", {
        address: "0x80013010",
        length: 4,
      });
      report.bss_gap_read = {
        returned_bytes: gap.returned_bytes,
        bytes_hex: gap.bytes_hex,
      };
      assertDolGap(gap);
      await call("close_binary");
      report.checks = [
        "independent DOL header and ELF/readelf agreement",
        "section file bytes and BSS gap set",
        "MCP open_binary format gamecube-dol and load-image attestation",
        "__start at entry, direct call to leaf, decompile",
        "data, tail, marker and BSS-gap bytes",
      ];
      report.procedures = procedures.length;
    } else {
      await call("close_binary");
      report.checks = [
        "MCP open with override",
        "load-image attestation with overridden language",
      ];
    }
  } catch (cause) {
    throw new Error(`GameCube DOL ${label} failed; MCP stderr: ${stderr}`, {
      cause,
    });
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
  if (languageOverride === undefined) {
    // CLI path through the same stock lane, not a private injected provider.
    const cli = await execute(
      process.execPath,
      [
        entrypoint,
        "function",
        fixture.path,
        "0x80003130",
        "--target-format",
        "gamecube-dol",
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
    const evidence = parseEvidence(JSON.parse(cli.stdout));
    assert.equal(evidence.subject?.architecture, "powerpc");
    assert.equal(evidence.subject?.digest.sha256, fixture.sha256);
    const cliDossier = functionDossierSchema.parse(evidence.normalized_result);
    assert.equal(BigInt(cliDossier.procedure.address), DOL_ENTRY);
    assert.ok(cliDossier.pseudocode.includes("__start"));
    report.cli = {
      entry: cliDossier.procedure.address,
      subject_format: evidence.subject?.format ?? null,
    };
  }
  return report;
}

const reports = [];
let primaryFailure;
try {
  const fixture = await buildGameCubeDolFixture(workspace);
  const elfBytes = await readFile(fixture.elf_path);
  const dolBytes = await readFile(fixture.path);
  const independentElf = await inspectReadelfDolSource(fixture.elf_path);
  const dol = parseDolHeaderIndependent(dolBytes);
  const shape = assertDolAgainstElf(
    dol,
    dolBytes,
    elfBytes,
    independentElf,
    fixture,
  );
  const resolved = await parseBinaryTarget(fixture.path, {
    formatHint: "gamecube-dol",
  });
  if (!resolved.ok) throw resolved.error;
  assert.equal(resolved.value.format, "gamecube-dol");
  assert.equal(resolved.value.sha256, fixture.sha256);
  assert.equal(BigInt(resolved.value.entryPoint), DOL_ENTRY);
  reports.push({
    fixture: "stock",
    ...fixture,
    dol_shape: shape,
    readelf: independentElf.version,
  });
  reports.push(await runPass({ fixture, label: "stock language" }));
  if (await languageInstalled(GEKKO_LANGUAGE)) {
    reports.push(
      await runPass({
        fixture,
        languageOverride: GEKKO_LANGUAGE,
        label: "Gekko override",
      }),
    );
  } else {
    console.log(
      `skipped: ${GEKKO_LANGUAGE} not installed (GameCubeLoader extension absent); stock lane still verified`,
    );
  }
} catch (cause) {
  primaryFailure = cause;
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(
    `Cleanup unverified; retained diagnostic workspace: ${workspace}`,
    { cause: primaryFailure },
  );
if (primaryFailure !== undefined)
  throw new Error(
    `GameCube DOL verification failed; retained workspace: ${workspace}`,
    { cause: primaryFailure },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));
