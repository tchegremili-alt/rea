import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parseConfig } from "../dist/config/parseConfig.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { SUPPORTED_GHIDRA_VERSION } from "../dist/ghidra/GhidraReleasePolicy.js";
import { cleanupOwnedProcessGroup } from "../dist/process/ProcessOwnership.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../dist/process/ProviderProcess.js";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const exec = promisify(execFile);
const run = createVerifierRun();
assert.ok(
  process.platform === "linux" || process.platform === "darwin",
  "This regression lane requires Linux or macOS",
);
const config = parseConfig(process.env);
if (!config.ok) throw config.error;
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: config.value.ghidraInstallDir,
  javaHome: config.value.ghidraJavaHome,
});
assert.equal(installation.status, "available", JSON.stringify(installation));
assert.equal(installation.providerVersion, SUPPORTED_GHIDRA_VERSION);
const fixtures = fileURLToPath(
  new URL("../tests/conformance/ghidra", import.meta.url),
);
const bridge = fileURLToPath(new URL("../bridge/ghidra", import.meta.url));
const clang = process.env.REA_CLANG ?? "clang";
const formats = [
  "elf",
  ...(process.platform === "darwin" && process.arch === "arm64"
    ? ["mach-o"]
    : []),
];
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const workspace = await mkdtemp(join(tmpdir(), "rea-ghidra-warning-"));
let cleaned = true;
const reports = [];
try {
  const bridgeDigest = digest(
    await readFile(join(bridge, "ReaGhidraBridge.java")),
  );
  for (const format of formats) {
    const targetPath = join(workspace, `removed-block-${format}.o`);
    await exec(clang, [
      ...(format === "elf" ? ["--target=aarch64-linux-gnu"] : []),
      "-c",
      join(fixtures, "decompiler-removed-block.S"),
      "-o",
      targetPath,
    ]);
    const targetDigest = digest(await readFile(targetPath));
    const project = join(workspace, `project-${format}`);
    await mkdir(project);
    const launch = await spawnOwnedProviderProcess({
      command: installation.analyzeHeadlessPath,
      arguments: [
        project,
        "WarningProvenance",
        "-import",
        targetPath,
        "-readOnly",
        "-deleteProject",
        "-scriptPath",
        `${fixtures};${bridge}`,
        "-postScript",
        join(fixtures, "ReaDecompilerWarningProvenanceProbe.java"),
        bridge,
      ],
      runId: run.run_id,
      expectedCommand: null,
    });
    const supervisor = new ProviderProcessSupervisor({
      ...launch,
      ownsProcessLifetime: true,
      cleanup: () => cleanupOwnedProcessGroup(launch.ownership),
    });
    try {
      assert.ok(
        await supervisor.waitForExit(180000),
        `${format} warning provenance probe timed out`,
      );
      assert.ok(
        await supervisor.waitForOutputClose(1000),
        `${format} warning provenance probe output did not close`,
      );
      const snapshot = supervisor.snapshot();
      const output = `${snapshot.stdout.text}\n${snapshot.stderr.text}`;
      assert.equal(snapshot.exitCode, 0, output);
      const found = [
        ...output.matchAll(
          /REA_WARNING_PROVENANCE_PROBE_JSON (\{[^\r\n]*\})/gu,
        ),
      ];
      assert.equal(found.length, 1, output);
      const probe = JSON.parse(found[0][1]);
      assert.equal(probe.status, "passed");
      assert.equal(probe.ghidra_version, SUPPORTED_GHIDRA_VERSION);
      assert.equal(probe.target_sha256, targetDigest);
      assert.equal(probe["ReaGhidraBridge.java"], bridgeDigest);
      for (const check of [
        "baseline_real_removal",
        "plate_decoy_rendered_as_header",
        "plate_decoy_not_recorded",
        "plate_decoy_no_omission_limitation",
        "plate_decoy_comment_retained",
        "plate_unmapped_decoy_not_recorded",
        "repeated_warning_rendered_twice",
        "repeated_warning_keeps_real_removal",
      ])
        assert.ok(probe.checks.includes(check), `${format}: ${check}`);
      reports.push({
        format,
        removed_start: probe.removed_start,
        checks: probe.checks,
      });
    } finally {
      const stopped = await supervisor.stop();
      cleaned = stopped.status === "verified-cleanup";
      assert.ok(
        cleaned,
        `Owned cleanup incomplete; retained ${workspace}: ${JSON.stringify(stopped)}`,
      );
    }
    assert.equal(digest(await readFile(targetPath)), targetDigest);
  }
} finally {
  if (cleaned) await rm(workspace, { recursive: true, force: true });
}
console.log(
  JSON.stringify({
    status: "passed",
    targets: reports,
    scope:
      "Real Ghidra AArch64 ELF (and Mach-O on Apple Silicon) objects with caller-authored entry plate comments, through the production bridge's analyze_function observation. Plate comments cannot be set through REA's public tools, so this lane drives the bridge in-process; no target execution.",
    cleanup: "complete",
    verifier_run: await completeVerifierRun(run),
  }),
);
