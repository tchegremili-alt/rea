import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { withCommands } from "./command-scope.mjs";
import { cleanupOwnedProcessGroup } from "../dist/process/ProcessOwnership.js";
import {
  observeProcessStartIdentity,
  observeProcessStartIdentityExit,
} from "../dist/process/ProcessOwnershipObservation.js";

test("retains bounded producer diagnostics and a nonzero process outcome", async () => {
  await assert.rejects(
    withCommands((run) =>
      run(process.execPath, [
        "-e",
        "process.stderr.write('fixture refusal');process.exit(9)",
      ]),
    ),
    (error) => {
      assert.equal(error.reason, "process");
      assert.equal(error.snapshot.exitCode, 9);
      assert.equal(error.snapshot.stderr.text, "fixture refusal");
      return true;
    },
  );
});
test("refuses incomplete output instead of accepting a truncated result", async () => {
  await assert.rejects(
    withCommands((run) =>
      run(process.execPath, ["-e", "process.stdout.write('x'.repeat(8192))"], {
        maxBytes: 1024,
      }),
    ),
    (error) => error.reason === "output-limit",
  );
});
test(
  "cancels a ready owned child and verifies its exact process has exited",
  {
    skip:
      process.platform === "win32"
        ? "POSIX process-group signal verification"
        : false,
  },
  async () => {
    const scope = await mkdtemp(join(tmpdir(), "rea-command-scope-"));
    const marker = join(scope, "child.ready");
    // The marker is written by the owned long-running child itself, so the
    // parent only signals once cancellation must interrupt an active child
    // rather than ownership preparation.
    const grandchild = `import {writeFileSync,renameSync} from 'node:fs';
writeFileSync(${JSON.stringify(marker + ".tmp")}, JSON.stringify({pid:process.pid,runId:process.env.REA_PROCESS_RUN_ID}), {flag:'wx'});
renameSync(${JSON.stringify(marker + ".tmp")}, ${JSON.stringify(marker)});
setInterval(()=>{},1000);`;
    const module = new URL("./command-scope.mjs", import.meta.url).href;
    const code = `import {withCommands} from ${JSON.stringify(module)};
try { await withCommands(async run => { await run(process.execPath,['-e',${JSON.stringify(grandchild)}]); }); }
catch (error) { process.stdout.write(error.reason+'\\n'); process.exitCode=error.reason==='cancelled'?0:1; }`;
    const child = spawn(process.execPath, ["--input-type=module", "-e", code], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    let diagnostic = "";
    child.stderr.on("data", (chunk) => {
      diagnostic += chunk;
    });
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    const closed = once(child, "close");
    void closed.catch(() => {});
    let wrapperClosed = false;
    child.once("close", () => {
      wrapperClosed = true;
    });
    const timeout = setTimeout(() => {
      if (!wrapperClosed) child.kill("SIGKILL");
    }, 10_000);
    let ownership;
    let childIdentity;
    const readOwnership = async () => {
      const ready = JSON.parse(await readFile(marker, "utf8"));
      assert(Number.isSafeInteger(ready.pid) && ready.pid > 0);
      assert.equal(typeof ready.runId, "string");
      assert(ready.runId.length > 0);
      return {
        runId: ready.runId,
        leaderPid: ready.pid,
        processGroupId: ready.pid,
      };
    };
    try {
      const deadline = Date.now() + 10_000;
      while (!existsSync(marker)) {
        assert.equal(wrapperClosed, false, output + diagnostic);
        if (Date.now() > deadline)
          throw new Error("owned child never started", { cause: output });
        await delay(50);
      }
      ownership = await readOwnership();
      const identity = await observeProcessStartIdentity(
        ownership.leaderPid,
        undefined,
        ownership.runId,
      );
      assert.equal(
        identity?.state,
        "readable",
        "The actual child must be live and token-owned before cancellation",
      );
      childIdentity = identity.identity;
      assert.equal(
        await observeProcessStartIdentityExit(
          ownership.leaderPid,
          identity.identity,
        ),
        "present",
      );
      assert.equal(child.kill("SIGINT"), true);
      const [exit, signal] = await closed;
      assert.equal(exit, 0, output + diagnostic);
      assert.equal(signal, null, output + diagnostic);
      assert.match(output, /cancelled/u);
      assert.equal(
        await observeProcessStartIdentityExit(
          ownership.leaderPid,
          identity.identity,
        ),
        "exited",
        "Reporting cancellation must not leave the actual owned child alive",
      );
    } finally {
      clearTimeout(timeout);
      if (!wrapperClosed) child.kill("SIGKILL");
      await closed.catch(() => {});
      // Preserve safe fallback cleanup even if readiness or the exit oracle fails.
      // This runs after the assertion, so it cannot turn leaked work into a pass.
      if (ownership === undefined && existsSync(marker))
        ownership = await readOwnership();
      if (ownership !== undefined) {
        const cleanup = await cleanupOwnedProcessGroup(ownership);
        assert.equal(cleanup.cleaned, true, JSON.stringify(cleanup));
        if (childIdentity !== undefined) {
          const deadline = Date.now() + 5000;
          let exit = await observeProcessStartIdentityExit(
            ownership.leaderPid,
            childIdentity,
          );
          while (exit === "present" && Date.now() < deadline) {
            await delay(25);
            exit = await observeProcessStartIdentityExit(
              ownership.leaderPid,
              childIdentity,
            );
          }
          assert.equal(
            exit,
            "exited",
            "Fallback cleanup must confirm the same child's exit",
          );
        }
      }
      await rm(scope, { recursive: true, force: true });
    }
  },
);
