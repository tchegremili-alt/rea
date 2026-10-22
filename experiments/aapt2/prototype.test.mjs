import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { withCommands } from "../command-scope.mjs";

const script = fileURLToPath(new URL("./verify.mjs", import.meta.url));
test("refuses an occupied output directory without overwriting its contents", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-aapt2-collision-"));
  const marker = join(root, "preserve.txt");
  await writeFile(marker, "caller evidence");
  try {
    await assert.rejects(
      withCommands((run) =>
        run(process.execPath, [
          script,
          "--aapt2",
          "missing-aapt2",
          "--apktool",
          "missing-apktool",
          "--framework",
          "missing.jar",
          "--output",
          root,
        ]),
      ),
      (error) =>
        error.reason === "process" &&
        error.snapshot.stderr.text.includes("EEXIST"),
    );
    assert.equal(await readFile(marker, "utf8"), "caller evidence");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
for (const mode of ["exit", "truncation"])
  test(
    `persists earlier commands and ${mode} diagnostics in a failed verifier receipt`,
    {
      skip:
        process.platform === "win32"
          ? "The selected executable fixture uses a POSIX shebang"
          : false,
    },
    async () => {
      const root = await mkdtemp(join(tmpdir(), "rea-aapt2-failure-"));
      const binary = join(root, "producer");
      const framework = join(root, "framework.jar");
      const output = join(root, "result");
      await writeFile(
        framework,
        "fixture input: compilation fails before linking",
      );
      await writeFile(
        binary,
        `#!${process.execPath}
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === 'version') console.log('fixture AAPT2');
else if (args.length === 1 && args[0] === '--version') console.log('fixture Apktool');
else if (args.length === 5 && args[0] === 'compile' && args[1] === '--dir' && args[3] === '-o') {
  ${mode === "exit" ? "process.stdout.write('partial compile output'); process.stderr.write('fixture compile refused'); process.exitCode = 9;" : "process.stdout.write('x'.repeat(5 * 1024 * 1024));"}
} else { console.error('unmodeled command', args); process.exitCode = 97; }
`,
        { mode: 0o700 },
      );
      try {
        await assert.rejects(
          withCommands((run) =>
            run(
              process.execPath,
              [
                script,
                "--aapt2",
                binary,
                "--apktool",
                binary,
                "--framework",
                framework,
                "--output",
                output,
              ],
              { maxBytes: 1024 * 1024 },
            ),
          ),
          (error) =>
            error.reason === "process" && error.snapshot.exitCode === 1,
        );
        const receipt = JSON.parse(
          await readFile(join(output, "receipt.json"), "utf8"),
        );
        assert.equal(receipt.outcome, "failed");
        assert.equal(receipt.commands.length, 3);
        assert.equal(receipt.commands[0].outcome, "completed");
        assert.equal(receipt.commands[0].stdout, "fixture AAPT2\n");
        assert.equal(receipt.commands[1].stdout, "fixture Apktool\n");
        const failed = receipt.commands[2];
        assert.equal(failed.binary, binary);
        assert.equal(failed.arguments[0], "compile");
        assert.equal(failed.outcome, "failed");
        for (const record of [failed.error, receipt.failure]) {
          assert.equal(
            record.reason,
            mode === "exit" ? "process" : "output-limit",
          );
          assert(
            record.snapshot,
            "Owner-captured command diagnostics must survive the receipt",
          );
          assert.equal(record.cleanup_failure, null);
          assert.deepEqual(record.resources, []);
          assert.equal(record.collection_failure, false);
          if (mode === "exit") {
            assert.equal(record.snapshot.exitCode, 9);
            assert.equal(record.snapshot.signal, null);
            assert.equal(record.snapshot.stdout.text, "partial compile output");
            assert.equal(
              record.snapshot.stderr.text,
              "fixture compile refused",
            );
            assert.equal(
              record.snapshot.stderr.bytes,
              Buffer.byteLength("fixture compile refused"),
            );
          } else {
            assert.equal(record.snapshot.diagnosticTruncated, true);
            assert(record.snapshot.stdout.bytes > 0);
            assert(
              record.snapshot.stdout.bytes + record.snapshot.stderr.bytes <=
                4 * 1024 * 1024,
            );
            assert(
              record.snapshot.stdout.observedBytes >
                record.snapshot.stdout.bytes,
            );
          }
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
const framework = process.env.REA_AAPT2_PROBE_FRAMEWORK;
const aapt2 = process.env.REA_AAPT2_PROBE_COMMAND;
const apktool = process.env.REA_APKTOOL_COMMAND;
test(
  "real AAPT2 inspection, compile/link and Apktool rebuild preserve input identity",
  {
    skip:
      framework === undefined || aapt2 === undefined || apktool === undefined
        ? "Set REA_AAPT2_PROBE_FRAMEWORK, REA_AAPT2_PROBE_COMMAND and REA_APKTOOL_COMMAND for the real lane"
        : false,
    timeout: 300_000,
  },
  async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-aapt2-real-"));
    try {
      const output = join(root, "result");
      const result = await withCommands((run) =>
        run(
          process.execPath,
          [
            script,
            "--aapt2",
            aapt2,
            "--apktool",
            apktool,
            "--framework",
            framework,
            "--output",
            output,
          ],
          { timeoutMs: 240_000 },
        ),
      );
      assert.match(result.stdout, /prototype:.*passed/u);
      const receipt = JSON.parse(
        await readFile(join(output, "receipt.json"), "utf8"),
      );
      assert.equal(receipt.existing_decode_cli_mcp_parity, true);
      assert.equal(receipt.malformed_resource_refused, true);
      assert.equal(receipt.missing_framework_refused, true);
      assert.match(receipt.rebuilt.sha256, /^[a-f0-9]{64}$/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
