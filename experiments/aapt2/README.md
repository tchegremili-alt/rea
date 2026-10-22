# AAPT2 resource workflow experiment

This unshipped draft evaluates APK inspection, direct compile/link and Apktool
rebuild with a caller-selected AAPT2 binary. Public integration remains subject
to the scope decision in [CONTRIBUTING.md](../../CONTRIBUTING.md#contribution-scope).
It complements the Android roadmap (#717); split-set identity is separately
discussed in #1813.

## Run

```sh
npm ci
npm run build:cached
node --test experiments/command-scope.test.mjs experiments/aapt2/prototype.test.mjs
node experiments/aapt2/verify.mjs --aapt2 /tools/aapt2 --apktool /tools/apktool \
  --framework /sdk/android.jar --output /lab/aapt2-result
```

The output directory must not exist. The experiment creates resource fixtures,
compiles and links a new APK, inspects badging/resources/string pools/configurations
and compiled XML, then decodes and rebuilds a copy with Apktool. It preserves
fixture, decoded-project, framework and linked-APK identities. Result APKs are
not signed or signature-verified by this workflow. A receipt retains tool output,
selected arguments, artifact hashes and timing; failed runs keep their output.
Failure receipts retain earlier commands, bounded stdout/stderr snapshots,
exit/signal observations, truncation flags and reported cleanup diagnostics.
Compound failures retain their members without serializing live process owners
or the ambient environment.

The real automated test is opt-in and reports a named skip without prerequisites:

```sh
REA_AAPT2_PROBE_COMMAND=/tools/aapt2 \
REA_AAPT2_PROBE_FRAMEWORK=/sdk/android.jar \
REA_APKTOOL_COMMAND=/tools/apktool \
node --test experiments/command-scope.test.mjs experiments/aapt2/prototype.test.mjs
```

## Verification

Linux with AAPT2 `2.19-10229193` (SDK build-tools 34.0.0), Android 35 framework,
Apktool `2.7.0-dirty`, OpenJDK 25.0.4.1 and Node 24.18.0 passed compile/link,
inspection and rebuilding. Default/German strings survived the round trip.
Malformed resources and missing frameworks were refused. Existing
`decode_android_resources` CLI/MCP results agreed for the generated APK.
Tests also cover output collisions and persisted failure/truncation receipts.
Cancellation waits for a marker from the actual child, authenticates its process
start identity with the run token and confirms that exact process has exited
before any fallback test cleanup.

Debian's `2.19-debian` AAPT2 rejected the Android 35 framework with an ARSC layout
error. The version prefix alone is therefore insufficient compatibility evidence;
future contracts must retain actual selected tool/framework identity.

An indicative warm-cache run took 61.19 s elapsed and 34.73 s host CPU, with a
839,786,496-byte payload-exit cgroup memory peak. Payload cleanup was verified;
final whole-scope counters were unavailable after scope exit. The observer is
included, and agent tokens are unmeasured. UI verification ran concurrently on the
same pinned CPU; cold measurements and comparative baselines are unmeasured.

## Remaining scope

These checks use controlled fixtures and Apktool 2.x's `--use-aapt2`/`--aapt`
interface. Apktool 3.x, other framework versions, large application resources,
cross-platform execution and new public inspection/build contracts remain
unverified. General caller-project admission, resource-limit calibration and
publication semantics need the maintainer decision before production integration.
