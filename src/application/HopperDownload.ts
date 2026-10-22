/** Maximum admitted vendor response bytes, shared by Hopper setup adapters. */
export const HOPPER_DOWNLOAD_BYTES = 100_000_000;

/** Abort only when the vendor stops delivering bytes; slow links may need far longer in total. */
const HOPPER_DOWNLOAD_IDLE_MS = 120_000;

/**
 * Bound observed response bytes before retaining them, including chunked bodies.
 * `timeoutMs` is an optional total budget for small responses; without it only
 * a stalled transfer (`idleTimeoutMs` without bytes) aborts.
 */
export const downloadHopperPackage = async (
  url: string,
  options: {
    readonly signal?: AbortSignal;
    readonly maxBytes?: number;
    readonly timeoutMs?: number;
    readonly idleTimeoutMs?: number;
  } = {},
): Promise<{ readonly ok: boolean; readonly bytes: Uint8Array }> => {
  const { timeoutMs } = options;
  if (
    timeoutMs !== undefined &&
    (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000)
  )
    throw new RangeError("Invalid Hopper response time budget");
  const maxBytes = options.maxBytes ?? HOPPER_DOWNLOAD_BYTES;
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > HOPPER_DOWNLOAD_BYTES
  )
    throw new RangeError("Invalid Hopper response byte budget");
  const idleTimeoutMs = options.idleTimeoutMs ?? HOPPER_DOWNLOAD_IDLE_MS;
  const idle = new AbortController();
  const stalled = (): void => {
    idle.abort(
      new DOMException(
        `Hopper download received no bytes for ${String(idleTimeoutMs)} ms`,
        "TimeoutError",
      ),
    );
  };
  let timer = setTimeout(stalled, idleTimeoutMs);
  const progressed = (): void => {
    clearTimeout(timer);
    timer = setTimeout(stalled, idleTimeoutMs);
  };
  const signals = [idle.signal];
  if (options.signal !== undefined) signals.push(options.signal);
  if (timeoutMs !== undefined) signals.push(AbortSignal.timeout(timeoutMs));
  try {
    const response = await fetch(url, {
      headers: { accept: "application/json", "user-agent": "rea-installer" },
      signal: AbortSignal.any(signals),
    });
    progressed();
    const refused = { ok: false, bytes: new Uint8Array() };
    if (
      !response.ok ||
      Number(response.headers.get("content-length")) > maxBytes
    ) {
      await response.body?.cancel();
      return refused;
    }
    if (response.body === null) return { ok: true, bytes: new Uint8Array() };
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done)
          return { ok: true, bytes: Buffer.concat(chunks, bytes) };
        progressed();
        if (chunk.value.byteLength > maxBytes - bytes) {
          await reader.cancel();
          return refused;
        }
        chunks.push(chunk.value);
        bytes += chunk.value.byteLength;
      }
    } finally {
      reader.releaseLock();
    }
  } finally {
    clearTimeout(timer);
  }
};
