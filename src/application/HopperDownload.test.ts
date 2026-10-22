import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import { downloadHopperPackage } from "./HopperDownload.js";

const servers: Server[] = [];

const serve = async (
  handler: (response: ServerResponse) => void,
): Promise<string> => {
  const server = createServer((_request, response) => {
    handler(response);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${String(port)}/hopper.dmg`;
};

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => {
            resolve();
          });
        }),
    ),
  );
});

describe("downloadHopperPackage", () => {
  it("completes a slow download whose total time exceeds the idle limit", async () => {
    const chunks = 8;
    const url = await serve((response) => {
      response.writeHead(200, { "content-length": String(chunks) });
      let sent = 0;
      const timer = setInterval(() => {
        response.write("x");
        sent += 1;
        if (sent === chunks) {
          clearInterval(timer);
          response.end();
        }
      }, 40);
    });

    const result = await downloadHopperPackage(url, { idleTimeoutMs: 150 });

    expect(result.ok).toBe(true);
    expect(Buffer.from(result.bytes).toString()).toBe("x".repeat(chunks));
  });

  it("aborts a download that stops delivering bytes", async () => {
    const url = await serve((response) => {
      response.writeHead(200, { "content-length": "10" });
      response.write("x");
    });

    await expect(
      downloadHopperPackage(url, { idleTimeoutMs: 100 }),
    ).rejects.toThrow(/no bytes for 100 ms/u);
  });
});
