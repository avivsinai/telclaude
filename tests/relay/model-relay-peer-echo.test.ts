import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { MODEL_RELAY_OBSERVED_PEER_HEADER } from "../../src/hermes/model-relay.js";
import { startCapabilityServer } from "../../src/relay/capabilities.js";

describe("relay model-relay peer echo", () => {
	let server: ReturnType<typeof startCapabilityServer> | null = null;

	afterEach(async () => {
		if (!server) return;
		await new Promise<void>((resolve, reject) => {
			server?.close((error) => (error ? reject(error) : resolve()));
		});
		server = null;
	});

	it("emits a server-observed peer header only on the model relay probe endpoint", async () => {
		server = startCapabilityServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		const address = server.address() as AddressInfo;
		const baseUrl = `http://127.0.0.1:${address.port}`;

		const probe = await fetch(`${baseUrl}/v1/models`);
		expect(probe.status).toBe(204);
		expect(probe.headers.get(MODEL_RELAY_OBSERVED_PEER_HEADER)).toBe("127.0.0.1");

		const health = await fetch(`${baseUrl}/health`);
		expect(health.status).toBe(200);
		expect(health.headers.get(MODEL_RELAY_OBSERVED_PEER_HEADER)).toBeNull();
	});
});
