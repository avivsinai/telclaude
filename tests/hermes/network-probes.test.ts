import net from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runHermesNetworkProbes } from "../../src/hermes/network-probes.js";

describe("Hermes network probes", () => {
	it("uses provider URL prefixes as provider-specific direct-deny attempt names", async () => {
		const deniedProviderUrl = await closedProbeUrl();
		const report = await runHermesNetworkProbes({
			allowRun: true,
			posture: "contained-internal",
			providerUrls: [`bank=${deniedProviderUrl}`, `clalit=${deniedProviderUrl}`],
			vaultSocketPath: path.join(os.tmpdir(), "missing-hermes-vault.sock"),
			modelProviderUrl: await closedProbeUrl(),
			dnsExfilUrls: [await closedProbeUrl()],
			firewallSentinelPath: path.join(os.tmpdir(), "missing-hermes-firewall-sentinel"),
			timeoutMs: 100,
			now: new Date("2026-06-01T09:10:00.000Z"),
		});
		const directProviderEvidence = report.evidence.find(
			(probe) => probe.id === "network.direct-provider-denied",
		);

		expect(directProviderEvidence?.attempts.map((attempt) => attempt.name)).toEqual([
			"provider:bank",
			"provider:clalit",
		]);
		expect(directProviderEvidence?.attempts.every((attempt) => attempt.status === "pass")).toBe(
			true,
		);
	});
});

async function closedProbeUrl(): Promise<string> {
	const server = net.createServer();
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("expected TCP server address");
	}
	await new Promise<void>((resolve, reject) => {
		server.close((error) => (error ? reject(error) : resolve()));
	});
	return `http://127.0.0.1:${address.port}/probe`;
}
