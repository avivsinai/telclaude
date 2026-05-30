import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
	type HermesModelRelayReport,
	MODEL_RELAY_OBSERVED_PEER_HEADER,
	runHermesModelRelayProbe,
} from "../../src/hermes/model-relay.js";

describe("Hermes model-relay probe", () => {
	const tempDirs: string[] = [];
	const servers: http.Server[] = [];
	const directModelUrl = "https://api.anthropic.com/v1/models";
	const containedIp = "172.29.92.11";
	const relayIp = "172.29.92.10";

	afterEach(async () => {
		await Promise.all(
			servers.splice(0).map(
				(server) =>
					new Promise<void>((resolve) => {
						server.close(() => resolve());
					}),
			),
		);
		for (const dir of tempDirs.splice(0)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("does not produce production evidence without explicit allow-run", async () => {
		const report = await runHermesModelRelayProbe({ allowRun: false });

		expect(report).toMatchObject({
			status: "pending",
			ran: false,
			summary: "Hermes model-relay probe requires --allow-run",
		});
		expect(gate(report, "modelRelay.allowed")).toMatchObject({ status: "pending" });
	});

	it("passes only when relay is reachable, direct model egress is denied, and profile has no model secrets", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, containedIp);
			res.writeHead(204).end();
		});
		const tempDir = makeTempDir();
		const profileDir = path.join(tempDir, "profile");
		fs.mkdirSync(profileDir);
		fs.writeFileSync(
			path.join(profileDir, "config.yaml"),
			"model_provider: telclaude-relay\nmodel_base_url: http://telclaude:8790/v1/models\n",
		);
		const sentinel = path.join(tempDir, "firewall-active");
		fs.writeFileSync(sentinel, "active\n");

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			relayPeerAddress: relayIp,
			fetchImpl: directModelFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("pass");
		expect(gate(report, "firewall.sentinel")).toMatchObject({ status: "pass" });
		expect(gate(report, "modelRelay.origin")).toMatchObject({ status: "pass" });
		expect(gate(report, "relay.reachable")).toMatchObject({ status: "pass" });
		expect(gate(report, "directModel.denied")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.noRawModelCredentials")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.noDirectModelHosts")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.scanComplete")).toMatchObject({ status: "pass" });
	});

	it("fails closed when direct model-provider egress is reachable", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, containedIp);
			res.writeHead(204).end();
		});
		const { profileDir, sentinel } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: directModelFetch("reachable"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "directModel.denied")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("reached HTTP status 401"),
		});
	});

	it("fails closed when the relay endpoint is not a successful response", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, containedIp);
			res.writeHead(500).end();
		});
		const { profileDir, sentinel } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: directModelFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "relay.reachable")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("HTTP status 500"),
		});
	});

	it("does not treat a direct model-provider timeout as positive denial evidence", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, containedIp);
			res.writeHead(204).end();
		});
		const { profileDir, sentinel } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: directModelFetch("timeout"),
			timeoutMs: 20,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "directModel.denied")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("without a positive denial"),
		});
	});

	it("fails closed before network probing when the direct model URL is synthetic", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, containedIp);
			res.writeHead(204).end();
		});
		const syntheticDirectModelUrl = await closedLocalUrl();
		const { profileDir, sentinel } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl: syntheticDirectModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "directModel.target")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("recognized provider host"),
		});
	});

	it("fails closed when firewall or contained-origin proof is missing", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.writeHead(204).end();
		});
		const { profileDir } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			fetchImpl: directModelFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "firewall.sentinel")).toMatchObject({ status: "fail" });
		expect(gate(report, "modelRelay.origin")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("server-observed contained peer IP"),
		});
	});

	it("fails closed when profile files are skipped", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, containedIp);
			res.writeHead(204).end();
		});
		const { profileDir, sentinel } = makeCleanProfile();
		fs.writeFileSync(path.join(profileDir, "provider.py"), "ANTHROPIC_API_KEY='sk-secret'\n");

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: directModelFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "profile.scanComplete")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("provider.py"),
		});
	});

	it("fails closed when generated profile contains raw model credentials or direct model hosts", async () => {
		const relayUrl = await startServer((_req, res) => {
			res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, containedIp);
			res.writeHead(204).end();
		});
		const tempDir = makeTempDir();
		const profileDir = path.join(tempDir, "profile");
		fs.mkdirSync(profileDir);
		fs.writeFileSync(
			path.join(profileDir, ".env"),
			"ANTHROPIC_API_KEY=sk-secret\nMODEL_BASE_URL=https://api.anthropic.com/v1\n",
		);
		const sentinel = path.join(tempDir, "firewall-active");
		fs.writeFileSync(sentinel, "active\n");

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: directModelFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "profile.noRawModelCredentials")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(".env"),
		});
		expect(gate(report, "profile.noDirectModelHosts")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(".env"),
		});
	});

	async function startServer(handler: http.RequestListener): Promise<string> {
		const server = http.createServer(handler);
		servers.push(server);
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const address = server.address();
		if (!address || typeof address === "string") throw new Error("server did not bind TCP");
		return `http://127.0.0.1:${address.port}`;
	}

	async function closedLocalUrl(): Promise<string> {
		const server = http.createServer((_req, res) => res.writeHead(204).end());
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const address = server.address();
		if (!address || typeof address === "string") throw new Error("server did not bind TCP");
		const port = address.port;
		await new Promise<void>((resolve) => server.close(() => resolve()));
		return `http://127.0.0.1:${port}`;
	}

	function makeCleanProfile(): { profileDir: string; sentinel: string } {
		const tempDir = makeTempDir();
		const profileDir = path.join(tempDir, "profile");
		fs.mkdirSync(profileDir);
		fs.writeFileSync(path.join(profileDir, "config.yaml"), "model_provider: telclaude-relay\n");
		const sentinel = path.join(tempDir, "firewall-active");
		fs.writeFileSync(sentinel, "active\n");
		return { profileDir, sentinel };
	}

	function makeTempDir(): string {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-"));
		tempDirs.push(dir);
		return dir;
	}

	function directModelFetch(result: "denied" | "reachable" | "timeout"): typeof fetch {
		const realFetch = globalThis.fetch;
		return async (input, init) => {
			if (String(input) !== directModelUrl) return realFetch(input, init);
			if (result === "reachable") return new Response(null, { status: 401 });
			if (result === "denied") throw positiveDenialError();
			return new Promise<Response>((_resolve, reject) => {
				const abort = () => reject(new DOMException("The operation was aborted", "AbortError"));
				if (init?.signal?.aborted) {
					abort();
					return;
				}
				init?.signal?.addEventListener("abort", abort, { once: true });
			});
		};
	}

	function positiveDenialError(): Error {
		const error = new TypeError("fetch failed") as Error & { cause?: { code: string } };
		error.cause = { code: "ECONNREFUSED" };
		return error;
	}

	function gate(report: HermesModelRelayReport, name: string) {
		const found = report.gates.find((candidate) => candidate.name === name);
		if (!found) throw new Error(`missing gate ${name}`);
		return found;
	}
});
