import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
	type HermesModelRelayReport,
	MODEL_RELAY_OBSERVED_PEER_HEADER,
	runHermesModelRelayProbe,
} from "../../src/hermes/model-relay.js";

describe("Hermes model-relay probe", () => {
	const tempDirs: string[] = [];
	const directModelUrl = "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0";
	const relayProxyUrl = "http://telclaude:8790/v1/openai-codex-proxy";
	const relayProbeUrl = "http://telclaude:8790/v1/models";
	const containedIp = "192.0.2.11";
	const relayIp = "192.0.2.10";
	const originalInferenceModel = process.env.HERMES_INFERENCE_MODEL;
	const originalCodexBaseUrl = process.env.HERMES_CODEX_BASE_URL;

	beforeEach(() => {
		process.env.HERMES_INFERENCE_MODEL = "gpt-5.5";
		process.env.HERMES_CODEX_BASE_URL = relayProxyUrl;
	});

	afterEach(async () => {
		for (const dir of tempDirs.splice(0)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
		if (originalInferenceModel === undefined) {
			delete process.env.HERMES_INFERENCE_MODEL;
		} else {
			process.env.HERMES_INFERENCE_MODEL = originalInferenceModel;
		}
		if (originalCodexBaseUrl === undefined) {
			delete process.env.HERMES_CODEX_BASE_URL;
		} else {
			process.env.HERMES_CODEX_BASE_URL = originalCodexBaseUrl;
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

	it("keeps the firewall sentinel gate for agent-iptables posture", async () => {
		const relayUrl = relayProbeUrl;
		const tempDir = makeTempDir();
		const profileDir = path.join(tempDir, "profile");
		fs.mkdirSync(profileDir);
		writeRelayCredentialProfile(profileDir);
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
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("pass");
		expect(report.modelProvider).toMatchObject({
			provider: "openai-codex",
			baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			baseUrlHost: "telclaude",
			model: "gpt-5.5",
			modelSource: "env:HERMES_INFERENCE_MODEL",
			authLocation: "hermes-auth-store:openai-codex",
			authScope: "relay-openai-codex-subscription-proxy",
			auxiliaryAuthSource: "manual:telclaude-relay",
			auxiliaryBaseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			auxiliaryBaseUrlHost: "telclaude",
			refreshTokenPolicy: "non-refreshable-placeholder",
		});
		expect(report.posture).toBe("agent-iptables");
		expect(gate(report, "firewall.sentinel")).toMatchObject({ status: "pass" });
		expect(gate(report, "modelRelay.modelProvider")).toMatchObject({ status: "pass" });
		expect(gate(report, "modelRelay.origin")).toMatchObject({ status: "pass" });
		expect(gate(report, "relay.reachable")).toMatchObject({ status: "pass" });
		expect(gate(report, "directModel.denied")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.relayCredentialReference")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.noRawModelCredentials")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.noDirectModelHosts")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.scanComplete")).toMatchObject({ status: "pass" });
	});

	it("passes contained-internal posture without a fake firewall sentinel", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			posture: "contained-internal",
			relayUrl,
			directModelUrl,
			profileDir,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			relayPeerAddress: relayIp,
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("pass");
		expect(report.posture).toBe("contained-internal");
		expect(report.gates.some((candidate) => candidate.name === "firewall.sentinel")).toBe(false);
		expect(gate(report, "modelRelay.modelProvider")).toMatchObject({ status: "pass" });
		expect(gate(report, "modelRelay.origin")).toMatchObject({ status: "pass" });
		expect(gate(report, "directModel.denied")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.relayCredentialReference")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.noRawModelCredentials")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.noDirectModelHosts")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.scanComplete")).toMatchObject({ status: "pass" });
	});

	it("fails closed when direct model-provider egress is reachable", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir, sentinel } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: modelRelayFetch("reachable"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "directModel.denied")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("reached HTTP status 401"),
		});
	});

	it("fails closed when the generated profile lacks a relay credential reference", async () => {
		const relayUrl = relayProbeUrl;
		const tempDir = makeTempDir();
		const profileDir = path.join(tempDir, "profile");
		fs.mkdirSync(profileDir);
		fs.writeFileSync(path.join(profileDir, "config.yaml"), "model_provider: none\n");
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
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "profile.relayCredentialReference")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("openai-codex-relay provider"),
		});
	});

	it("does not accept relay reference strings outside canonical profile files", async () => {
		const relayUrl = relayProbeUrl;
		const tempDir = makeTempDir();
		const profileDir = path.join(tempDir, "profile");
		fs.mkdirSync(profileDir);
		fs.writeFileSync(path.join(profileDir, "config.yaml"), "model_provider: none\n");
		fs.writeFileSync(
			path.join(profileDir, "README.md"),
			[
				"provider: openai-codex-relay",
				"baseUrl: http://telclaude:8790/v1/openai-codex-proxy",
				"credentialSource: telclaude-relay-auth-store",
				'{"rawCredentialPolicy":"relay-owned-only"}',
			].join("\n"),
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
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "profile.relayCredentialReference")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("secret-manifest.json"),
		});
	});

	it("fails closed when the relay endpoint is not a successful response", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir, sentinel } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: modelRelayFetch("denied", { status: 500 }),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "relay.reachable")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("HTTP status 500"),
		});
	});

	it("does not treat a direct model-provider timeout as positive denial evidence", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir, sentinel } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: modelRelayFetch("timeout"),
			timeoutMs: 20,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "directModel.denied")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("without a positive denial"),
		});
	});

	it("fails closed before network probing when the direct model URL is synthetic", async () => {
		const relayUrl = relayProbeUrl;
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
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "directModel.target")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("recognized provider host"),
		});
	});

	it("fails closed when firewall or contained-origin proof is missing", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir } = makeCleanProfile();

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			fetchImpl: modelRelayFetch("denied", { observedPeerAddress: undefined }),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "firewall.sentinel")).toMatchObject({ status: "fail" });
		expect(gate(report, "modelRelay.origin")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("server-observed contained peer IP"),
		});
	});

	it("scans script files for model credentials instead of skipping them", async () => {
		const relayUrl = relayProbeUrl;
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
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "profile.noRawModelCredentials")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("provider.py"),
		});
		expect(gate(report, "profile.scanComplete")).toMatchObject({ status: "pass" });
	});

	it("accepts the canonical MCP relay token-file reference", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir, sentinel } = makeCleanProfile();
		fs.writeFileSync(
			path.join(profileDir, "mcp.json"),
			`${JSON.stringify(
				{
					schemaVersion: 1,
					servers: {
						telclaudeRelay: {
							transport: "http",
							url: "http://telclaude:8790/v1/hermes/mcp",
							auth: "relay-token-file",
						},
					},
				},
				null,
				2,
			)}\n`,
		);

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			relayPeerAddress: relayIp,
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("pass");
		expect(gate(report, "profile.noRawModelCredentials")).toMatchObject({ status: "pass" });
		expect(gate(report, "profile.scanComplete")).toMatchObject({ status: "pass" });
	});

	it("fails closed when generated MCP config contains raw bearer material", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir, sentinel } = makeCleanProfile();
		fs.writeFileSync(
			path.join(profileDir, "mcp.json"),
			`${JSON.stringify(
				{
					schemaVersion: 1,
					servers: {
						telclaudeRelay: {
							transport: "http",
							url: "http://telclaude:8790/v1/hermes/mcp",
							auth: "Bearer bearer-token-value-1234567890",
						},
					},
				},
				null,
				2,
			)}\n`,
		);

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			relayPeerAddress: relayIp,
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "profile.noRawModelCredentials")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("mcp.json"),
		});
		expect(gate(report, "profile.scanComplete")).toMatchObject({ status: "pass" });
	});

	it("fails closed on auth.json, Codex OAuth state, JWTs, and cookie/session tokens", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir, sentinel } = makeCleanProfile();
		fs.writeFileSync(
			path.join(profileDir, "auth.json"),
			JSON.stringify({
				access_token: "access_token_value_1234567890",
				refresh_token: "refresh_token_value_1234567890",
			}),
		);
		const codexDir = path.join(profileDir, ".codex");
		fs.mkdirSync(codexDir);
		fs.writeFileSync(
			path.join(codexDir, "auth.json"),
			JSON.stringify({
				id_token:
					"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjb2RleC1vYXV0aCJ9.signatureValue1234567890",
			}),
		);
		fs.writeFileSync(
			path.join(profileDir, "cookies.txt"),
			"session_token=session-token-value-1234567890\nAuthorization: Bearer bearer-token-value-1234567890\n",
		);
		fs.writeFileSync(
			path.join(profileDir, "profile.json"),
			JSON.stringify({
				api_key: "sk-proj-raw-provider-key-1234567890",
				refresh_token: "refresh-token-value-1234567890",
			}),
		);

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		const rawCredentialGate = gate(report, "profile.noRawModelCredentials");
		expect(rawCredentialGate).toMatchObject({ status: "fail" });
		expect(rawCredentialGate.detail).toContain("auth.json");
		expect(rawCredentialGate.detail).toContain(path.join(".codex", "auth.json"));
		expect(rawCredentialGate.detail).toContain("cookies.txt");
		expect(rawCredentialGate.detail).toContain("profile.json");
		expect(gate(report, "profile.scanComplete")).toMatchObject({ status: "pass" });
	});

	it("fails closed when profile files cannot be fully scanned", async () => {
		const relayUrl = relayProbeUrl;
		const { profileDir, sentinel } = makeCleanProfile();
		fs.writeFileSync(path.join(profileDir, "oversized.bin"), Buffer.alloc(1_000_001));

		const report = await runHermesModelRelayProbe({
			allowRun: true,
			relayUrl,
			directModelUrl,
			profileDir,
			firewallSentinelPath: sentinel,
			containerName: DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME,
			expectedPeerAddress: containedIp,
			fetchImpl: modelRelayFetch("denied"),
			timeoutMs: 200,
		});

		expect(report.status).toBe("fail");
		expect(gate(report, "profile.scanComplete")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("oversized.bin"),
		});
	});

	it("fails closed when generated profile contains raw model credentials or direct model hosts", async () => {
		const relayUrl = relayProbeUrl;
		const tempDir = makeTempDir();
		const profileDir = path.join(tempDir, "profile");
		fs.mkdirSync(profileDir);
		fs.writeFileSync(
			path.join(profileDir, ".env"),
			"OPENAI_API_KEY=sk-secret\nHERMES_CODEX_BASE_URL=https://chatgpt.com/backend-api/codex\n",
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
			fetchImpl: modelRelayFetch("denied"),
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
		writeRelayCredentialProfile(profileDir);
		const sentinel = path.join(tempDir, "firewall-active");
		fs.writeFileSync(sentinel, "active\n");
		return { profileDir, sentinel };
	}

	function writeRelayCredentialProfile(profileDir: string): void {
		fs.writeFileSync(
			path.join(profileDir, "config.yaml"),
			[
				"model:",
				"  provider: openai-codex-relay",
				`  baseUrl: ${relayProxyUrl}`,
				"  credentialSource: telclaude-relay-auth-store",
				"",
			].join("\n"),
		);
		fs.writeFileSync(
			path.join(profileDir, "secret-manifest.json"),
			`${JSON.stringify({ schemaVersion: 1, rawCredentialPolicy: "relay-owned-only" }, null, 2)}\n`,
		);
	}

	function makeTempDir(): string {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-"));
		tempDirs.push(dir);
		return dir;
	}

	function modelRelayFetch(
		result: "denied" | "reachable" | "timeout",
		relay: { status?: number; observedPeerAddress?: string } = {},
	): typeof fetch {
		const realFetch = globalThis.fetch;
		return async (input, init) => {
			if (String(input) === relayProbeUrl) {
				const headers = new Headers();
				const observedPeerAddress =
					"observedPeerAddress" in relay ? relay.observedPeerAddress : containedIp;
				if (observedPeerAddress) {
					headers.set(MODEL_RELAY_OBSERVED_PEER_HEADER, observedPeerAddress);
				}
				return new Response(null, { status: relay.status ?? 204, headers });
			}
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
