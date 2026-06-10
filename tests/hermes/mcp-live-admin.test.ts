import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { TelclaudeMcpAuthorityConnection } from "../../src/hermes/mcp/authority-registry.js";
import type { TelclaudeMcpAuthority } from "../../src/hermes/mcp/bridge.js";
import {
	DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET,
	readTelclaudeLiveMcpAdminConfig,
	requestTelclaudeLiveMcpProbeTokens,
	startTelclaudeLiveMcpAdminServer,
	TELCLAUDE_LIVE_MCP_ADMIN_PROBE_TOKENS_PATH,
} from "../../src/hermes/mcp/live-admin.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";
import {
	startTelclaudeLiveMcpRuntime,
	type TelclaudeLiveMcpRuntimeConfig,
} from "../../src/hermes/mcp/live-runtime.js";
import { buildInternalAuthHeaders, generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_OPERATOR_PRIVATE = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
const ORIGINAL_OPERATOR_PUBLIC = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
const ORIGINAL_SOCIAL_PRIVATE = process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY;
const ORIGINAL_SOCIAL_PUBLIC = process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY;

describe("Telclaude live MCP admin socket", () => {
	it("is disabled by default and validates socket paths only when explicitly enabled", () => {
		expect(readTelclaudeLiveMcpAdminConfig({})).toEqual({
			enabled: false,
			socketPath: DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET,
		});
		expect(
			readTelclaudeLiveMcpAdminConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET: "relative.sock",
			}),
		).toEqual({
			enabled: false,
			socketPath: DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET,
		});
		expect(() =>
			readTelclaudeLiveMcpAdminConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED: "1",
				TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET: "relative.sock",
			}),
		).toThrow("must be absolute");
	});

	it("requires signed operator scope and does not log token material", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-live-admin-auth-"));
		const socketPath = path.join(tempDir, "admin.sock");
		const operatorKeys = generateKeyPair();
		const socialKeys = generateKeyPair();
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = operatorKeys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = operatorKeys.publicKey;
		process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY = socialKeys.privateKey;
		process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY = socialKeys.publicKey;
		const issuedInputs: unknown[] = [];
		const logLines: unknown[][] = [];
		const logger = {
			info: (...args: unknown[]) => logLines.push(args),
			warn: (...args: unknown[]) => logLines.push(args),
			error: (...args: unknown[]) => logLines.push(args),
			debug: (...args: unknown[]) => logLines.push(args),
		};
		const handle = await startTelclaudeLiveMcpAdminServer({
			socketPath,
			logger,
			issueProbeTokenBundle: (input) => {
				issuedInputs.push(input);
				return fixedTokenBundle();
			},
		});
		const body = JSON.stringify(probeTokenRequest());

		try {
			expect(fs.statSync(tempDir).mode & 0o777).toBe(0o700);
			expect(fs.statSync(socketPath).mode & 0o777).toBe(0o600);

			const unsigned = await postAdmin(socketPath, body);
			const wrongScope = await postAdmin(
				socketPath,
				body,
				buildInternalAuthHeaders("POST", TELCLAUDE_LIVE_MCP_ADMIN_PROBE_TOKENS_PATH, body, {
					scope: "social",
				}),
			);
			const wrongPath = await postAdmin(
				socketPath,
				body,
				buildInternalAuthHeaders("POST", "/v1/not-probe-tokens", body, {
					scope: "operator",
				}),
			);
			const allowed = await postAdmin(
				socketPath,
				body,
				buildInternalAuthHeaders("POST", TELCLAUDE_LIVE_MCP_ADMIN_PROBE_TOKENS_PATH, body, {
					scope: "operator",
				}),
			);

			expect(unsigned.statusCode).toBe(401);
			expect(wrongScope.statusCode).toBe(403);
			expect(wrongPath.statusCode).toBe(401);
			expect(allowed.statusCode).toBe(200);
			expect(allowed.body).toMatchObject({
				allowed: { token: "tc_mcp_conn_ALLOWEDSECRET" },
				wrongConnection: { token: "tc_mcp_conn_WRONGSECRET" },
				forged: { token: "tc_mcp_conn_FORGEDSECRET" },
				metadata: { tokenMaterial: "omitted" },
			});
			expect(issuedInputs).toHaveLength(1);
			const logged = JSON.stringify(logLines);
			expect(logged).not.toContain("tc_mcp_conn_ALLOWEDSECRET");
			expect(logged).not.toContain("Bearer tc_mcp_conn");
		} finally {
			await handle.stop();
			fs.rmSync(tempDir, { recursive: true, force: true });
			restoreEnv("OPERATOR_RPC_AGENT_PRIVATE_KEY", ORIGINAL_OPERATOR_PRIVATE);
			restoreEnv("OPERATOR_RPC_AGENT_PUBLIC_KEY", ORIGINAL_OPERATOR_PUBLIC);
			restoreEnv("SOCIAL_RPC_AGENT_PRIVATE_KEY", ORIGINAL_SOCIAL_PRIVATE);
			restoreEnv("SOCIAL_RPC_AGENT_PUBLIC_KEY", ORIGINAL_SOCIAL_PUBLIC);
		}
	});

	it("issues served-MCP probe tokens through a 0600 relay-local Unix socket", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-live-admin-"));
		const socketPath = path.join(tempDir, "admin.sock");
		const operatorKeys = generateKeyPair();
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = operatorKeys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = operatorKeys.publicKey;
		const runtime = await startTelclaudeLiveMcpRuntime({
			config: config(),
			nowMs: () => 2_000,
			admin: {
				start: (context) =>
					startTelclaudeLiveMcpAdminServer({
						socketPath,
						issueProbeTokenBundle: context.issueProbeTokenBundle,
					}),
			},
		});

		try {
			expect(fs.statSync(socketPath).mode & 0o777).toBe(0o600);
			const response = await requestTelclaudeLiveMcpProbeTokens({
				socketPath,
				input: {
					privateConnection: connection(),
					wrongConnection: connection({
						sessionKey: "probe:wrong",
						profileId: "social",
						endpointId: "endpoint-social",
					}),
					privateAuthority: authority(),
					nowMs: 1_000,
					ttlMs: 60_000,
					peerAddress: "127.0.0.1",
				},
			});

			expect(response).toMatchObject({
				metadata: {
					tokenMaterial: "omitted",
					peerBound: true,
					offDomainPeerBound: true,
				},
			});
			expect(response.allowed.token).toMatch(/^tc_mcp_conn_/);
			expect(response.offDomainPeer.token).toMatch(/^tc_mcp_conn_/);
			expect(response.forged.token).toMatch(/^tc_mcp_conn_/);
			expect(response.wrongConnection.token).toMatch(/^tc_mcp_conn_/);

			const initialized = await postRpc(
				runtime.endpoint?.url,
				response.allowed.authorizationHeader,
				{
					jsonrpc: "2.0",
					id: "initialize",
					method: "initialize",
				},
			);
			const wrong = await postRpc(
				runtime.endpoint?.url,
				response.wrongConnection.authorizationHeader,
				{
					jsonrpc: "2.0",
					id: "wrong",
					method: "tools/list",
				},
			);
			const forged = await postRpc(runtime.endpoint?.url, response.forged.authorizationHeader, {
				jsonrpc: "2.0",
				id: "forged",
				method: "tools/list",
			});

			expect(initialized.httpStatus).toBe(200);
			expect(wrong.httpStatus).toBe(403);
			expect(forged.httpStatus).toBe(403);
		} finally {
			await runtime.stop();
			restoreEnv("OPERATOR_RPC_AGENT_PRIVATE_KEY", ORIGINAL_OPERATOR_PRIVATE);
			restoreEnv("OPERATOR_RPC_AGENT_PUBLIC_KEY", ORIGINAL_OPERATOR_PUBLIC);
		}
		expect(fs.existsSync(socketPath)).toBe(false);
	});

	it("refuses to replace a non-socket admin path", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-live-admin-path-"));
		const socketPath = path.join(tempDir, "admin.sock");
		fs.writeFileSync(socketPath, "not a socket\n", "utf8");

		await expect(
			startTelclaudeLiveMcpAdminServer({
				socketPath,
				issueProbeTokenBundle: () => {
					throw new Error("must not issue tokens");
				},
			}),
		).rejects.toThrow("not a socket");
		expect(fs.readFileSync(socketPath, "utf8")).toBe("not a socket\n");
	});
});

function config(
	overrides: Partial<TelclaudeLiveMcpRuntimeConfig> = {},
): TelclaudeLiveMcpRuntimeConfig {
	return {
		enabled: true,
		host: "127.0.0.1",
		port: 0,
		path: "/mcp",
		networkName: "telclaude-hermes-relay",
		runtimeTransportToken: "tc-live-mcp-runtime-token",
		...overrides,
	};
}

function probeTokenRequest() {
	return {
		privateConnection: connection(),
		wrongConnection: connection({
			sessionKey: "probe:wrong",
			profileId: "social",
			endpointId: "endpoint-social",
		}),
		privateAuthority: authority(),
		nowMs: 1_000,
		ttlMs: 60_000,
	};
}

function fixedTokenBundle(): TelclaudeLiveMcpProbeTokenBundle {
	return {
		allowed: {
			token: "tc_mcp_conn_ALLOWEDSECRET",
			authorizationHeader: "Bearer tc_mcp_conn_ALLOWEDSECRET",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
		},
		wrongConnection: {
			token: "tc_mcp_conn_WRONGSECRET",
			authorizationHeader: "Bearer tc_mcp_conn_WRONGSECRET",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
		},
		forged: {
			token: "tc_mcp_conn_FORGEDSECRET",
			authorizationHeader: "Bearer tc_mcp_conn_FORGEDSECRET",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
		},
		metadata: {
			schemaVersion: "telclaude.hermes.live-mcp.probe-token-metadata.v1",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
			ttlMs: 60_000,
			tokenPrefix: "tc_mcp_conn_",
			tokenMaterial: "omitted",
			peerBound: false,
			privateConnection: {
				profileId: "default",
				endpointId: "endpoint-private",
				networkNamespace: "telclaude-hermes-relay",
			},
			wrongConnection: {
				profileId: "social",
				endpointId: "endpoint-social",
				networkNamespace: "telclaude-hermes-relay",
			},
		},
	};
}

async function postAdmin(
	socketPath: string,
	body: string,
	headers: Record<string, string> = {},
): Promise<{ statusCode: number; body: unknown }> {
	return new Promise((resolve, reject) => {
		const request = http.request(
			{
				socketPath,
				path: TELCLAUDE_LIVE_MCP_ADMIN_PROBE_TOKENS_PATH,
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"Content-Length": Buffer.byteLength(body),
					...headers,
				},
			},
			(response) => {
				const chunks: Buffer[] = [];
				response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
				response.on("end", () => {
					const raw = Buffer.concat(chunks).toString("utf8");
					resolve({
						statusCode: response.statusCode ?? 0,
						body: raw ? (JSON.parse(raw) as unknown) : null,
					});
				});
			},
		);
		request.on("error", reject);
		request.end(body);
	});
}

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[name];
	} else {
		process.env[name] = value;
	}
}

async function postRpc(
	url: string | undefined,
	authorizationHeader: string,
	body: Record<string, unknown>,
): Promise<{ httpStatus: number; body: unknown }> {
	if (!url) throw new Error("runtime endpoint URL missing");
	const response = await fetch(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: authorizationHeader,
		},
		body: JSON.stringify(body),
	});
	return {
		httpStatus: response.status,
		body: (await response.json()) as unknown,
	};
}

function connection(
	overrides: Partial<TelclaudeMcpAuthorityConnection> = {},
): TelclaudeMcpAuthorityConnection {
	return {
		sessionKey: "probe:private",
		profileId: "default",
		endpointId: "endpoint-private",
		networkNamespace: "telclaude-hermes-relay",
		...overrides,
	};
}

function authority(overrides: Partial<TelclaudeMcpAuthority> = {}): TelclaudeMcpAuthority {
	return {
		actorId: "operator:probe",
		profileId: "default",
		domain: "private",
		memorySource: "telegram:default",
		writableNamespace: "private:default",
		providerScopes: ["bank"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "telclaude-hermes-relay",
		...overrides,
	};
}
