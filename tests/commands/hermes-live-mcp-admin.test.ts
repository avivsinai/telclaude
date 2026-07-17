import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerHermesCommand } from "../../src/commands/hermes.js";
import { startTelclaudeLiveMcpAdminServer } from "../../src/hermes/mcp/live-admin.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_OPERATOR_PRIVATE = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
const ORIGINAL_OPERATOR_PUBLIC = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;

describe("hermes live-mcp admin CLI", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-admin-cli-"));
		const operatorKeys = generateKeyPair();
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = operatorKeys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = operatorKeys.publicKey;
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		restoreEnv("OPERATOR_RPC_AGENT_PRIVATE_KEY", ORIGINAL_OPERATOR_PRIVATE);
		restoreEnv("OPERATOR_RPC_AGENT_PUBLIC_KEY", ORIGINAL_OPERATOR_PUBLIC);
	});

	it("prints env-ready served-MCP token headers from the admin socket", async () => {
		const socketPath = path.join(tempDir, "admin.sock");
		const handle = await startTelclaudeLiveMcpAdminServer({
			socketPath,
			issueProbeTokenBundle: () => tokenBundle(),
		});
		try {
			const result = await runHermesCommand([
				"hermes",
				"live-mcp",
				"probe-tokens",
				"--socket",
				socketPath,
				"--json",
				"--session-key",
				"telegram:ops",
				"--profile-id",
				"ops",
				"--provider-scopes",
				"bank,google",
				"--outbound-channels",
				"whatsapp",
			]);

			expect(result.exitCode).toBeUndefined();
			const payload = JSON.parse(result.stdout) as {
				env: Record<string, string>;
				metadata: { tokenMaterial: string };
			};
			expect(payload.env.TELCLAUDE_HERMES_SERVED_MCP_AUTH).toBe(
				"Authorization: Bearer tc_mcp_conn_ALLOWEDSECRET",
			);
			expect(payload.env.TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH).toContain(
				"tc_mcp_conn_WRONGSECRET",
			);
			expect(payload.env.TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH).toContain(
				"tc_mcp_conn_FORGEDSECRET",
			);
			expect(payload.metadata.tokenMaterial).toBe("omitted");
		} finally {
			await handle.stop();
		}
	});

	it("passes explicit household subject and turn authority through the admin socket", async () => {
		const socketPath = path.join(tempDir, "household-admin.sock");
		let captured: unknown;
		const handle = await startTelclaudeLiveMcpAdminServer({
			socketPath,
			issueProbeTokenBundle: (input) => {
				captured = input;
				return tokenBundle();
			},
		});
		try {
			const result = await runHermesCommand([
				"hermes",
				"live-mcp",
				"probe-tokens",
				"--socket",
				socketPath,
				"--json",
				"--domain",
				"household",
				"--profile-id",
				"parent-a",
				"--subject-user-id",
				"household:parent-a",
				"--turn-conversation-ref",
				`turn_${"a".repeat(32)}`,
			]);

			expect(result.exitCode).toBeUndefined();
			expect(captured).toMatchObject({
				privateAuthority: {
					actorId: "household:probe:parent-a",
					subjectUserId: "household:parent-a",
					profileId: "parent-a",
					domain: "household",
					memorySource: "household:parent-a",
					writableNamespace: "household:parent-a",
					providerScopes: ["clalit"],
					outboundChannels: ["whatsapp"],
					turnConversationRef: `turn_${"a".repeat(32)}`,
				},
			});
		} finally {
			await handle.stop();
		}
	});

	it("fails clearly when the runtime admin socket is absent", async () => {
		const result = await runHermesCommand([
			"hermes",
			"live-mcp",
			"probe-tokens",
			"--socket",
			path.join(tempDir, "missing.sock"),
			"--json",
		]);

		expect(result.exitCode).toBe(1);
		expect(result.stderr).toContain("Hermes live MCP admin socket is not active");
	});
});

async function runHermesCommand(
	args: string[],
): Promise<{ exitCode: unknown; stdout: string; stderr: string }> {
	const stdout: string[] = [];
	const stderr: string[] = [];
	const logSpy = vi.spyOn(console, "log").mockImplementation((...values: unknown[]) => {
		stdout.push(values.map(String).join(" "));
	});
	const errorSpy = vi.spyOn(console, "error").mockImplementation((...values: unknown[]) => {
		stderr.push(values.map(String).join(" "));
	});
	const program = new Command();
	registerHermesCommand(program);
	process.exitCode = undefined;
	try {
		await program.parseAsync(["node", "telclaude", ...args]);
		return {
			exitCode: process.exitCode,
			stdout: stdout.join("\n"),
			stderr: stderr.join("\n"),
		};
	} finally {
		process.exitCode = undefined;
		logSpy.mockRestore();
		errorSpy.mockRestore();
	}
}

function tokenBundle(): TelclaudeLiveMcpProbeTokenBundle {
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
		offDomainPeer: {
			token: "tc_mcp_conn_OFFDOMAINSECRET",
			authorizationHeader: "Bearer tc_mcp_conn_OFFDOMAINSECRET",
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
				profileId: "ops",
				endpointId: "endpoint-private",
				networkNamespace: "netns-private",
			},
			wrongConnection: {
				profileId: "social",
				endpointId: "endpoint-social",
				networkNamespace: "netns-social",
			},
		},
	};
}

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[name];
	} else {
		process.env[name] = value;
	}
}
