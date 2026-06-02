import fs from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { shutdownTokenClient } from "../../src/agent/token-client.js";
import { registerHermesCommand } from "../../src/commands/hermes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

describe("Hermes rollback rehearsal CLI", () => {
	it("refuses live rollback rehearsal without the operator relay verification key before relay I/O", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-no-key-"));
		const outPath = path.join(tempDir, "rollback.json");
		const originalUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		const originalOperatorPrivate = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
		const originalOperatorPublic = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
		const originalOperatorRelayPublic = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const operatorKeys = generateKeyPair();
		const relay = await startProbeServer((_req, res) => {
			res.setHeader("Content-Type", "application/json");
			res.end(JSON.stringify(legacyRuntimeState()));
		});

		shutdownTokenClient();
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = operatorKeys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = operatorKeys.publicKey;
		process.env.TELCLAUDE_CAPABILITIES_URL = new URL(relay.url).origin;
		delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

		try {
			const result = await runHermesCommand([
				"hermes",
				"rollback-rehearsal",
				"--allow-run",
				"--json",
				"--out",
				outPath,
			]);
			const report = JSON.parse(result.stdout) as {
				passed: boolean;
				written: boolean;
				checks: Array<{ name: string; status: string; detail: string }>;
			};

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({ passed: false, written: false });
			expect(report.checks[0]).toMatchObject({
				name: "rollback.controlSurface",
				status: "fail",
				detail:
					"Missing relay response verification key for operator. Set OPERATOR_RPC_RELAY_PUBLIC_KEY.",
			});
			expect(relay.requests.count).toBe(0);
			expect(fs.existsSync(outPath)).toBe(false);
		} finally {
			await relay.close();
			shutdownTokenClient();
			restoreEnv("TELCLAUDE_CAPABILITIES_URL", originalUrl);
			restoreEnv("OPERATOR_RPC_AGENT_PRIVATE_KEY", originalOperatorPrivate);
			restoreEnv("OPERATOR_RPC_AGENT_PUBLIC_KEY", originalOperatorPublic);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalOperatorRelayPublic);
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});

async function runHermesCommand(args: string[]): Promise<{ exitCode: unknown; stdout: string }> {
	const output: string[] = [];
	const logSpy = vi.spyOn(console, "log").mockImplementation((...values: unknown[]) => {
		output.push(values.map(String).join(" "));
	});
	const program = new Command();
	registerHermesCommand(program);
	process.exitCode = undefined;
	try {
		await program.parseAsync(["node", "telclaude", ...args]);
		return { exitCode: process.exitCode, stdout: output.join("\n") };
	} finally {
		process.exitCode = undefined;
		logSpy.mockRestore();
	}
}

async function startProbeServer(
	handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ url: string; requests: { count: number }; close: () => Promise<void> }> {
	const requests = { count: 0 };
	const sockets = new Set<Socket>();
	const server = http.createServer((req, res) => {
		requests.count += 1;
		handler(req, res);
	});
	server.on("connection", (socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address() as AddressInfo;
	return {
		url: `http://127.0.0.1:${address.port}/probe`,
		requests,
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise<void>((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
			});
		},
	};
}

function legacyRuntimeState() {
	return {
		ok: true,
		effectiveMode: "legacy",
		effectiveValue: "0",
		rolloutAllowed: true,
		rolloutEnvValue: "1",
		controlMode: "legacy",
		controlSource: "runtime-config",
		fallbackPath: "telclaude.private-runtime.legacy",
	};
}

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[name];
	} else {
		process.env[name] = value;
	}
}
