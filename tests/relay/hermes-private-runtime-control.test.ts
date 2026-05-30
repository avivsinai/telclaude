import { once } from "node:events";
import fs from "node:fs";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resetConfigPath, setConfigPath } from "../../src/config/path.js";
import { buildInternalAuthHeaders, generateKeyPair } from "../../src/internal-auth.js";
import { startCapabilityServer } from "../../src/relay/capabilities.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_AGENT_PRIVATE_KEY: process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY,
	OPERATOR_RPC_AGENT_PUBLIC_KEY: process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY,
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
	SOCIAL_RPC_AGENT_PRIVATE_KEY: process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY,
	SOCIAL_RPC_AGENT_PUBLIC_KEY: process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY,
	TELEGRAM_RPC_AGENT_PRIVATE_KEY: process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY,
	TELEGRAM_RPC_AGENT_PUBLIC_KEY: process.env.TELEGRAM_RPC_AGENT_PUBLIC_KEY,
	TELCLAUDE_HERMES_PRIVATE_RUNTIME: process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME,
};

afterEach(() => {
	resetConfigPath();
	for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
		if (value === undefined) {
			delete process.env[key];
		} else {
			process.env[key] = value;
		}
	}
});

describe("relay Hermes private-runtime control surface", () => {
	it("lets only operator RPC observe and drive the durable private-runtime mode", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-relay-runtime-control-"));
		const configPath = path.join(tempDir, "telclaude.json");
		const runtimeConfigPath = path.join(tempDir, "telclaude.runtime.json");
		setConfigPath(configPath);
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "1";
		const keys = generateKeyPair();
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = keys.publicKey;
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		const server = startCapabilityServer({ port: 0, host: "127.0.0.1" });
		try {
			await once(server, "listening");
			const address = server.address() as AddressInfo;
			const baseUrl = `http://127.0.0.1:${address.port}`;

			const initial = await post(baseUrl, "/v1/hermes.private-runtime.status", {});
			expect(initial.status).toBe(200);
			expect(await initial.json()).toMatchObject({
				effectiveMode: "hermes",
				effectiveValue: "1",
				controlSource: "runtime-config-default",
			});

			const updated = await post(baseUrl, "/v1/hermes.private-runtime.mode", { mode: "legacy" });
			expect(updated.status).toBe(200);
			expect(await updated.json()).toMatchObject({
				effectiveMode: "legacy",
				effectiveValue: "0",
				controlMode: "legacy",
				controlSource: "runtime-config",
			});
			const runtimeConfig = JSON.parse(fs.readFileSync(runtimeConfigPath, "utf8")) as {
				hermes?: { privateRuntime?: { mode?: string } };
			};
			expect(runtimeConfig.hermes?.privateRuntime?.mode).toBe("legacy");

			const unauthenticated = await fetch(`${baseUrl}/v1/hermes.private-runtime.status`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: "{}",
			});
			expect(unauthenticated.status).toBe(401);

			const socialKeys = generateKeyPair();
			const telegramKeys = generateKeyPair();
			process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY = socialKeys.privateKey;
			process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY = socialKeys.publicKey;
			process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY = telegramKeys.privateKey;
			process.env.TELEGRAM_RPC_AGENT_PUBLIC_KEY = telegramKeys.publicKey;
			for (const scope of ["telegram", "social"]) {
				expect(
					(await postWithScope(baseUrl, "/v1/hermes.private-runtime.status", {}, scope)).status,
				).toBe(403);
				expect(
					(
						await postWithScope(
							baseUrl,
							"/v1/hermes.private-runtime.mode",
							{ mode: "hermes" },
							scope,
						)
					).status,
				).toBe(403);
			}
			expect(
				(await post(baseUrl, "/v1/hermes.private-runtime.mode", { mode: "maybe" })).status,
			).toBe(400);
		} finally {
			await new Promise<void>((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
			});
		}
	});

	it("fails closed on malformed runtime config and lets operator rollback repair it", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-relay-runtime-control-"));
		const configPath = path.join(tempDir, "telclaude.json");
		const runtimeConfigPath = path.join(tempDir, "telclaude.runtime.json");
		setConfigPath(configPath);
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "1";
		fs.writeFileSync(runtimeConfigPath, "{ bad json", { mode: 0o600 });
		const keys = generateKeyPair();
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = keys.publicKey;
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		const server = startCapabilityServer({ port: 0, host: "127.0.0.1" });
		try {
			await once(server, "listening");
			const address = server.address() as AddressInfo;
			const baseUrl = `http://127.0.0.1:${address.port}`;

			const status = await post(baseUrl, "/v1/hermes.private-runtime.status", {});
			expect(status.status).toBe(200);
			expect(await status.json()).toMatchObject({
				effectiveMode: "legacy",
				effectiveValue: "0",
				controlSource: "runtime-config-invalid",
			});

			const updated = await post(baseUrl, "/v1/hermes.private-runtime.mode", { mode: "legacy" });
			expect(updated.status).toBe(200);
			expect(await updated.json()).toMatchObject({
				effectiveMode: "legacy",
				effectiveValue: "0",
				controlMode: "legacy",
				controlSource: "runtime-config",
			});
		} finally {
			await new Promise<void>((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
			});
		}
	});
});

function post(baseUrl: string, requestPath: string, body: unknown) {
	return postWithScope(baseUrl, requestPath, body, "operator");
}

function postWithScope(baseUrl: string, requestPath: string, body: unknown, scope: string) {
	const payload = JSON.stringify(body);
	return fetch(`${baseUrl}${requestPath}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...buildInternalAuthHeaders("POST", requestPath, payload, { scope }),
		},
		body: payload,
	});
}
