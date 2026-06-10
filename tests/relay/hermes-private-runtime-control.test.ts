import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
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
};

afterEach(() => {
	for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
		if (value === undefined) {
			delete process.env[key];
		} else {
			process.env[key] = value;
		}
	}
});

describe("relay Hermes private-runtime control surface", () => {
	it("lets only operator RPC observe the Hermes-only private-runtime status", async () => {
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
			const state = await status.json();
			expect(state).toMatchObject({
				ok: true,
				effectiveMode: "hermes",
				effectiveValue: "1",
				controlMode: "hermes",
				controlSource: "hermes-only",
			});
			expect(state).not.toHaveProperty("fallbackPath");
			expect(state.relayProof).toMatchObject({
				method: "POST",
				path: "/v1/hermes.private-runtime.status",
				scope: "operator",
			});

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
			}
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
