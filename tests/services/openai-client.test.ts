import { beforeEach, describe, expect, it, vi } from "vitest";

const getSecretMock = vi.hoisted(() => vi.fn());
const vaultMocks = vi.hoisted(() => {
	const ping = vi.fn();
	const get = vi.fn();
	const singletonGet = vi.fn();
	const isAvailable = vi.fn();
	const Client = vi.fn().mockImplementation(() => ({ ping, get }));
	return { Client, get, isAvailable, ping, singletonGet };
});
const loadConfigMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/secrets/index.js", () => ({
	getSecret: getSecretMock,
	SECRET_KEYS: { OPENAI_API_KEY: "openai-api-key" },
}));
vi.mock("../../src/vault-daemon/client.js", () => ({
	VaultClient: vaultMocks.Client,
	getVaultClient: () => ({ get: vaultMocks.singletonGet }),
	isVaultAvailable: vaultMocks.isAvailable,
}));
vi.mock("../../src/config/config.js", () => ({ loadConfig: loadConfigMock }));
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }),
}));

import {
	clearOpenAICache,
	getCachedOpenAIKey,
	getOpenAIKey,
} from "../../src/services/openai-client.js";

function bearerEntry(token: string) {
	return {
		type: "get",
		ok: true,
		entry: {
			protocol: "http",
			target: "api.openai.com",
			credential: { type: "bearer", token },
			createdAt: "2026-01-01T00:00:00.000Z",
		},
	};
}

describe("openai-client getOpenAIKey — shared vault http credential", () => {
	beforeEach(() => {
		clearOpenAICache();
		getSecretMock.mockReset().mockResolvedValue(null);
		vaultMocks.Client.mockClear();
		vaultMocks.get.mockReset();
		vaultMocks.isAvailable.mockReset().mockResolvedValue(false);
		vaultMocks.ping.mockReset().mockResolvedValue(false);
		vaultMocks.singletonGet.mockReset();
		loadConfigMock.mockReset().mockReturnValue({});
		delete process.env.OPENAI_API_KEY;
		delete process.env.TELCLAUDE_CREDENTIAL_PROXY_URL;
	});

	it("reuses the vault http:api.openai.com bearer when keychain/env/config miss", async () => {
		vaultMocks.ping.mockResolvedValue(true);
		vaultMocks.get.mockResolvedValue(bearerEntry("sk-from-vault-http"));
		expect(await getOpenAIKey()).toBe("sk-from-vault-http");
		expect(vaultMocks.Client).toHaveBeenCalledWith({ timeout: 2000 });
		expect(vaultMocks.get).toHaveBeenCalledWith("http", "api.openai.com");
	});

	it("prefers an explicitly provisioned keychain key over the vault http credential", async () => {
		getSecretMock.mockResolvedValue("sk-from-keychain");
		vaultMocks.ping.mockResolvedValue(true);
		vaultMocks.get.mockResolvedValue(bearerEntry("sk-vault"));
		expect(await getOpenAIKey()).toBe("sk-from-keychain");
		expect(vaultMocks.get).not.toHaveBeenCalled();
	});

	it("never touches the vault when it is unreachable (contained agent) and uses the credential proxy", async () => {
		vaultMocks.ping.mockResolvedValue(false);
		process.env.TELCLAUDE_CREDENTIAL_PROXY_URL = "http://relay:8792";
		expect(await getOpenAIKey()).toBe("credential-proxy");
		expect(vaultMocks.get).not.toHaveBeenCalled();
	});

	it("ignores a non-bearer / missing vault credential and returns null when nothing is configured", async () => {
		vaultMocks.ping.mockResolvedValue(true);
		vaultMocks.get.mockResolvedValue({ type: "get", ok: false, error: "not_found" });
		expect(await getOpenAIKey()).toBeNull();
	});

	it("surfaces the vault bearer through getCachedOpenAIKey() for relay-local consumers (e.g. summarize)", async () => {
		vaultMocks.ping.mockResolvedValue(true);
		vaultMocks.get.mockResolvedValue(bearerEntry("sk-from-vault-http"));
		await getOpenAIKey();
		// Relay-side: the resolved vault key is a real string, usable in-process by summarize-core.
		expect(getCachedOpenAIKey()).toBe("sk-from-vault-http");
	});

	it("never surfaces the credential-proxy placeholder through getCachedOpenAIKey() (contained agent)", async () => {
		vaultMocks.ping.mockResolvedValue(false);
		process.env.TELCLAUDE_CREDENTIAL_PROXY_URL = "http://relay:8792";
		await getOpenAIKey();
		// Contained agent: proxy mode must keep getCachedOpenAIKey() null so no key/placeholder leaks to env.
		expect(getCachedOpenAIKey()).toBeNull();
	});

	it("does not depend on the process-wide vault singleton for relay-local OpenAI credentials", async () => {
		vaultMocks.isAvailable.mockResolvedValue(true);
		vaultMocks.singletonGet.mockRejectedValue(new Error("stale singleton socket"));
		vaultMocks.ping.mockResolvedValue(true);
		vaultMocks.get.mockResolvedValue(bearerEntry("sk-from-fresh-vault-client"));

		expect(await getOpenAIKey()).toBe("sk-from-fresh-vault-client");
		expect(vaultMocks.singletonGet).not.toHaveBeenCalled();
		expect(vaultMocks.get).toHaveBeenCalledWith("http", "api.openai.com");
	});
});
