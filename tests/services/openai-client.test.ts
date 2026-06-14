import { beforeEach, describe, expect, it, vi } from "vitest";

const getSecretMock = vi.hoisted(() => vi.fn());
const isVaultAvailableMock = vi.hoisted(() => vi.fn());
const vaultGetMock = vi.hoisted(() => vi.fn());
const loadConfigMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/secrets/index.js", () => ({
	getSecret: getSecretMock,
	SECRET_KEYS: { OPENAI_API_KEY: "openai-api-key" },
}));
vi.mock("../../src/vault-daemon/client.js", () => ({
	getVaultClient: () => ({ get: vaultGetMock }),
	isVaultAvailable: isVaultAvailableMock,
}));
vi.mock("../../src/config/config.js", () => ({ loadConfig: loadConfigMock }));
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }),
}));

import { clearOpenAICache, getOpenAIKey } from "../../src/services/openai-client.js";

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
		isVaultAvailableMock.mockReset().mockResolvedValue(false);
		vaultGetMock.mockReset();
		loadConfigMock.mockReset().mockReturnValue({});
		delete process.env.OPENAI_API_KEY;
		delete process.env.TELCLAUDE_CREDENTIAL_PROXY_URL;
	});

	it("reuses the vault http:api.openai.com bearer when keychain/env/config miss", async () => {
		isVaultAvailableMock.mockResolvedValue(true);
		vaultGetMock.mockResolvedValue(bearerEntry("sk-from-vault-http"));
		expect(await getOpenAIKey()).toBe("sk-from-vault-http");
		expect(vaultGetMock).toHaveBeenCalledWith("http", "api.openai.com");
	});

	it("prefers an explicitly provisioned keychain key over the vault http credential", async () => {
		getSecretMock.mockResolvedValue("sk-from-keychain");
		isVaultAvailableMock.mockResolvedValue(true);
		vaultGetMock.mockResolvedValue(bearerEntry("sk-vault"));
		expect(await getOpenAIKey()).toBe("sk-from-keychain");
		expect(vaultGetMock).not.toHaveBeenCalled();
	});

	it("never touches the vault when it is unreachable (contained agent) and uses the credential proxy", async () => {
		isVaultAvailableMock.mockResolvedValue(false);
		process.env.TELCLAUDE_CREDENTIAL_PROXY_URL = "http://relay:8792";
		expect(await getOpenAIKey()).toBe("credential-proxy");
		expect(vaultGetMock).not.toHaveBeenCalled();
	});

	it("ignores a non-bearer / missing vault credential and returns null when nothing is configured", async () => {
		isVaultAvailableMock.mockResolvedValue(true);
		vaultGetMock.mockResolvedValue({ type: "get", ok: false, error: "not_found" });
		expect(await getOpenAIKey()).toBeNull();
	});
});
