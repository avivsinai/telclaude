import { beforeEach, describe, expect, it, vi } from "vitest";

const getSecretMock = vi.hoisted(() => vi.fn());
const authFnMock = vi.hoisted(() => vi.fn());
const createAppAuthMock = vi.hoisted(() => vi.fn());

vi.mock("@octokit/auth-app", () => ({
	createAppAuth: createAppAuthMock,
}));

vi.mock("@octokit/rest", () => ({
	Octokit: vi.fn(),
}));

vi.mock("../../src/secrets/index.js", () => ({
	getSecret: getSecretMock,
	SECRET_KEYS: { GITHUB_APP: "github-app" },
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

import {
	clearGitHubAppCache,
	getInstallationToken,
	getInstallationTokenInfo,
} from "../../src/services/github-app.js";

const APP_CONFIG = {
	appId: 123,
	installationId: 456,
	privateKey: "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----",
	botUserId: 789,
	appSlug: "telclaude",
};

describe("github app installation tokens", () => {
	beforeEach(() => {
		clearGitHubAppCache();
		getSecretMock.mockReset().mockResolvedValue(JSON.stringify(APP_CONFIG));
		authFnMock.mockReset().mockResolvedValue({
			token: "installation-token",
			expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
		});
		createAppAuthMock.mockReset().mockReturnValue(authFnMock);
	});

	it("requests a repository-scoped contents token for git proxy operations", async () => {
		const info = await getInstallationTokenInfo({
			repository: "avivsinai/telclaude",
			contentsPermission: "write",
		});

		expect(info?.token).toBe("installation-token");
		expect(authFnMock).toHaveBeenCalledWith({
			type: "installation",
			repositoryNames: ["telclaude"],
			permissions: { contents: "write" },
		});
	});

	it("caches tokens separately by repository and requested contents permission", async () => {
		authFnMock
			.mockResolvedValueOnce({
				token: "read-token",
				expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
			})
			.mockResolvedValueOnce({
				token: "write-token",
				expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
			});

		await expect(
			getInstallationToken({ repository: "avivsinai/telclaude", contentsPermission: "read" }),
		).resolves.toBe("read-token");
		await expect(
			getInstallationToken({ repository: "avivsinai/telclaude", contentsPermission: "read" }),
		).resolves.toBe("read-token");
		await expect(
			getInstallationToken({ repository: "avivsinai/telclaude", contentsPermission: "write" }),
		).resolves.toBe("write-token");

		expect(authFnMock).toHaveBeenCalledTimes(2);
		expect(authFnMock).toHaveBeenNthCalledWith(1, {
			type: "installation",
			repositoryNames: ["telclaude"],
			permissions: { contents: "read" },
		});
		expect(authFnMock).toHaveBeenNthCalledWith(2, {
			type: "installation",
			repositoryNames: ["telclaude"],
			permissions: { contents: "write" },
		});
	});

	it("rejects malformed repository scopes before asking GitHub for a token", async () => {
		await expect(
			getInstallationToken({ repository: "https://github.com/avivsinai/telclaude" }),
		).resolves.toBeNull();

		expect(authFnMock).not.toHaveBeenCalled();
	});

	it("rejects installation token responses without a valid expiry", async () => {
		authFnMock.mockResolvedValueOnce({
			token: "installation-token",
		});

		await expect(
			getInstallationToken({ repository: "avivsinai/telclaude", contentsPermission: "read" }),
		).resolves.toBeNull();
		await expect(
			getInstallationToken({ repository: "avivsinai/telclaude", contentsPermission: "read" }),
		).resolves.toBe("installation-token");

		expect(authFnMock).toHaveBeenCalledTimes(2);
	});
});
