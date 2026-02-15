import { afterEach, describe, expect, it, vi } from "vitest";

const originalEnv = { ...process.env };

function resetEnv() {
	for (const key of Object.keys(process.env)) {
		if (!(key in originalEnv)) {
			delete process.env[key];
		}
	}
	for (const [key, value] of Object.entries(originalEnv)) {
		process.env[key] = value;
	}
}

async function loadPermissions(authDir: string) {
	resetEnv();
	process.env.TELCLAUDE_AUTH_DIR = authDir;
	vi.resetModules();
	return await import("../../src/security/permissions.js");
}

afterEach(() => {
	resetEnv();
});

describe("auth dir sensitive path blocking", () => {
	it("blocks direct reads under TELCLAUDE_AUTH_DIR", async () => {
		const { isSensitivePath } = await loadPermissions("/home/telclaude-auth");
		expect(isSensitivePath("/home/telclaude-auth/.credentials.json")).toBe(true);
		expect(isSensitivePath("/home/telclaude-auth/anything.txt")).toBe(true);
	});

	it("blocks shell commands that access TELCLAUDE_AUTH_DIR", async () => {
		const { isSensitivePath } = await loadPermissions("/home/telclaude-auth");
		expect(isSensitivePath("cd /home/telclaude-auth && ls")).toBe(true);
	});
});
