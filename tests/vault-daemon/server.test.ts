import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { startServer } from "../../src/vault-daemon/server.js";

const cleanupDirs = new Set<string>();
const originalSocketModeEnv = process.env.TELCLAUDE_VAULT_SOCKET_MODE;

function createTempPaths() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-vault-server-"));
	cleanupDirs.add(dir);
	return {
		dir,
		socketPath: path.join(dir, "vault.sock"),
		vaultFilePath: path.join(dir, "vault.json"),
	};
}

afterEach(() => {
	if (originalSocketModeEnv === undefined) {
		delete process.env.TELCLAUDE_VAULT_SOCKET_MODE;
	} else {
		process.env.TELCLAUDE_VAULT_SOCKET_MODE = originalSocketModeEnv;
	}

	for (const dir of cleanupDirs) {
		fs.rmSync(dir, { recursive: true, force: true });
	}
	cleanupDirs.clear();
});

describe("vault daemon socket permissions", () => {
	it("defaults to 0600", async () => {
		const { socketPath, vaultFilePath } = createTempPaths();
		const handle = await startServer({
			socketPath,
			storeOptions: {
				filePath: vaultFilePath,
				encryptionKey: "test-vault-encryption-key-default-mode",
			},
		});

		try {
			const mode = fs.statSync(socketPath).mode & 0o777;
			expect(mode).toBe(0o600);
		} finally {
			await handle.stop();
		}
	});

	it("supports an explicit socket mode override", async () => {
		process.env.TELCLAUDE_VAULT_SOCKET_MODE = "0666";

		const { socketPath, vaultFilePath } = createTempPaths();
		const handle = await startServer({
			socketPath,
			storeOptions: {
				filePath: vaultFilePath,
				encryptionKey: "test-vault-encryption-key-override-mode",
			},
		});

		try {
			const mode = fs.statSync(socketPath).mode & 0o777;
			expect(mode).toBe(0o666);
		} finally {
			await handle.stop();
		}
	});
});
