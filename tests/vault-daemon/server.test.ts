import { once } from "node:events";
import fs from "node:fs";
import { createConnection } from "node:net";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	CURATOR_PRODUCER_SIGNING_PREFIX,
	GOOGLE_APPROVAL_SIGNING_PREFIX,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
} from "../../src/security/approval-domains.js";
import { VaultClient } from "../../src/vault-daemon/client.js";
import type { ServerHandle } from "../../src/vault-daemon/server.js";
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

	it("destroys connected clients without stop-time disconnect debug logs", async () => {
		const debug = vi.fn();
		const logger = {
			debug,
			error: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
		};

		vi.resetModules();
		vi.doMock("../../src/logging.js", () => ({
			getChildLogger: () => logger,
		}));

		const { startServer: startServerWithMockedLogger } = await import(
			"../../src/vault-daemon/server.js"
		);
		const { socketPath, vaultFilePath } = createTempPaths();
		const handle = await startServerWithMockedLogger({
			socketPath,
			storeOptions: {
				filePath: vaultFilePath,
				encryptionKey: "test-vault-encryption-key-stop-race",
			},
		});
		const socket = createConnection(socketPath);

		try {
			await once(socket, "connect");
			debug.mockClear();

			const closed = once(socket, "close");
			await handle.stop();
			await closed;

			expect(socket.destroyed).toBe(true);
			expect(debug.mock.calls.map((call) => call[1])).not.toContain("client disconnected");
			expect(debug.mock.calls.map((call) => call[1])).not.toContain("socket error");
		} finally {
			socket.destroy();
			if (handle.isRunning()) await handle.stop();
			vi.doUnmock("../../src/logging.js");
			vi.resetModules();
		}
	});
});

// ─────────────────────────────────────────────────────────────────────
// sign-payload / verify-payload prefix allowlist.
//
// The generic signing endpoint signs `${prefix}\n${payload}` with the shared
// master keypair, so a caller-controlled prefix is a domain-separation oracle.
// The server must only sign/verify the domains that legitimately use this
// endpoint (Google, Curator, and Hermes MCP side-effect approvals) and reject
// every other prefix — including domains owned by dedicated endpoints (`skill-v1`) or
// other token formats (`session-v1`, `pairing-v1`). These tests drive the live
// server over the Unix socket; they fail against a server that signs any
// prefix because the forbidden cases would come back with a signature instead
// of an error.
// ─────────────────────────────────────────────────────────────────────

describe("vault sign-payload prefix allowlist", () => {
	let handle: ServerHandle | undefined;
	let client: VaultClient;

	async function startVault(): Promise<void> {
		const { socketPath, vaultFilePath } = createTempPaths();
		handle = await startServer({
			socketPath,
			storeOptions: {
				filePath: vaultFilePath,
				encryptionKey: "test-vault-encryption-key-prefix-allowlist",
			},
		});
		client = new VaultClient({ socketPath, timeout: 5000 });
	}

	afterEach(async () => {
		if (handle) {
			await handle.stop();
			handle = undefined;
		}
	});

	it("signs a payload under an allowed prefix (approval-v1)", async () => {
		await startVault();

		const response = await client.signPayload("approval-payload", GOOGLE_APPROVAL_SIGNING_PREFIX);

		expect(response.type).toBe("sign-payload");
		expect(typeof response.signature).toBe("string");
		expect(response.signature.length).toBeGreaterThan(0);
	});

	it("signs a payload under the other allowed prefix (curator-producer-v1)", async () => {
		await startVault();

		const response = await client.signPayload("curator-payload", CURATOR_PRODUCER_SIGNING_PREFIX);

		expect(response.type).toBe("sign-payload");
		expect(typeof response.signature).toBe("string");
		expect(response.signature.length).toBeGreaterThan(0);
	});

	it("signs payloads under Hermes MCP provider and outbound approval domains", async () => {
		await startVault();

		const provider = await client.signPayload(
			"provider-approval-payload",
			TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
		);
		const outbound = await client.signPayload(
			"outbound-approval-payload",
			TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
		);

		expect(provider.type).toBe("sign-payload");
		expect(outbound.type).toBe("sign-payload");
		expect(provider.type === "sign-payload" ? provider.signature : "").not.toBe(
			outbound.type === "sign-payload" ? outbound.signature : "",
		);
	});

	it("refuses to sign under a forbidden domain prefix (skill-v1) and returns no signature", async () => {
		await startVault();

		const response = await client.signPayload("skill-digest", "skill-v1");

		expect(response.type).toBe("error");
		expect(response).not.toHaveProperty("signature");
		if (response.type === "error") {
			expect(response.error).toContain("skill-v1");
		}
	});

	it("refuses to sign under an unknown prefix and returns no signature", async () => {
		await startVault();

		const response = await client.signPayload("payload", "totally-bogus-v9");

		expect(response.type).toBe("error");
		expect(response).not.toHaveProperty("signature");
	});

	it("refuses to verify under a forbidden prefix", async () => {
		await startVault();

		// First obtain a genuine approval-v1 signature for some payload.
		const signed = await client.signPayload("payload", GOOGLE_APPROVAL_SIGNING_PREFIX);
		expect(signed.type).toBe("sign-payload");
		const signature = signed.type === "sign-payload" ? signed.signature : "";

		// Presenting that signature for verification under a forbidden prefix
		// must be rejected before any cryptographic check (the oracle is
		// closed on the verify side too).
		const response = await client.verifyPayload("payload", signature, "skill-v1");

		expect(response.type).toBe("error");
		expect(response).not.toHaveProperty("valid");
	});

	it("verifies a signature it produced under an allowed prefix", async () => {
		await startVault();

		const signed = await client.signPayload("round-trip-payload", GOOGLE_APPROVAL_SIGNING_PREFIX);
		expect(signed.type).toBe("sign-payload");
		const signature = signed.type === "sign-payload" ? signed.signature : "";

		const verified = await client.verifyPayload(
			"round-trip-payload",
			signature,
			GOOGLE_APPROVAL_SIGNING_PREFIX,
		);

		expect(verified.type).toBe("verify-payload");
		if (verified.type === "verify-payload") {
			expect(verified.valid).toBe(true);
		}
	});

	it("verifies Hermes MCP side-effect signatures only under the matching approval domain", async () => {
		await startVault();

		const signed = await client.signPayload(
			"provider-round-trip-payload",
			TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
		);
		expect(signed.type).toBe("sign-payload");
		const signature = signed.type === "sign-payload" ? signed.signature : "";

		const providerVerified = await client.verifyPayload(
			"provider-round-trip-payload",
			signature,
			TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
		);
		const outboundVerified = await client.verifyPayload(
			"provider-round-trip-payload",
			signature,
			TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
		);

		expect(providerVerified).toEqual({ type: "verify-payload", valid: true });
		expect(outboundVerified).toEqual({ type: "verify-payload", valid: false });
	});
});
