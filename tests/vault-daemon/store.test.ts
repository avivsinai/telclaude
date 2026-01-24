/**
 * Tests for vault store encryption and persistence.
 */

import { mkdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { resetVaultStore, VaultStore } from "../../src/vault-daemon/store.js";

const TEST_DIR = join(process.cwd(), ".test-vault");
const TEST_FILE = join(TEST_DIR, "vault.json");
const TEST_KEY = "test-encryption-key-at-least-32-chars";

describe("VaultStore", () => {
	beforeEach(() => {
		// Clean up and create test directory
		try {
			rmSync(TEST_DIR, { recursive: true });
		} catch {
			// Ignore if doesn't exist
		}
		mkdirSync(TEST_DIR, { recursive: true });
		resetVaultStore();
	});

	afterEach(() => {
		resetVaultStore();
		try {
			rmSync(TEST_DIR, { recursive: true });
		} catch {
			// Ignore
		}
	});

	it("should store and retrieve a bearer credential", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store("http", "api.openai.com", {
			type: "bearer",
			token: "sk-secret-token-12345",
		});

		const entry = await store.get("http", "api.openai.com");

		expect(entry).not.toBeNull();
		expect(entry?.protocol).toBe("http");
		expect(entry?.target).toBe("api.openai.com");
		expect(entry?.credential.type).toBe("bearer");
		expect((entry?.credential as { token: string }).token).toBe("sk-secret-token-12345");
	});

	it("should store and retrieve an api-key credential", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store("http", "api.anthropic.com", {
			type: "api-key",
			token: "sk-ant-api-key",
			header: "x-api-key",
		});

		const entry = await store.get("http", "api.anthropic.com");

		expect(entry).not.toBeNull();
		expect(entry?.credential.type).toBe("api-key");
		const cred = entry?.credential as { token: string; header: string };
		expect(cred.token).toBe("sk-ant-api-key");
		expect(cred.header).toBe("x-api-key");
	});

	it("should return null for non-existent credential", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		const entry = await store.get("http", "nonexistent.com");
		expect(entry).toBeNull();
	});

	it("should delete a credential", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store("http", "api.example.com", {
			type: "bearer",
			token: "test-token",
		});

		// Verify it exists
		expect(await store.has("http", "api.example.com")).toBe(true);

		// Delete it
		const deleted = await store.delete("http", "api.example.com");
		expect(deleted).toBe(true);

		// Verify it's gone
		expect(await store.has("http", "api.example.com")).toBe(false);
		expect(await store.get("http", "api.example.com")).toBeNull();
	});

	it("should list credentials without exposing secrets", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store(
			"http",
			"api.openai.com",
			{ type: "bearer", token: "secret-1" },
			{ label: "OpenAI API" },
		);
		await store.store(
			"http",
			"api.github.com",
			{ type: "bearer", token: "secret-2" },
			{ label: "GitHub API" },
		);

		const entries = await store.list();

		expect(entries).toHaveLength(2);

		// List should not expose tokens
		const openai = entries.find((e) => e.target === "api.openai.com");
		expect(openai).toBeDefined();
		expect(openai?.credentialType).toBe("bearer");
		expect(openai?.label).toBe("OpenAI API");
		expect((openai as Record<string, unknown>).token).toBeUndefined();
	});

	it("should filter list by protocol", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store("http", "api.example.com", { type: "bearer", token: "t1" });
		await store.store("postgres", "db.example.com:5432", {
			type: "db",
			username: "admin",
			password: "pass",
		});

		const httpOnly = await store.list("http");
		expect(httpOnly).toHaveLength(1);
		expect(httpOnly[0].protocol).toBe("http");

		const postgresOnly = await store.list("postgres");
		expect(postgresOnly).toHaveLength(1);
		expect(postgresOnly[0].protocol).toBe("postgres");
	});

	it("should persist and survive store recreation", async () => {
		const store1 = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store1.store("http", "api.test.com", {
			type: "bearer",
			token: "persistent-token",
		});

		// Create a new store instance (simulating process restart)
		resetVaultStore();
		const store2 = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		const entry = await store2.get("http", "api.test.com");
		expect(entry).not.toBeNull();
		expect((entry?.credential as { token: string }).token).toBe("persistent-token");
	});

	it("should fail with wrong encryption key", async () => {
		const store1 = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store1.store("http", "api.test.com", {
			type: "bearer",
			token: "secret",
		});

		// Create a new store with different key
		resetVaultStore();
		const store2 = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: "wrong-key-that-is-at-least-32-chars",
		});

		// Should return null (decryption fails)
		const entry = await store2.get("http", "api.test.com");
		expect(entry).toBeNull();
	});

	it("should set file permissions to 0600", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store("http", "api.test.com", {
			type: "bearer",
			token: "test",
		});

		const stats = statSync(TEST_FILE);
		const mode = stats.mode & 0o777;
		expect(mode).toBe(0o600);
	});

	it("should store oauth2 credentials", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store("http", "api.google.com", {
			type: "oauth2",
			clientId: "client-123",
			clientSecret: "secret-456",
			refreshToken: "refresh-789",
			tokenEndpoint: "https://oauth2.googleapis.com/token",
			scope: "email profile",
		});

		const entry = await store.get("http", "api.google.com");
		expect(entry).not.toBeNull();
		expect(entry?.credential.type).toBe("oauth2");

		const cred = entry?.credential as {
			clientId: string;
			clientSecret: string;
			refreshToken: string;
		};
		expect(cred.clientId).toBe("client-123");
		expect(cred.clientSecret).toBe("secret-456");
		expect(cred.refreshToken).toBe("refresh-789");
	});

	it("should store with optional metadata", async () => {
		const store = new VaultStore({
			filePath: TEST_FILE,
			encryptionKey: TEST_KEY,
		});

		await store.store(
			"http",
			"api.limited.com",
			{ type: "bearer", token: "test" },
			{
				label: "Rate Limited API",
				allowedPaths: ["^/v1/safe/.*", "^/v2/also-safe/.*"],
				rateLimitPerMinute: 60,
			},
		);

		const entry = await store.get("http", "api.limited.com");
		expect(entry?.label).toBe("Rate Limited API");
		expect(entry?.allowedPaths).toEqual(["^/v1/safe/.*", "^/v2/also-safe/.*"]);
		expect(entry?.rateLimitPerMinute).toBe(60);
	});
});
