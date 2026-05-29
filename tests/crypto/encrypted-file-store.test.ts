/**
 * Regression tests for EncryptedFileStore corruption handling.
 *
 * Security fix under test: on a corrupt/unreadable backing file, readFile()
 * must QUARANTINE the existing file to `<path>.corrupted.<ts>` BEFORE returning
 * a fresh empty store, and must THROW if the quarantine rename fails. The old
 * behavior silently returned an empty store, letting the next write overwrite
 * every existing secret (which also silently disabled TOTP 2FA).
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { EncryptedFileStore } from "../../src/crypto/encrypted-file-store.js";

const KEY = "test-encryption-key-at-least-32-chars-long"; // gitleaks:allow -- fake test passphrase, not a real secret
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

describe("EncryptedFileStore", () => {
	let tempDir: string;
	let filePath: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-encfs-"));
		filePath = path.join(tempDir, "secrets.json");
	});

	afterEach(() => {
		// Restore perms first so a permission-test failure can still be cleaned up.
		try {
			fs.chmodSync(tempDir, 0o700);
		} catch {
			// best effort
		}
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	/** Quarantine files are named `<path>.corrupted.<ts>`. */
	function quarantineFiles(): string[] {
		const base = path.basename(filePath);
		return fs.readdirSync(tempDir).filter((name) => name.startsWith(`${base}.corrupted.`));
	}

	it("round-trips a stored secret through a fresh instance over the same file", () => {
		const writer = new EncryptedFileStore(filePath, KEY);
		writer.store("totp:alice", "JBSWY3DPEHPK3PXP");

		// A brand new instance reading the same file (simulates a process restart)
		// must decrypt and return the value it never held in memory.
		const reader = new EncryptedFileStore(filePath, KEY);
		expect(reader.get("totp:alice")).toBe("JBSWY3DPEHPK3PXP");
		expect(reader.has("totp:alice")).toBe(true);
		expect(reader.get("totp:missing")).toBeNull();
	});

	it("quarantines a corrupt file before any fresh write and preserves the corrupt bytes", () => {
		// Seed a real, valid store so there is something worth protecting.
		new EncryptedFileStore(filePath, KEY).store("totp:alice", "JBSWY3DPEHPK3PXP");

		// Corrupt the backing file (e.g. partial write / disk damage).
		const garbage = "this is not valid json {{{";
		fs.writeFileSync(filePath, garbage);

		// Any access triggers readFile(); reading is a non-mutating access, so the
		// OLD silent-reset behavior would simply return an empty store here with NO
		// quarantine file ever appearing — that is exactly the bug we guard against.
		const store = new EncryptedFileStore(filePath, KEY);
		expect(store.get("totp:alice")).toBeNull(); // value is gone (file was garbage)...

		// ...but the quarantine MUST have happened (this is the load-bearing assertion
		// that fails against the old silent-reset behavior).
		const quarantined = quarantineFiles();
		expect(quarantined).toHaveLength(1);

		// The quarantine must be a rename of the existing file, not a fresh empty
		// write: the corrupt bytes must survive verbatim for manual recovery.
		const recovered = fs.readFileSync(path.join(tempDir, quarantined[0]), "utf8");
		expect(recovered).toBe(garbage);

		// And the live file must not still hold the corrupt content (it was moved away).
		if (fs.existsSync(filePath)) {
			expect(fs.readFileSync(filePath, "utf8")).not.toBe(garbage);
		}

		// After quarantine, storing a NEW key must succeed and persist to a fresh
		// instance — the store recovered cleanly rather than wedging.
		store.store("totp:bob", "GEZDGNBVGY3TQOJQ");
		const after = new EncryptedFileStore(filePath, KEY);
		expect(after.get("totp:bob")).toBe("GEZDGNBVGY3TQOJQ");
		// Storing one new key must not produce a second quarantine.
		expect(quarantineFiles()).toHaveLength(1);
	});

	it("treats structurally-valid-but-wrong-shape JSON as corrupt and quarantines it", () => {
		for (const shape of ["{}", JSON.stringify({ salt: "" }), JSON.stringify({ salt: "x" })]) {
			// Fresh file path per shape so each case is independent.
			const localPath = path.join(tempDir, `shape-${Buffer.from(shape).toString("hex")}.json`);
			fs.writeFileSync(localPath, shape);

			const store = new EncryptedFileStore(localPath, KEY);
			// Touching the store must not trust the malformed shape...
			expect(store.has("anything")).toBe(false);

			// ...it must quarantine it instead.
			const base = path.basename(localPath);
			const quarantined = fs
				.readdirSync(tempDir)
				.filter((name) => name.startsWith(`${base}.corrupted.`));
			expect(quarantined, `shape ${shape} should be quarantined`).toHaveLength(1);
		}
	});

	it.skipIf(isRoot)("throws (fails closed) when the quarantine rename cannot be performed", () => {
		fs.writeFileSync(filePath, "garbage that cannot be parsed");

		// Make the containing directory read+execute only: renameSync within it
		// fails with EACCES, so the fix must throw rather than silently reset.
		fs.chmodSync(tempDir, 0o500);

		const store = new EncryptedFileStore(filePath, KEY);
		expect(() => store.get("totp:alice")).toThrow(/corrupted/i);
	});
});
