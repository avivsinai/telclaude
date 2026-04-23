import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

vi.mock("../../src/secrets/index.js", () => ({
	getSecret: vi.fn(),
	SECRET_KEYS: { MOLTBOOK_API_KEY: "moltbook-api-key" },
}));

import {
	assertProviderReplayFixture,
	assertSocialReplayFixture,
	type ProviderProbeResult,
	type SocialProbeResult,
} from "../../src/testing/integration-harness.js";
import {
	buildFixtureEnvelope,
	readFixtureFile,
	untrustedPublicText,
	writeFixtureFile,
} from "../../src/testing/live-replay.js";

const fixtureDir = path.join(process.cwd(), "tests", "fixtures", "integration");

describe("live/replay integration harness fixtures", () => {
	let tempDir: string | null = null;

	afterEach(() => {
		if (tempDir) {
			fs.rmSync(tempDir, { recursive: true, force: true });
			tempDir = null;
		}
	});

	it("redacts structured secrets, identifiers, and private text before writing", async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-fixture-redaction-"));
		const fixturePath = path.join(tempDir, "redacted.json");
		const secret = ["Bear", "er", " ", "sk", "-", "a".repeat(32)].join("");

		const written = await writeFixtureFile(
			fixturePath,
			buildFixtureEnvelope(
				"redacted",
				{
					headers: { authorization: secret },
					actorUserId: "telegram-user-123",
					chatId: 99999,
					message: "private Telegram message",
					publicPost: untrustedPublicText("Public social post text"),
				},
				{ mode: "capture", capturedAt: "2026-04-23T00:00:00.000Z" },
			),
		);

		expect(written.data.headers.authorization).toBe("[REDACTED_SECRET]");
		expect(written.data.actorUserId).toMatch(/^\[REDACTED_ID:/);
		expect(written.data.chatId).toMatch(/^\[REDACTED_ID:/);
		expect(written.data.message).toBe("[REDACTED_TEXT]");
		expect(written.data.publicPost).toEqual({
			trust: "untrusted_public",
			value: "Public social post text",
		});
		expect(fs.readFileSync(fixturePath, "utf8")).not.toContain("sk-");
	});

	it("fails closed when a secret-looking value survives structured redaction", async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-fixture-secret-"));
		const fixturePath = path.join(tempDir, "unsafe.json");

		await expect(
			writeFixtureFile(
				fixturePath,
				buildFixtureEnvelope(
					"unsafe",
					{
						description: `unexpected sk-${"b".repeat(32)}`,
					},
					{ mode: "capture" },
				),
			),
		).rejects.toThrow(/unredacted secret-like value/);
	});

	it("validates provider and social replay fixtures without network", async () => {
		const provider = await readFixtureFile<ProviderProbeResult>(
			path.join(fixtureDir, "provider-basic.json"),
		);
		const social = await readFixtureFile<SocialProbeResult>(
			path.join(fixtureDir, "social-moltbook-basic.json"),
		);

		expect(() => assertProviderReplayFixture(provider.data)).not.toThrow();
		expect(() => assertSocialReplayFixture(social.data)).not.toThrow();
	});
});
