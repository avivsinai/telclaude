import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let createEntries: typeof import("../../src/memory/store.js").createEntries;
let createQuarantinedEntry: typeof import("../../src/memory/store.js").createQuarantinedEntry;
let getEntries: typeof import("../../src/memory/store.js").getEntries;
let markEntryPosted: typeof import("../../src/memory/store.js").markEntryPosted;
let promoteEntryTrust: typeof import("../../src/memory/store.js").promoteEntryTrust;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("memory store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-mem-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ createEntries, createQuarantinedEntry, getEntries, markEntryPosted, promoteEntryTrust } =
			await import("../../src/memory/store.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("assigns trust based on source", () => {
		createEntries(
			[
				{ id: "entry-telegram", category: "profile", content: "from telegram" },
			],
			"telegram",
			1,
		);
		createEntries(
			[{ id: "entry-social", category: "profile", content: "from social" }],
			"social",
			2,
		);

		const entries = getEntries({ order: "asc" });
		const telegramEntry = entries.find((entry) => entry.id === "entry-telegram");
		const socialEntry = entries.find((entry) => entry.id === "entry-social");

		expect(telegramEntry?._provenance.trust).toBe("trusted");
		expect(socialEntry?._provenance.trust).toBe("untrusted");
	});

	it("filters entries by category/source/trust", () => {
		createEntries(
			[
				{ id: "profile-1", category: "profile", content: "trusted" },
				{ id: "threads-1", category: "threads", content: "trusted" },
			],
			"telegram",
			10,
		);
		createEntries(
			[{ id: "profile-2", category: "profile", content: "untrusted" }],
			"social",
			11,
		);

		const profiles = getEntries({ categories: ["profile"], order: "asc" });
		expect(profiles).toHaveLength(2);

		const untrusted = getEntries({ trust: ["untrusted"], order: "asc" });
		expect(untrusted).toHaveLength(1);
		expect(untrusted[0].id).toBe("profile-2");

		const telegramOnly = getEntries({ sources: ["telegram"], order: "asc" });
		expect(telegramOnly).toHaveLength(2);
	});

	it("promotes quarantined telegram posts to trusted", () => {
		const entry = createQuarantinedEntry({
			id: "idea-1",
			category: "posts",
			content: "An idea for Moltbook",
			chatId: "chat-1",
		});

		expect(entry._provenance.trust).toBe("quarantined");
		expect(entry._provenance.source).toBe("telegram");

		const result = promoteEntryTrust("idea-1", "user");
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.entry._provenance.trust).toBe("trusted");
			expect(result.entry._provenance.promotedBy).toBe("user");
			expect(result.entry._provenance.promotedAt).toBeTypeOf("number");
		}

		const updated = getEntries({ order: "asc" })[0];
		expect(updated._provenance.trust).toBe("trusted");
	});

	it("promotes untrusted social posts entries", () => {
		createEntries(
			[{ id: "social-entry", category: "posts", content: "from social" }],
			"social",
			20,
		);

		const result = promoteEntryTrust("social-entry", "admin");
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.entry._provenance.trust).toBe("trusted");
			expect(result.entry._provenance.source).toBe("social");
		}
	});

	it("rejects promotion of non-telegram/social source entries", () => {
		createEntries(
			[{ id: "import-entry", category: "posts", content: "from import" }],
			"import" as "social", // Force disallowed source via type cast
			20,
		);

		const result = promoteEntryTrust("import-entry", "admin");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.reason).toContain("telegram or social");
		}
	});

	it("rejects promotion of non-posts category", () => {
		// Create a telegram entry with non-posts category by using createEntries
		// and manually making it untrusted (legacy path)
		createEntries(
			[{ id: "profile-entry", category: "profile", content: "profile info" }],
			"telegram",
			21,
		);

		const result = promoteEntryTrust("profile-entry", "admin");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.reason).toContain("posts");
		}
	});

	it("rejects promotion of already trusted entries", () => {
		const entry = createQuarantinedEntry({
			id: "idea-2",
			category: "posts",
			content: "Another idea",
			chatId: "chat-1",
		});

		// First promotion succeeds
		const firstResult = promoteEntryTrust("idea-2", "user");
		expect(firstResult.ok).toBe(true);

		// Second promotion fails (entry is now trusted, not quarantined)
		const secondResult = promoteEntryTrust("idea-2", "user");
		expect(secondResult.ok).toBe(false);
		if (!secondResult.ok) {
			expect(secondResult.reason).toContain("Only quarantined");
		}
	});

	it("rejects duplicate entry ids", () => {
		createEntries(
			[{ id: "dup-1", category: "profile", content: "first" }],
			"telegram",
			30,
		);

		expect(() =>
			createEntries(
				[{ id: "dup-1", category: "profile", content: "second" }],
				"telegram",
				31,
			),
		).toThrow(/already exists/i);
	});

	it("creates quarantined entries for posts category only", () => {
		const entry = createQuarantinedEntry({
			id: "q-post",
			category: "posts",
			content: "A post idea",
			chatId: "chat-1",
		});

		expect(entry.category).toBe("posts");
		expect(entry._provenance.trust).toBe("quarantined");
		expect(entry._provenance.source).toBe("telegram");
	});

	it("rejects quarantined entries for non-posts category", () => {
		expect(() =>
			createQuarantinedEntry({
				id: "q-profile",
				category: "profile",
				content: "A profile entry",
				chatId: "chat-1",
			}),
		).toThrow(/posts category/i);
	});

	it("rejects quarantined entries without chat id", () => {
		expect(() =>
			createQuarantinedEntry({
				id: "q-no-chat",
				category: "posts",
				content: "A post without chat id",
			}),
		).toThrow(/chatId/i);
	});

	it("marks entries as posted", () => {
		const entry = createQuarantinedEntry({
			id: "post-me",
			category: "posts",
			content: "To be posted",
			chatId: "chat-1",
		});
		promoteEntryTrust("post-me", "user");

		expect(markEntryPosted("post-me")).toBe(true);

		const updated = getEntries({ order: "asc" })[0];
		expect(updated._provenance.postedAt).toBeTypeOf("number");

		// Second mark fails (already posted)
		expect(markEntryPosted("post-me")).toBe(false);
	});

	it("filters entries by promoted status", () => {
		createQuarantinedEntry({
			id: "promoted-1",
			category: "posts",
			content: "Will promote",
			chatId: "chat-1",
		});
		createQuarantinedEntry({
			id: "unpromoted-1",
			category: "posts",
			content: "Will stay",
			chatId: "chat-1",
		});
		promoteEntryTrust("promoted-1", "user");

		const promoted = getEntries({ promoted: true, order: "asc" });
		expect(promoted).toHaveLength(1);
		expect(promoted[0].id).toBe("promoted-1");

		const unpromoted = getEntries({ promoted: false, order: "asc" });
		expect(unpromoted).toHaveLength(1);
		expect(unpromoted[0].id).toBe("unpromoted-1");
	});

	it("filters entries by posted status", () => {
		createQuarantinedEntry({
			id: "posted-1",
			category: "posts",
			content: "Will post",
			chatId: "chat-1",
		});
		createQuarantinedEntry({
			id: "unposted-1",
			category: "posts",
			content: "Will not post",
			chatId: "chat-1",
		});
		promoteEntryTrust("posted-1", "user");
		promoteEntryTrust("unposted-1", "user");
		markEntryPosted("posted-1");

		const posted = getEntries({ posted: true, order: "asc" });
		expect(posted).toHaveLength(1);
		expect(posted[0].id).toBe("posted-1");

		const unposted = getEntries({ posted: false, order: "asc" });
		expect(unposted).toHaveLength(1);
		expect(unposted[0].id).toBe("unposted-1");
	});
});
