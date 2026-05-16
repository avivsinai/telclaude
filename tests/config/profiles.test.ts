import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("operator profile resolution", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-profiles-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(async () => {
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("resolves unbound chats to the implicit default profile", async () => {
		const { resolveChatProfile } = await import("../../src/config/profiles.js");
		const resolved = resolveChatProfile(123, { profiles: [] } as never);

		expect(resolved.profile).toMatchObject({
			id: "default",
			label: "Default",
			implicit: true,
		});
		expect(resolved.warnings).toEqual([]);
	});

	it("resolves chat bindings to configured profiles", async () => {
		const { setChatActiveProfileId } = await import("../../src/config/sessions.js");
		const { resolveChatProfile } = await import("../../src/config/profiles.js");
		setChatActiveProfileId(123, "engineer", 1_234);

		const resolved = resolveChatProfile(123, {
			profiles: [{ id: "engineer", label: "Engineer", allowedSkills: ["integration-test"] }],
		} as never);

		expect(resolved.profile).toMatchObject({
			id: "engineer",
			label: "Engineer",
			implicit: false,
			allowedSkills: ["integration-test"],
		});
	});

	it("falls back to default when a stored binding is stale", async () => {
		const { setChatActiveProfileId } = await import("../../src/config/sessions.js");
		const { resolveChatProfile } = await import("../../src/config/profiles.js");
		setChatActiveProfileId(123, "missing", 1_234);

		const resolved = resolveChatProfile(123, { profiles: [] } as never);

		expect(resolved.profile.id).toBe("default");
		expect(resolved.missingProfileId).toBe("missing");
		expect(resolved.warnings[0]).toContain("missing");
	});
});
