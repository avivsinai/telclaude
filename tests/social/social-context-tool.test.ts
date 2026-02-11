import { describe, expect, it } from "vitest";

import {
	buildSocialContextPayload,
	formatSocialContextForPrompt,
	SOCIAL_CONTEXT_WARNING,
} from "../../src/social/context.js";

describe("social context formatting", () => {
	const snapshot = {
		entries: [
			{
				id: "entry-1",
				category: "profile",
				content: "Name: telclaude",
				_provenance: {
					source: "telegram",
					trust: "trusted",
					createdAt: 1,
				},
			},
		],
	};

	it("wraps social context with warning metadata", () => {
		const payload = buildSocialContextPayload(snapshot, "moltbook");
		expect(payload._warning).toBe(SOCIAL_CONTEXT_WARNING);
		expect(payload._source).toBe("moltbook_social_memory");
		expect(payload.data.entries).toHaveLength(1);
	});

	it("includes UNTRUSTED warning in prompt section", () => {
		const formatted = formatSocialContextForPrompt(snapshot, "moltbook");
		expect(formatted).toContain("SOCIAL CONTEXT");
		expect(formatted).toContain(SOCIAL_CONTEXT_WARNING);
		expect(formatted).toContain("moltbook_social_memory");
		expect(formatted).toContain("Name: telclaude");
	});
});
