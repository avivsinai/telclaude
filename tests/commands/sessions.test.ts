import { describe, expect, it, vi } from "vitest";

const getAllSessionsImpl = vi.hoisted(() => vi.fn());

vi.mock("../../src/config/sessions.js", () => ({
	getAllSessions: (...args: unknown[]) => getAllSessionsImpl(...args),
}));

import { collectSessionRows } from "../../src/commands/sessions.js";

describe("collectSessionRows", () => {
	it("sorts by most recently active and classifies session kinds", () => {
		const now = Date.now();
		getAllSessionsImpl.mockReturnValueOnce({
			global: { sessionId: "a", updatedAt: now - 30_000, systemSent: false },
			"tg:123": { sessionId: "b", updatedAt: now - 10_000, systemSent: true },
			"tg:-200": { sessionId: "c", updatedAt: now - 20_000, systemSent: false },
		});

		const rows = collectSessionRows();
		expect(rows).toHaveLength(3);
		expect(rows[0].key).toBe("tg:123");
		expect(rows[0].kind).toBe("direct");
		expect(rows[1].kind).toBe("group");
		expect(rows[2].kind).toBe("global");
	});

	it("applies active and limit filters", () => {
		const now = Date.now();
		getAllSessionsImpl.mockReturnValueOnce({
			"tg:1": { sessionId: "a", updatedAt: now - 30_000, systemSent: false },
			"tg:2": { sessionId: "b", updatedAt: now - 90_000, systemSent: false },
			"tg:3": { sessionId: "c", updatedAt: now - 150_000, systemSent: false },
		});

		const rows = collectSessionRows({ activeMinutes: 2, limit: 1 });
		expect(rows).toHaveLength(1);
		expect(rows[0].key).toBe("tg:1");
	});
});
