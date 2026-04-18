/**
 * DashboardSessionStore unit tests.
 *
 * These guard the spec invariants:
 *   - TTL is 15 minutes from creation (no sliding).
 *   - Sessions expire at the expected instant (lookup returns null).
 *   - Revocation immediately invalidates a session.
 */

import { describe, expect, it } from "vitest";
import {
	DASHBOARD_SESSION_TTL_MS,
	DashboardSessionStore,
} from "../../src/dashboard/sessions.js";

describe("DashboardSessionStore", () => {
	it("TTL constant is exactly 15 minutes", () => {
		expect(DASHBOARD_SESSION_TTL_MS).toBe(15 * 60 * 1000);
	});

	it("create + lookup round-trips the localUserId", () => {
		const store = new DashboardSessionStore();
		const row = store.create("op", 1000);
		const found = store.lookup(row.id, 1000);
		expect(found).not.toBeNull();
		expect(found?.localUserId).toBe("op");
	});

	it("lookup returns null after TTL expires", () => {
		const store = new DashboardSessionStore();
		const row = store.create("op", 0);
		expect(store.lookup(row.id, DASHBOARD_SESSION_TTL_MS - 1)).not.toBeNull();
		expect(store.lookup(row.id, DASHBOARD_SESSION_TTL_MS)).toBeNull();
	});

	it("does NOT extend TTL on each lookup (no sliding window)", () => {
		const store = new DashboardSessionStore();
		const row = store.create("op", 0);
		// Fast-forward close to but within the TTL
		store.lookup(row.id, DASHBOARD_SESSION_TTL_MS - 10);
		// Any subsequent lookup past the original expiry is null
		expect(store.lookup(row.id, DASHBOARD_SESSION_TTL_MS + 1)).toBeNull();
	});

	it("revoke invalidates immediately", () => {
		const store = new DashboardSessionStore();
		const row = store.create("op", 0);
		store.revoke(row.id);
		expect(store.lookup(row.id, 0)).toBeNull();
	});

	it("sweep drops expired rows during lookup", () => {
		const store = new DashboardSessionStore();
		const a = store.create("a", 0);
		const b = store.create("b", 0);
		// Both present initially
		expect(store.size()).toBe(2);
		// Triggering a lookup after expiry should purge both (the sweep is
		// synchronous-on-lookup).
		store.lookup(a.id, DASHBOARD_SESSION_TTL_MS + 1);
		expect(store.size()).toBe(0);
		expect(store.lookup(b.id, DASHBOARD_SESSION_TTL_MS + 1)).toBeNull();
	});

	it("lookup of empty id is null", () => {
		const store = new DashboardSessionStore();
		expect(store.lookup(undefined)).toBeNull();
		expect(store.lookup("")).toBeNull();
	});
});
