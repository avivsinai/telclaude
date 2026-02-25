import { describe, expect, it } from "vitest";
import { getAction, getActionsForService, getAllActions } from "../../src/google-services/actions.js";

describe("action registry", () => {
	it("finds gmail search action", () => {
		const action = getAction("gmail", "search");
		expect(action).toBeDefined();
		expect(action!.type).toBe("read");
		expect(action!.scope).toContain("gmail.readonly");
	});

	it("returns undefined for unknown action", () => {
		expect(getAction("gmail", "nonexistent")).toBeUndefined();
	});

	it("identifies action types correctly", () => {
		expect(getAction("gmail", "create_draft")?.type).toBe("action");
		expect(getAction("gmail", "search")?.type).toBe("read");
		expect(getAction("calendar", "create_event")?.type).toBe("action");
		expect(getAction("calendar", "list_events")?.type).toBe("read");
	});

	it("lists all gmail actions", () => {
		const actions = getActionsForService("gmail");
		expect(actions.length).toBe(6);
		expect(actions.some((a) => a.id === "search")).toBe(true);
		expect(actions.some((a) => a.id === "create_draft")).toBe(true);
	});

	it("lists all calendar actions", () => {
		const actions = getActionsForService("calendar");
		expect(actions.length).toBe(6);
		expect(actions.some((a) => a.id === "freebusy")).toBe(true);
	});

	it("lists all drive actions", () => {
		const actions = getActionsForService("drive");
		expect(actions.length).toBe(5);
	});

	it("lists all contacts actions", () => {
		const actions = getActionsForService("contacts");
		expect(actions.length).toBe(3);
	});

	it("has exactly 20 total actions", () => {
		expect(getAllActions().length).toBe(20);
	});

	it("only gmail.create_draft and calendar.create_event are action type", () => {
		const actionTypes = getAllActions().filter((a) => a.type === "action");
		expect(actionTypes.length).toBe(2);
		expect(actionTypes.map((a) => `${a.service}.${a.id}`).sort()).toEqual([
			"calendar.create_event",
			"gmail.create_draft",
		]);
	});
});
