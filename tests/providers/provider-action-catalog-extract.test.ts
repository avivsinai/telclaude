import { describe, expect, it } from "vitest";
import {
	formatGrantedProviderActionCatalog,
	type ProviderActionCatalog,
} from "../../src/providers/provider-action-catalog.js";
import { buildProviderActionCatalog } from "../../src/providers/provider-skill.js";

// Real /v1/schema shapes observed on william (2026-07-01), trimmed:
// - israel-services: `services` is an ARRAY of {id, actions:[{id, mode:"read"|"write"|"api", ...}]}
// - google-services: `services` is an OBJECT keyed by service id, actions carry type:"read"|"action"
const ISRAEL_SCHEMA = {
	version: "1.0",
	services: [
		{
			id: "clalit",
			name: "Clalit Health Services",
			actions: [
				{ id: "appointments", method: "POST", mode: "read", requiresAuth: true },
				{ id: "lab_results", method: "POST", mode: "read", requiresAuth: true },
				{ id: "prescription_renewal", method: "POST", mode: "write", requiresAuth: true },
			],
		},
		{
			id: "poalim",
			name: "Bank Hapoalim",
			// Banking reads are tagged mode:"api" — must classify as reads, not writes.
			actions: [
				{ id: "balance", mode: "api" },
				{ id: "transactions", mode: "api" },
			],
		},
	],
};

const GOOGLE_SCHEMA = {
	version: "1.0",
	services: {
		gmail: {
			actions: [
				{ id: "search", type: "read" },
				{ id: "create_draft", type: "action" },
			],
		},
	},
};

function build(): ProviderActionCatalog {
	return buildProviderActionCatalog([
		{ provider: { id: "israel-services", baseUrl: "http://israel", services: [] }, schema: ISRAEL_SCHEMA },
		{ provider: { id: "google", baseUrl: "http://google", services: [] }, schema: GOOGLE_SCHEMA },
	]);
}

describe("buildProviderActionCatalog (real schema extraction)", () => {
	it("extracts clalit actions and classifies mode:write as a write", () => {
		const catalog = build();
		const clalit = catalog["israel-services"]?.clalit;
		expect(clalit).toBeDefined();
		expect(clalit).toContainEqual({ id: "appointments", write: false });
		expect(clalit).toContainEqual({ id: "lab_results", write: false });
		expect(clalit).toContainEqual({ id: "prescription_renewal", write: true });
	});

	it("classifies bank mode:api actions as reads (not writes)", () => {
		const catalog = build();
		const poalim = catalog["israel-services"]?.poalim;
		expect(poalim).toContainEqual({ id: "balance", write: false });
		expect(poalim).toContainEqual({ id: "transactions", write: false });
		expect(poalim?.some((a) => a.write)).toBe(false);
	});

	it("extracts google object-shaped services and classifies type:action as a write", () => {
		const catalog = build();
		const gmail = catalog.google?.gmail;
		expect(gmail).toContainEqual({ id: "search", write: false });
		expect(gmail).toContainEqual({ id: "create_draft", write: true });
	});

	it("feeds a prompt block with the correct read/write split end to end", () => {
		const block = formatGrantedProviderActionCatalog(["clalit", "bank", "google"], build());
		expect(block).toMatch(/Reads[\s\S]*- service "clalit": appointments, lab_results/);
		expect(block).toMatch(/Reads[\s\S]*- service "bank": balance, transactions/);
		expect(block).toMatch(/Writes[\s\S]*- service "clalit": prescription_renewal/);
		expect(block).toMatch(/Writes[\s\S]*- service "gmail": create_draft/);
	});
});
