import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let CardKind: typeof import("../../../src/telegram/cards/types.js").CardKind;
let systemHealthRenderer: typeof import(
	"../../../src/telegram/cards/renderers/system-health.js"
).systemHealthRenderer;
let resolveNthIssueIndex: typeof import(
	"../../../src/telegram/cards/renderers/system-health.js"
).resolveNthIssueIndex;
let getRemediation: typeof import("../../../src/telegram/remediation-commands.js").getRemediation;
let listRemediations: typeof import(
	"../../../src/telegram/remediation-commands.js"
).listRemediations;
let REMEDIATION_KEYS: typeof import(
	"../../../src/telegram/remediation-commands.js"
).REMEDIATION_KEYS;
let registerAllCardRenderers: typeof import(
	"../../../src/telegram/cards/renderers/index.js"
).registerAllCardRenderers;
let resetDatabase: typeof import("../../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

type SystemHealthCardState = import(
	"../../../src/telegram/cards/types.js"
).SystemHealthCardState;

function makeBaseCard(overrides: Partial<SystemHealthCardState> = {}) {
	const state: SystemHealthCardState = {
		kind: "SystemHealth" as never,
		title: "System Health",
		view: "list",
		overallStatus: "degraded",
		issueCount: 2,
		collectedAtMs: Date.now(),
		items: [
			{ id: "tier:default", label: "Default tier", status: "ok", detail: "READ_ONLY" },
			{
				id: "vault:daemon",
				label: "Vault",
				status: "unreachable",
				detail: "socket not responding",
				remediationKey: "vault_unreachable",
			},
			{
				id: "oauth:google",
				label: "OAuth Google",
				status: "auth_expired",
				detail: "refresh token revoked",
				remediationKey: "google_oauth_expired",
			},
			{ id: "providers:none", label: "Providers", status: "ok", detail: "none configured" },
		],
		...overrides,
	};
	return {
		cardId: "sh-1",
		shortId: "abcdef12",
		kind: state.kind,
		version: 1,
		chatId: 777,
		messageId: 55,
		actorScope: "user:101" as const,
		entityRef: "system-health",
		revision: 1,
		expiresAt: Date.now() + 60_000,
		status: "active" as const,
		createdAt: Date.now(),
		updatedAt: Date.now(),
		state,
	};
}

describe("system health card", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-system-health-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../../src/storage/db.js"));
		resetDatabase();
		({ CardKind } = await import("../../../src/telegram/cards/types.js"));
		({ systemHealthRenderer, resolveNthIssueIndex } = await import(
			"../../../src/telegram/cards/renderers/system-health.js"
		));
		({ getRemediation, listRemediations, REMEDIATION_KEYS } = await import(
			"../../../src/telegram/remediation-commands.js"
		));
		({ registerAllCardRenderers } = await import(
			"../../../src/telegram/cards/renderers/index.js"
		));
		registerAllCardRenderers();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("renders the list view with an inline fix button per degraded item", () => {
		const card = { ...makeBaseCard(), kind: CardKind.SystemHealth } as any;
		const render = systemHealthRenderer.render(card);
		expect(render.text).toContain("System Health");
		expect(render.text).toContain("Vault");
		expect(render.text).toContain("OAuth Google");

		const labels =
			render.keyboard?.inline_keyboard
				.flat()
				.map((button) => ("text" in button ? button.text : "")) ?? [];
		expect(labels.some((t) => t.includes("Vault"))).toBe(true);
		expect(labels.some((t) => t.includes("OAuth Google"))).toBe(true);
		expect(labels.some((t) => t.includes("Refresh"))).toBe(true);
	});

	it("maps fix-N actions to the Nth degraded item, skipping ok entries", () => {
		const card = { ...makeBaseCard(), kind: CardKind.SystemHealth } as any;
		const idxFirst = resolveNthIssueIndex(card.state, 0);
		const idxSecond = resolveNthIssueIndex(card.state, 1);
		const idxMissing = resolveNthIssueIndex(card.state, 2);

		expect(card.state.items[idxFirst].id).toBe("vault:daemon");
		expect(card.state.items[idxSecond].id).toBe("oauth:google");
		expect(idxMissing).toBe(-1);
	});

	it("reduces fix-0 into the remediation view with the corresponding item selected", () => {
		const card = { ...makeBaseCard(), kind: CardKind.SystemHealth } as any;
		const nextState = systemHealthRenderer.reduce(card, { type: "fix-0" });
		expect(nextState.view).toBe("remediation");
		expect(nextState.selectedItemId).toBe("vault:daemon");
	});

	it("renders the central remediation command without hardcoding strings in the renderer", () => {
		const base = makeBaseCard();
		const card = {
			...base,
			kind: CardKind.SystemHealth,
			state: {
				...base.state,
				view: "remediation" as const,
				selectedItemId: "vault:daemon",
			},
		} as any;
		const render = systemHealthRenderer.render(card);
		const expected = getRemediation("vault_unreachable");
		expect(expected).toBeDefined();
		if (expected) {
			// MarkdownV2 escapes `-` in the rendered text; compare by
			// stripping leading backslashes before punctuation.
			const unescape = (s: string) => s.replace(/\\([_*[\]()~`>#+\-=|{}.!\\])/g, "$1");
			expect(unescape(render.text)).toContain(expected.command);
			expect(unescape(render.text)).toContain(expected.title);
		}
	});

	it("falls back cleanly when an item has no remediation key", () => {
		const base = makeBaseCard();
		const card = {
			...base,
			kind: CardKind.SystemHealth,
			state: {
				...base.state,
				view: "remediation" as const,
				selectedItemId: "tier:default",
			},
		} as any;
		const render = systemHealthRenderer.render(card);
		expect(render.text).toContain("No remediation available");
	});

	it("remediation table exposes stable keys via REMEDIATION_KEYS and listRemediations", () => {
		const keys = REMEDIATION_KEYS;
		const list = listRemediations();
		expect(list.length).toBe(keys.length);
		for (const entry of list) {
			expect(keys).toContain(entry.key);
			expect(entry.command.length).toBeGreaterThan(0);
			expect(entry.title.length).toBeGreaterThan(0);
		}
	});

	it("view-list reducer returns to the list view and clears selection", () => {
		const base = makeBaseCard();
		const card = {
			...base,
			kind: CardKind.SystemHealth,
			state: {
				...base.state,
				view: "remediation" as const,
				selectedItemId: "vault:daemon",
			},
		} as any;
		const nextState = systemHealthRenderer.reduce(card, { type: "view-list" });
		expect(nextState.view).toBe("list");
		expect(nextState.selectedItemId).toBeUndefined();
	});

	it("execute(refresh) returns a fresh state from collectSystemHealth", async () => {
		vi.resetModules();
		vi.doMock("../../../src/telegram/status-overview.js", () => ({
			collectSystemHealth: async () => ({
				overallStatus: "ok",
				issueCount: 0,
				collectedAtMs: 1_700_000_000_000,
				items: [
					{
						id: "tier:default",
						label: "Default tier",
						status: "ok",
						detail: "READ_ONLY",
					},
				],
			}),
		}));
		const mod = await import("../../../src/telegram/cards/renderers/system-health.js");
		const { CardKind: CK } = await import("../../../src/telegram/cards/types.js");
		const card = { ...makeBaseCard(), kind: CK.SystemHealth } as any;
		const result = await mod.systemHealthRenderer.execute({
			action: { type: "refresh" },
			card,
			ctx: { api: {}, from: { id: 101 } },
		} as any);
		expect(result.rerender).toBe(true);
		expect(result.state?.overallStatus).toBe("ok");
		expect(result.state?.issueCount).toBe(0);
		expect(result.state?.items).toHaveLength(1);
		expect(result.callbackText).toBe("All systems nominal");
	});

	it("execute(refresh) handles probe failures gracefully", async () => {
		vi.resetModules();
		vi.doMock("../../../src/telegram/status-overview.js", () => ({
			collectSystemHealth: async () => {
				throw new Error("probe boom");
			},
		}));
		const mod = await import("../../../src/telegram/cards/renderers/system-health.js");
		const { CardKind: CK } = await import("../../../src/telegram/cards/types.js");
		const card = { ...makeBaseCard(), kind: CK.SystemHealth } as any;
		const result = await mod.systemHealthRenderer.execute({
			action: { type: "refresh" },
			card,
			ctx: { api: {}, from: { id: 101 } },
		} as any);
		expect(result.rerender).toBe(false);
		expect(result.callbackAlert).toBe(true);
		expect(result.callbackText).toContain("Health probe failed");
	});

	it("execute(fix-N) warns if the issue index no longer exists", async () => {
		const card = {
			...makeBaseCard({
				items: [
					{ id: "tier:default", label: "Default tier", status: "ok", detail: "READ_ONLY" },
				],
				issueCount: 0,
			}),
			kind: CardKind.SystemHealth,
		} as any;
		const result = await systemHealthRenderer.execute({
			action: { type: "fix-0" },
			card,
			ctx: { api: {}, from: { id: 101 } },
		} as any);
		expect(result.callbackAlert).toBe(true);
		expect(result.callbackText).toBe("Issue no longer present");
	});
});
