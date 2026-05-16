import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let CardKind: typeof import("../../../src/telegram/cards/types.js").CardKind;
let curatorInboxRenderer: typeof import("../../../src/telegram/cards/renderers/curator-inbox.js").curatorInboxRenderer;
let loadCuratorInboxEntries: typeof import("../../../src/telegram/cards/renderers/curator-inbox.js").loadCuratorInboxEntries;
let resetDatabase: typeof import("../../../src/storage/db.js").resetDatabase;
let upsertCuratorItem: typeof import("../../../src/curator/store.js").upsertCuratorItem;
let getCuratorItem: typeof import("../../../src/curator/store.js").getCuratorItem;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

type CuratorInboxCardState = import("../../../src/telegram/cards/types.js").CuratorInboxCardState;

function baseCard(state: CuratorInboxCardState) {
	return {
		cardId: "curator-card-1",
		shortId: "abcdef12",
		kind: state.kind,
		version: 1,
		chatId: 777,
		messageId: 9,
		actorScope: "admin" as const,
		entityRef: "curator-inbox",
		revision: 1,
		expiresAt: Date.now() + 60_000,
		status: "active" as const,
		createdAt: Date.now(),
		updatedAt: Date.now(),
		state,
	};
}

describe("curator inbox card", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-curator-card-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();

		({ resetDatabase } = await import("../../../src/storage/db.js"));
		resetDatabase();
		({ upsertCuratorItem, getCuratorItem } = await import("../../../src/curator/store.js"));
		({ CardKind } = await import("../../../src/telegram/cards/types.js"));
		({ curatorInboxRenderer, loadCuratorInboxEntries } = await import(
			"../../../src/telegram/cards/renderers/curator-inbox.js"
		));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	function seedItem() {
		return upsertCuratorItem(
			{
				fingerprint: "cron:unsafe:v1",
				kind: "cron_hardening",
				severity: "high",
				source: "cron",
				title: "Cron job needs a skill allowlist",
				summary: "Add explicit --skill flags before it runs unattended.",
				rationale: "Scheduled automation should be narrow.",
				entityRef: "cron:unsafe",
				proposedAction: { type: "manual_cron_hardening" },
				evidence: { jobId: "unsafe" },
			},
			1_700_000_000_000,
		);
	}

	function makeState(): CuratorInboxCardState {
		return {
			kind: CardKind.CuratorInbox,
			title: "Curator",
			view: "list",
			entries: loadCuratorInboxEntries(),
			page: 0,
			lastRefreshedAtMs: Date.now(),
		};
	}

	it("renders open suggestions without exposing raw action JSON", () => {
		const item = seedItem();
		const card = baseCard(makeState());
		const render = curatorInboxRenderer.render(card);

		expect(render.text).toContain("Curator");
		expect(render.text).toContain(item.shortId);
		expect(render.text).toContain("Cron job needs a skill allowlist");
		expect(render.text).not.toContain('"type"');
		expect(
			render.keyboard?.inline_keyboard
				.flat()
				.some((button) => "text" in button && button.text.includes(item.shortId)),
		).toBe(true);
	});

	it("opens detail view and records accept decisions without executing the action", async () => {
		const item = seedItem();
		const card = baseCard(makeState());

		const selected = await curatorInboxRenderer.execute({
			action: { type: "select-0" },
			card,
			ctx: { from: { id: 101 } },
		} as never);
		expect(selected.state?.selectedShortId).toBe(item.shortId);
		expect(selected.state?.view).toBe("detail");

		const accepted = await curatorInboxRenderer.execute({
			action: { type: "accept" },
			card: { ...card, state: selected.state as CuratorInboxCardState },
			ctx: { from: { id: 101 } },
		} as never);

		expect(accepted.callbackText).toBe("Accepted");
		expect(getCuratorItem(item.shortId)?.status).toBe("accepted");
		expect(accepted.state?.entries).toHaveLength(0);
	});
});
