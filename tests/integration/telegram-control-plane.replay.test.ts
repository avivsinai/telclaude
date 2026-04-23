import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFixtureFile } from "../../src/testing/live-replay.js";

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const fixturePath = path.join(
	process.cwd(),
	"tests",
	"fixtures",
	"integration",
	"telegram-control-plane.json",
);

type ControlPlaneFixture = {
	cardCallbacks: {
		providerList: {
			action: string;
			callbackText: string;
			expectedView: string;
			expectedSelectedProviderId: string;
			expectedRevision: number;
		};
	};
	backgroundJobs: {
		completion: { expectedStatus: string; expectedMessage: string };
		restartRecovery: { expectedInterruptedStatus: string; expectedRecoveredStatus: string };
	};
};

async function settle(ms = 30): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, ms));
}

describe("Telegram control-plane replay harness", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-control-plane-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("replays provider card callback reducers/executors with persisted state", async () => {
		const fixture = await readFixtureFile<ControlPlaneFixture>(fixturePath);
		const { buildCallbackToken } = await import("../../src/telegram/cards/callback-tokens.js");
		const { CardRegistry } = await import("../../src/telegram/cards/registry.js");
		const { createCard, getCard } = await import("../../src/telegram/cards/store.js");
		const { handleCallback } = await import("../../src/telegram/cards/callback-controller.js");
		const { CardKind } = await import("../../src/telegram/cards/types.js");

		const registry = new CardRegistry();
		registry.register(CardKind.ProviderList, {
			render: (current) => ({
				text: `${current.state.title}:${current.state.view}`,
				parseMode: "MarkdownV2",
				keyboard: null,
			}),
			reduce: (current) => current.state,
			execute: ({ card }) => ({
				state: {
					...card.state,
					view: "detail",
					selectedProviderId: fixture.data.cardCallbacks.providerList.expectedSelectedProviderId,
				},
				callbackText: fixture.data.cardCallbacks.providerList.callbackText,
				rerender: true,
			}),
		});

		const card = createCard({
			kind: CardKind.ProviderList,
			chatId: 123,
			messageId: 77,
			actorScope: "user:456",
			entityRef: "provider-list",
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				view: "list",
				page: 0,
				canMutate: false,
				providers: [
					{
						id: fixture.data.cardCallbacks.providerList.expectedSelectedProviderId,
						label: fixture.data.cardCallbacks.providerList.callbackText,
						health: "ok",
					},
				],
			},
			expiresAt: Date.now() + 60_000,
		});

		const answerCallbackQuery = vi.fn(async () => {});
		const editMessageText = vi.fn(async () => ({}));
		await handleCallback(
			{
				callbackQuery: {
					data: buildCallbackToken({
						shortId: card.shortId,
						action: fixture.data.cardCallbacks.providerList.action,
						revision: card.revision,
					}),
					message: { message_id: card.messageId },
				},
				chat: { id: card.chatId },
				from: { id: 456, username: "operator" },
				api: { editMessageText },
				answerCallbackQuery,
			} as any,
			{ registry },
		);

		const persisted = getCard(card.cardId);
		expect(answerCallbackQuery).toHaveBeenCalledWith({
			text: fixture.data.cardCallbacks.providerList.callbackText,
			show_alert: false,
		});
		expect(persisted?.revision).toBe(fixture.data.cardCallbacks.providerList.expectedRevision);
		expect(persisted?.state).toEqual(
			expect.objectContaining({
				view: fixture.data.cardCallbacks.providerList.expectedView,
				selectedProviderId: fixture.data.cardCallbacks.providerList.expectedSelectedProviderId,
			}),
		);
	});

	it("replays background completion and restart recovery semantics", async () => {
		const fixture = await readFixtureFile<ControlPlaneFixture>(fixturePath);
		const { claimQueuedJobs, createJob, getJob, markInterruptedOnStartup } = await import(
			"../../src/background/jobs.js"
		);
		const { startBackgroundRunner } = await import("../../src/background/runner.js");

		const completed = createJob({
			title: "replay completion",
			userId: "fixture-user",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", message: fixture.data.backgroundJobs.completion.expectedMessage },
		});
		const handle = startBackgroundRunner({ pollIntervalMs: 10 });
		await handle.tick();
		await settle(50);
		handle.stop();
		expect(getJob(completed.id)?.status).toBe(
			fixture.data.backgroundJobs.completion.expectedStatus,
		);
		expect(getJob(completed.id)?.result?.message).toBe(
			fixture.data.backgroundJobs.completion.expectedMessage,
		);

		const stuck = createJob({
			title: "stuck",
			userId: "fixture-user",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		claimQueuedJobs();
		const recovered = createJob({
			title: "recovered",
			userId: "fixture-user",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", message: "recovered" },
		});

		const interrupted = markInterruptedOnStartup();
		expect(interrupted.map((job) => job.id)).toContain(stuck.id);
		expect(getJob(stuck.id)?.status).toBe(
			fixture.data.backgroundJobs.restartRecovery.expectedInterruptedStatus,
		);

		const restartHandle = startBackgroundRunner({ pollIntervalMs: 10 });
		await restartHandle.tick();
		await settle(50);
		restartHandle.stop();
		expect(getJob(recovered.id)?.status).toBe(
			fixture.data.backgroundJobs.restartRecovery.expectedRecoveredStatus,
		);
	});
});
