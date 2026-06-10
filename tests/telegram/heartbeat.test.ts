import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const executeHermesQueryImpl = vi.hoisted(() => vi.fn());
const sendAdminAlertImpl = vi.hoisted(() => vi.fn(async () => undefined));

vi.mock("../../src/hermes/private-execute.js", () => ({
	executeHermesQuery: (...args: unknown[]) => executeHermesQueryImpl(...args),
}));

vi.mock("../../src/telegram/admin-alert.js", () => ({
	sendAdminAlert: (...args: unknown[]) => sendAdminAlertImpl(...args),
}));

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("private heartbeat Hermes runtime routing", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-heartbeat-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		executeHermesQueryImpl.mockReset();
		sendAdminAlertImpl.mockClear();
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

	it("routes private heartbeat through Hermes", async () => {
		executeHermesQueryImpl.mockReturnValueOnce(mockStream("hermes activity"));
		const { handlePrivateHeartbeat } = await import("../../src/telegram/heartbeat.js");

		const result = await handlePrivateHeartbeat({
			hermes: { privateRuntime: { providerScopes: [] } },
			telegram: { heartbeat: { notifyOnActivity: false } },
		} as never);

		expect(result).toEqual({ acted: true, summary: "hermes activity" });
		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			expect.stringContaining("[PRIVATE HEARTBEAT - AUTONOMOUS]"),
			expect.objectContaining({
				poolKey: "telegram:private-heartbeat",
				telclaudeSessionId: "telegram:private-heartbeat",
				profileId: "default",
				userId: "system:private-heartbeat",
				enableSkills: true,
				mcpAuthority: { providerScopes: [] },
			}),
		);
	});

	it("routes private heartbeat to Hermes by default", async () => {
		executeHermesQueryImpl.mockReturnValueOnce(mockStream("hermes activity"));
		const { handlePrivateHeartbeat } = await import("../../src/telegram/heartbeat.js");

		const result = await handlePrivateHeartbeat({
			telegram: { heartbeat: { notifyOnActivity: false } },
		} as never);

		expect(result).toEqual({ acted: true, summary: "hermes activity" });
		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			expect.stringContaining("[PRIVATE HEARTBEAT - AUTONOMOUS]"),
			expect.objectContaining({
				poolKey: "telegram:private-heartbeat",
				telclaudeSessionId: "telegram:private-heartbeat",
				profileId: "default",
				userId: "system:private-heartbeat",
				enableSkills: true,
			}),
		);
	});

	it("uses Hermes even when no remote private runtime is configured", async () => {
		executeHermesQueryImpl.mockReturnValueOnce(mockStream("hermes activity"));
		const { handlePrivateHeartbeat } = await import("../../src/telegram/heartbeat.js");

		const result = await handlePrivateHeartbeat({} as never);

		expect(result).toEqual({ acted: true, summary: "hermes activity" });
		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			expect.stringContaining("[PRIVATE HEARTBEAT - AUTONOMOUS]"),
			expect.objectContaining({
				poolKey: "telegram:private-heartbeat",
				telclaudeSessionId: "telegram:private-heartbeat",
				profileId: "default",
				userId: "system:private-heartbeat",
				enableSkills: true,
			}),
		);
	});
});

async function* mockStream(response: string) {
	yield { type: "text", content: response } as const;
	yield {
		type: "done",
		result: {
			response,
			success: true,
			costUsd: 0,
			numTurns: 1,
			durationMs: 1,
		},
	} as const;
}
