import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const executeRemoteQueryImpl = vi.hoisted(() => vi.fn());
const executeHermesPrivateQueryImpl = vi.hoisted(() => vi.fn());
const shouldUseHermesPrivateRuntimeImpl = vi.hoisted(() =>
	vi.fn((env: NodeJS.ProcessEnv = process.env) => env.TELCLAUDE_HERMES_PRIVATE_RUNTIME === "1"),
);
const sendAdminAlertImpl = vi.hoisted(() => vi.fn(async () => undefined));

vi.mock("../../src/agent/client.js", () => ({
	executeRemoteQuery: (...args: unknown[]) => executeRemoteQueryImpl(...args),
}));

vi.mock("../../src/hermes/private-execute.js", () => ({
	executeHermesPrivateQuery: (...args: unknown[]) => executeHermesPrivateQueryImpl(...args),
	shouldUseHermesPrivateRuntime: (...args: unknown[]) => shouldUseHermesPrivateRuntimeImpl(...args),
}));

vi.mock("../../src/telegram/admin-alert.js", () => ({
	sendAdminAlert: (...args: unknown[]) => sendAdminAlertImpl(...args),
}));

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const ORIGINAL_AGENT_URL = process.env.TELCLAUDE_AGENT_URL;
const ORIGINAL_HERMES_PRIVATE_RUNTIME = process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME;

describe("private heartbeat Hermes runtime routing", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-heartbeat-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		delete process.env.TELCLAUDE_AGENT_URL;
		delete process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME;
		executeRemoteQueryImpl.mockReset();
		executeHermesPrivateQueryImpl.mockReset();
		shouldUseHermesPrivateRuntimeImpl.mockClear();
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
		if (ORIGINAL_AGENT_URL === undefined) {
			delete process.env.TELCLAUDE_AGENT_URL;
		} else {
			process.env.TELCLAUDE_AGENT_URL = ORIGINAL_AGENT_URL;
		}
		if (ORIGINAL_HERMES_PRIVATE_RUNTIME === undefined) {
			delete process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME;
		} else {
			process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = ORIGINAL_HERMES_PRIVATE_RUNTIME;
		}
	});

	it("keeps the remote private heartbeat path when Hermes is off", async () => {
		process.env.TELCLAUDE_AGENT_URL = "http://agent:8788";
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "0";
		executeRemoteQueryImpl.mockReturnValueOnce(mockStream("remote activity"));
		executeHermesPrivateQueryImpl.mockReturnValueOnce(mockStream("wrong runtime"));
		const { handlePrivateHeartbeat } = await import("../../src/telegram/heartbeat.js");

		const result = await handlePrivateHeartbeat({
			telegram: { heartbeat: { notifyOnActivity: false } },
		} as never);

		expect(result).toEqual({ acted: true, summary: "remote activity" });
		expect(executeHermesPrivateQueryImpl).not.toHaveBeenCalled();
		expect(executeRemoteQueryImpl).toHaveBeenCalledWith(
			expect.stringContaining("[PRIVATE HEARTBEAT - AUTONOMOUS]"),
			expect.objectContaining({
				agentUrl: "http://agent:8788",
				scope: "telegram",
				poolKey: "telegram:private-heartbeat",
				userId: "system:private-heartbeat",
			}),
		);
	});

	it("routes private heartbeat to Hermes when the Hermes flag is on", async () => {
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "1";
		executeHermesPrivateQueryImpl.mockReturnValueOnce(mockStream("hermes activity"));
		const { handlePrivateHeartbeat } = await import("../../src/telegram/heartbeat.js");

		const result = await handlePrivateHeartbeat({
			telegram: { heartbeat: { notifyOnActivity: false } },
		} as never);

		expect(result).toEqual({ acted: true, summary: "hermes activity" });
		expect(executeRemoteQueryImpl).not.toHaveBeenCalled();
		expect(executeHermesPrivateQueryImpl).toHaveBeenCalledWith(
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

	it("skips when neither private runtime is configured", async () => {
		const { handlePrivateHeartbeat } = await import("../../src/telegram/heartbeat.js");

		const result = await handlePrivateHeartbeat({} as never);

		expect(result).toEqual({ acted: false, summary: "" });
		expect(executeRemoteQueryImpl).not.toHaveBeenCalled();
		expect(executeHermesPrivateQueryImpl).not.toHaveBeenCalled();
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
