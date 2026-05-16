import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const relayDeliverLocalFileImpl = vi.hoisted(() => vi.fn());

vi.mock("../../src/relay/capabilities-client.js", () => ({
	relayDeliverLocalFile: (...args: unknown[]) => relayDeliverLocalFileImpl(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		debug: vi.fn(),
		error: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
	}),
}));

import { registerSendFileCommand } from "../../src/commands/send-file.js";
import { registerSendLocalFileCommand } from "../../src/commands/send-local-file.js";

const ORIGINAL_CAPABILITIES_URL = process.env.TELCLAUDE_CAPABILITIES_URL;
const ORIGINAL_REQUEST_USER_ID = process.env.TELCLAUDE_REQUEST_USER_ID;

function buildProgram(): Command {
	const program = new Command();
	program.name("telclaude");
	registerSendFileCommand(program);
	registerSendLocalFileCommand(program);
	return program;
}

describe("send-file commands", () => {
	let stdout: string[] = [];
	let stderr: string[] = [];
	let exitSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		stdout = [];
		stderr = [];
		relayDeliverLocalFileImpl.mockReset();
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://127.0.0.1:9999";
		delete process.env.TELCLAUDE_REQUEST_USER_ID;
		vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
			stdout.push(args.map(String).join(" "));
		});
		vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
			stderr.push(args.map(String).join(" "));
		});
		exitSpy = vi.spyOn(process, "exit").mockImplementation(((_code?: number) => {
			throw new Error(`__process_exit__:${_code ?? 0}`);
		}) as never);
	});

	afterEach(() => {
		vi.restoreAllMocks();
		if (ORIGINAL_CAPABILITIES_URL === undefined) {
			delete process.env.TELCLAUDE_CAPABILITIES_URL;
		} else {
			process.env.TELCLAUDE_CAPABILITIES_URL = ORIGINAL_CAPABILITIES_URL;
		}
		if (ORIGINAL_REQUEST_USER_ID === undefined) {
			delete process.env.TELCLAUDE_REQUEST_USER_ID;
		} else {
			process.env.TELCLAUDE_REQUEST_USER_ID = ORIGINAL_REQUEST_USER_ID;
		}
	});

	it("registers send-file as the operator-facing workspace file command", async () => {
		relayDeliverLocalFileImpl.mockResolvedValueOnce({
			status: "ok",
			path: "/media/outbox/documents/report-1234.pdf",
			filename: "report-1234.pdf",
			size: 42,
		});
		process.env.TELCLAUDE_REQUEST_USER_ID = "user-123";

		await buildProgram().parseAsync([
			"node",
			"telclaude",
			"send-file",
			"--path",
			"/workspace/report.pdf",
			"--filename",
			"report.pdf",
		]);

		expect(relayDeliverLocalFileImpl).toHaveBeenCalledWith({
			sourcePath: "/workspace/report.pdf",
			filename: "report.pdf",
			userId: "user-123",
		});
		expect(stdout.join("\n")).toContain("File ready: /media/outbox/documents/report-1234.pdf");
		expect(stdout.join("\n")).toContain("Filename: report-1234.pdf");
		expect(stdout.join("\n")).toContain("Size: 42 bytes");
		expect(exitSpy).not.toHaveBeenCalled();
	});

	it("keeps send-local-file as a backward-compatible spelling", async () => {
		relayDeliverLocalFileImpl.mockResolvedValueOnce({
			status: "ok",
			path: "/media/outbox/documents/old-1234.pdf",
			filename: "old-1234.pdf",
			size: 99,
		});

		await buildProgram().parseAsync([
			"node",
			"telclaude",
			"send-local-file",
			"--path",
			"/workspace/old.pdf",
		]);

		expect(relayDeliverLocalFileImpl).toHaveBeenCalledWith({
			sourcePath: "/workspace/old.pdf",
			filename: undefined,
			userId: undefined,
		});
		expect(stdout.join("\n")).toContain("File delivered: /media/outbox/documents/old-1234.pdf");
		expect(exitSpy).not.toHaveBeenCalled();
	});

	it("requires --path before contacting the relay", async () => {
		await expect(buildProgram().parseAsync(["node", "telclaude", "send-file"])).rejects.toThrow(
			/__process_exit__:1/,
		);

		expect(relayDeliverLocalFileImpl).not.toHaveBeenCalled();
		expect(stderr.join("\n")).toContain("Error: --path is required.");
		expect(stderr.join("\n")).toContain("Usage: telclaude send-file --path /workspace/file.pdf");
	});
});
