import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditLogger } from "../../src/security/audit.js";

describe("AuditLogger", () => {
	let tempDir = "";
	let logFile = "";

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-audit-test-"));
		logFile = path.join(tempDir, "logs", "audit.log");
		fs.mkdirSync(path.dirname(logFile), { recursive: true });
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("rotates oversized audit logs before appending new entries", async () => {
		const oldRotated = `${logFile}.2026-05-15T00-00-00-000Z`;
		const manualBackup = `${logFile}.manual-backup`;
		fs.writeFileSync(logFile, "x".repeat(32), "utf8");
		fs.writeFileSync(oldRotated, "old", "utf8");
		fs.writeFileSync(manualBackup, "manual", "utf8");
		fs.utimesSync(logFile, new Date(), new Date());
		fs.utimesSync(
			oldRotated,
			new Date("2026-05-15T00:00:00.000Z"),
			new Date("2026-05-15T00:00:00.000Z"),
		);

		const logger = new AuditLogger({
			enabled: true,
			logFile,
			maxBytes: 16,
			retainedFiles: 1,
		});

		await logger.log({
			timestamp: new Date("2026-05-16T00:00:00.000Z"),
			requestId: "req-1",
			telegramUserId: "tg:1",
			chatId: 123,
			messagePreview: "hello",
			permissionTier: "READ_ONLY",
			outcome: "success",
		});

		const rotatedFiles = fs
			.readdirSync(path.dirname(logFile))
			.filter((entry) => /^audit\.log\.\d{4}-\d{2}-\d{2}T/.test(entry));
		expect(rotatedFiles).toHaveLength(1);
		expect(fs.existsSync(oldRotated)).toBe(false);
		expect(fs.readFileSync(manualBackup, "utf8")).toBe("manual");
		expect(fs.readFileSync(logFile, "utf8")).toContain('"requestId":"req-1"');
		expect(fs.readFileSync(path.join(path.dirname(logFile), rotatedFiles[0] ?? ""), "utf8")).toBe(
			"x".repeat(32),
		);
	});

	it("reads recent entries across retained rotated audit logs", async () => {
		const rotated = `${logFile}.2026-05-15T00-00-00-000Z`;
		const rotatedEntry = {
			timestamp: "2026-05-15T00:00:00.000Z",
			requestId: "rotated-warn",
			telegramUserId: "tg:1",
			chatId: 123,
			messagePreview: "warn",
			observerClassification: "WARN",
			permissionTier: "READ_ONLY",
			outcome: "blocked",
		};
		const activeEntry = {
			timestamp: "2026-05-16T00:00:00.000Z",
			requestId: "active-ok",
			telegramUserId: "tg:2",
			chatId: 456,
			messagePreview: "ok",
			permissionTier: "READ_ONLY",
			outcome: "success",
		};
		fs.writeFileSync(rotated, `${JSON.stringify(rotatedEntry)}\n`, "utf8");
		fs.writeFileSync(logFile, `${JSON.stringify(activeEntry)}\n`, "utf8");

		const logger = new AuditLogger({ enabled: true, logFile });
		const entries = await logger.readRecent(2);

		expect(entries.map((entry) => entry.requestId)).toEqual(["rotated-warn", "active-ok"]);
	});
});
