import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { __test as outboundTest } from "../../src/telegram/outbound.js";

const SECRET_SAMPLE = "sk-0123456789abcdef0123";

describe("outbound media secret scanning", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-outbound-"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("blocks oversized files that cannot be scanned", async () => {
		const filePath = path.join(tempDir, "oversize.txt");
		const size = outboundTest.MAX_FILE_SCAN_SIZE + 1;
		fs.writeFileSync(filePath, Buffer.alloc(size, "a"));

		const result = await outboundTest.scanFileForSecrets(filePath);
		expect(result.safe).toBe(false);
		expect(result.reason).toMatch(/too large/i);
	});

	it("blocks secrets in small files", async () => {
		const filePath = path.join(tempDir, "secret.txt");
		fs.writeFileSync(filePath, `token=${SECRET_SAMPLE}`);

		const result = await outboundTest.scanFileForSecrets(filePath);
		expect(result.safe).toBe(false);
		expect(result.reason).toMatch(/sensitive/i);
	});
});
