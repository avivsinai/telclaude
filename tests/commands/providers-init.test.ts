import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scaffoldProviderSidecar } from "../../src/commands/provider-scaffold.js";

describe("providers init scaffold", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-provider-init-"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("writes a minimal provider sidecar scaffold", () => {
		const result = scaffoldProviderSidecar({
			providerId: "israel-services",
			services: ["gov-api", "health-api"],
			port: 3010,
			description: "Citizen services sidecar",
			outDir: tempDir,
		});

		expect(result.baseUrl).toBe("http://israel-services:3010");
		expect(result.files.map((file) => file.relativePath).sort()).toEqual([
			"docker/Dockerfile.israel-services",
			"src/israel-services/actions.ts",
			"src/israel-services/config.ts",
			"src/israel-services/health.ts",
			"src/israel-services/index.ts",
			"src/israel-services/server.ts",
			"src/israel-services/types.ts",
		]);
		const server = fs.readFileSync(path.join(tempDir, "src/israel-services/server.ts"), "utf8");
		expect(server).toContain("/v1/health");
		expect(server).toContain("/v1/schema");
		expect(server).toContain("/v1/fetch");
		expect(server).toContain("Citizen services sidecar");
		const types = fs.readFileSync(path.join(tempDir, "src/israel-services/types.ts"), "utf8");
		expect(types).toContain('"gov-api"');
		expect(types).toContain('"health-api"');
		const dockerfile = fs.readFileSync(
			path.join(tempDir, "docker/Dockerfile.israel-services"),
			"utf8",
		);
		expect(dockerfile).toContain("src/israel-services/index.ts");
	});

	it("rejects invalid provider ids", () => {
		expect(() =>
			scaffoldProviderSidecar({
				providerId: "../bad",
				outDir: tempDir,
			}),
		).toThrow(/Provider id/);
	});

	it("refuses to overwrite without force", () => {
		scaffoldProviderSidecar({ providerId: "alpha", outDir: tempDir });

		expect(() => scaffoldProviderSidecar({ providerId: "alpha", outDir: tempDir })).toThrow(
			/Refusing to overwrite/,
		);
	});

	it("preflights overwrite conflicts before writing any scaffold file", () => {
		fs.mkdirSync(path.join(tempDir, "docker"), { recursive: true });
		fs.writeFileSync(path.join(tempDir, "docker/Dockerfile.beta"), "existing", "utf8");

		expect(() => scaffoldProviderSidecar({ providerId: "beta", outDir: tempDir })).toThrow(
			/Refusing to overwrite/,
		);
		expect(fs.existsSync(path.join(tempDir, "src/beta-services/index.ts"))).toBe(false);
	});

	it("overwrites existing scaffold files with force", () => {
		scaffoldProviderSidecar({ providerId: "alpha", outDir: tempDir });
		fs.writeFileSync(path.join(tempDir, "src/alpha-services/health.ts"), "custom", "utf8");

		scaffoldProviderSidecar({ providerId: "alpha", outDir: tempDir, force: true });

		expect(fs.readFileSync(path.join(tempDir, "src/alpha-services/health.ts"), "utf8")).toContain(
			"getHealth",
		);
	});
});
