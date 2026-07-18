import { afterEach, describe, expect, it } from "vitest";

import {
	computeProviderHealthExitCode,
	type HealthCheckResult,
	resolveProviderStartupHealthPolicy,
} from "../../src/providers/provider-health.js";

const unhealthyProvider: HealthCheckResult = {
	providerId: "israel-services",
	baseUrl: "http://israel-services:3003",
	reachable: true,
	response: { status: "unhealthy" },
};

describe("provider health policy", () => {
	const originalRequireHealthyProviders = process.env.TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS;
	const originalAllowDegradedProviders = process.env.TELCLAUDE_ALLOW_DEGRADED_PROVIDERS;

	afterEach(() => {
		if (originalRequireHealthyProviders === undefined) {
			delete process.env.TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS;
		} else {
			process.env.TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS = originalRequireHealthyProviders;
		}
		if (originalAllowDegradedProviders === undefined) {
			delete process.env.TELCLAUDE_ALLOW_DEGRADED_PROVIDERS;
		} else {
			process.env.TELCLAUDE_ALLOW_DEGRADED_PROVIDERS = originalAllowDegradedProviders;
		}
	});

	it.each([
		["degraded", { ...unhealthyProvider, response: { status: "degraded" as const } }, 1],
		["unhealthy", unhealthyProvider, 2],
		["unreachable", { ...unhealthyProvider, reachable: false, response: undefined }, 2],
	])("defaults startup to continued operation for %s providers", (_label, provider, exitCode) => {
		delete process.env.TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS;

		expect(resolveProviderStartupHealthPolicy([provider])).toMatchObject({
			exitCode,
			shouldExit: false,
		});
	});

	it.each([
		["degraded", { ...unhealthyProvider, response: { status: "degraded" as const } }, 1],
		["unhealthy", unhealthyProvider, 2],
		["unreachable", { ...unhealthyProvider, reachable: false, response: undefined }, 2],
	])("restores fatal startup behavior for %s providers in strict mode", (_label, provider, exitCode) => {
		process.env.TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS = "1";

		expect(resolveProviderStartupHealthPolicy([provider])).toMatchObject({
			exitCode,
			shouldExit: true,
		});
	});

	it("gives the strict flag precedence over the legacy degraded alias", () => {
		process.env.TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS = "1";
		process.env.TELCLAUDE_ALLOW_DEGRADED_PROVIDERS = "1";

		expect(resolveProviderStartupHealthPolicy([unhealthyProvider])).toEqual({
			exitCode: 2,
			shouldExit: true,
			summary: "israel-services: unhealthy",
		});
	});

	it.each([
		["healthy", [{ ...unhealthyProvider, response: { status: "healthy" as const } }], 0],
		["degraded", [{ ...unhealthyProvider, response: { status: "degraded" as const } }], 1],
		["unhealthy", [unhealthyProvider], 2],
		["unreachable", [{ ...unhealthyProvider, reachable: false, response: undefined }], 2],
	])("keeps doctor exit semantics unchanged for %s providers", (_label, results, exitCode) => {
		expect(computeProviderHealthExitCode(results)).toBe(exitCode);
	});
});
