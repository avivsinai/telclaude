import { getChildLogger } from "../logging.js";
import { validateProviderBaseUrl } from "./provider-validation.js";

const logger = getChildLogger({ module: "provider-health" });

// Health response from provider
export interface ConnectorHealth {
	status: "ok" | "auth_expired" | "drift_detected" | "error";
	lastSuccess?: string;
	lastAttempt?: string;
	failureCount?: number;
	driftSignals?: string[];
}

export interface HealthAlert {
	level: "warn" | "error";
	connector: string;
	message: string;
	since?: string;
}

export interface ProviderHealthResponse {
	status: "healthy" | "degraded" | "unhealthy";
	connectors?: Record<string, ConnectorHealth>;
	alerts?: HealthAlert[];
	error?: string;
}

export interface HealthCheckResult {
	providerId: string;
	baseUrl: string;
	reachable: boolean;
	response?: ProviderHealthResponse;
	error?: string;
}

export async function checkProviderHealth(
	providerId: string,
	baseUrl: string,
): Promise<HealthCheckResult> {
	const result: HealthCheckResult = {
		providerId,
		baseUrl,
		reachable: false,
	};

	try {
		const { url: base } = await validateProviderBaseUrl(baseUrl);
		const url = new URL("/v1/health", base);

		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 10000);

		try {
			const response = await fetch(url.toString(), {
				method: "GET",
				headers: {
					accept: "application/json",
				},
				signal: controller.signal,
			});

			if (!response.ok) {
				result.error = `HTTP ${response.status}: ${response.statusText}`;
				return result;
			}

			const text = await response.text();
			try {
				result.response = JSON.parse(text) as ProviderHealthResponse;
				result.reachable = true;
			} catch {
				result.error = "Invalid JSON response from health endpoint";
			}
		} finally {
			clearTimeout(timeout);
		}
	} catch (err) {
		if (err instanceof Error && err.name === "AbortError") {
			result.error = "Request timeout (10s)";
		} else if (err instanceof Error && err.message) {
			result.error = err.message;
		} else {
			result.error = String(err);
		}
	}

	return result;
}

export function computeProviderHealthExitCode(results: HealthCheckResult[]): number {
	let hasError = false;
	let hasWarn = false;

	for (const result of results) {
		if (!result.reachable) {
			hasError = true;
			continue;
		}

		const status = result.response?.status;
		if (status === "unhealthy") {
			hasError = true;
		} else if (status === "degraded") {
			hasWarn = true;
		}

		for (const alert of result.response?.alerts ?? []) {
			if (alert.level === "error") {
				hasError = true;
			} else if (alert.level === "warn") {
				hasWarn = true;
			}
		}
	}

	if (hasError) return 2;
	if (hasWarn) return 1;
	return 0;
}

export function formatProviderHealthSummary(results: HealthCheckResult[]): string {
	const issues = results.filter(
		(result) => !result.reachable || result.response?.status !== "healthy",
	);
	if (issues.length === 0) {
		return "All providers healthy.";
	}
	return issues
		.map((result) => `${result.providerId}: ${result.response?.status ?? result.error}`)
		.join("; ");
}

export function logProviderHealthResults(results: HealthCheckResult[]): void {
	for (const result of results) {
		if (!result.reachable) {
			logger.warn(
				{ provider: result.providerId, error: result.error },
				"provider health check failed",
			);
			continue;
		}
		const status = result.response?.status ?? "unknown";
		if (status === "healthy") {
			logger.info({ provider: result.providerId }, "provider healthy");
		} else {
			logger.warn({ provider: result.providerId, status }, "provider not healthy");
		}
	}
}
