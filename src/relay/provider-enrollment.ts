import type { TelclaudeConfig } from "../config/config.js";
import { type ExternalProviderConfig, loadConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBindingById } from "../config/profiles.js";
import { getChildLogger } from "../logging.js";
import { validateProviderBaseUrl } from "../providers/provider-validation.js";
import { buildRequiredProviderSidecarRelayAuthHeaders } from "./provider-sidecar-auth.js";

const logger = getChildLogger({ module: "provider-enrollment" });

const ENROLL_SESSION_PATH = "/v1/credentials/enroll-session";
const DEFAULT_ENROLL_TIMEOUT_MS = 30_000;
const POLL_PATH_PREFIX = `${ENROLL_SESSION_PATH}/`;

export type ProviderEnrollmentStartRequest = {
	service: string;
	subjectUserId: string;
	actorUserId: string;
};

export type ProviderEnrollmentStartResult =
	| {
			status: "enroll_pending";
			enrollmentId: string;
			interactUrl: string;
			expiresAt: number;
			pollPath: string;
	  }
	| {
			status: "busy" | "error";
			error: string;
	  };

export type ProviderEnrollmentPollResult =
	| { status: "pending"; expiresAt: number }
	| {
			status: "ok";
			summary: {
				service: string;
				owner: string;
				authorizedOperators: string[];
				credentialKeys: string[];
				hasSession: boolean;
				updatedAt: string;
			};
	  }
	| { status: "failed"; error: string }
	| { status: "expired" }
	| { status: "error"; error: string };

export function resolveHouseholdProviderEnrollmentSubject(input: {
	readonly service: string;
	readonly bindingId: string;
	readonly config: TelclaudeConfig;
}): string | null {
	if (input.service.trim() !== "clalit") return null;
	const binding = resolveWhatsAppHouseholdBindingById(input.bindingId, input.config);
	const consent = binding?.providerConsent;
	if (
		!binding ||
		!consent ||
		consent.service !== "clalit" ||
		consent.state !== "granted" ||
		consent.revokedAt
	) {
		return null;
	}
	return binding.subjectUserId;
}

type ProviderResolution = {
	provider: ExternalProviderConfig;
};

export async function startProviderSessionEnrollment(
	request: ProviderEnrollmentStartRequest,
): Promise<ProviderEnrollmentStartResult> {
	const service = request.service.trim();
	const subjectUserId = request.subjectUserId.trim();
	const actorUserId = request.actorUserId.trim();
	if (!service || !subjectUserId || !actorUserId) {
		return { status: "error", error: "service, subjectUserId, and actorUserId are required" };
	}

	const resolution = resolveProviderForEnrollment(service);
	if (!resolution) {
		return { status: "error", error: `No provider configured for service '${service}'` };
	}

	const body = JSON.stringify({ service, subjectUserId });
	const response = await fetchEnrollmentSidecar(resolution.provider, {
		method: "POST",
		path: ENROLL_SESSION_PATH,
		body,
		actorUserId,
	});
	const data = await readJsonResponse(response, resolution.provider.id);

	if (response.status === 202 && isEnrollmentPending(data)) {
		return data;
	}
	if (response.status === 409) {
		return { status: "busy", error: extractError(data) ?? "interactive session active" };
	}
	return {
		status: "error",
		error: extractError(data) ?? `Provider returned HTTP ${response.status}`,
	};
}

export async function pollProviderSessionEnrollment(params: {
	pollPath: string;
	actorUserId: string;
	service: string;
}): Promise<ProviderEnrollmentPollResult> {
	const service = params.service.trim();
	const actorUserId = params.actorUserId.trim();
	if (!service || !actorUserId) {
		return { status: "error", error: "service and actorUserId are required" };
	}
	const pollPath = validateEnrollmentPollPath(params.pollPath);
	if (!pollPath) {
		return { status: "error", error: "Invalid enrollment poll path" };
	}

	const resolution = resolveProviderForEnrollment(service);
	if (!resolution) {
		return { status: "error", error: `No provider configured for service '${service}'` };
	}

	const response = await fetchEnrollmentSidecar(resolution.provider, {
		method: "GET",
		path: pollPath,
		body: "",
		actorUserId,
	});
	const data = await readJsonResponse(response, resolution.provider.id);

	if (response.status === 404) {
		return { status: "error", error: extractError(data) ?? "unknown enrollment" };
	}
	if (!response.ok) {
		return {
			status: "error",
			error: extractError(data) ?? `Provider returned HTTP ${response.status}`,
		};
	}
	if (isEnrollmentPollResult(data)) {
		return data;
	}
	return { status: "error", error: "Invalid provider enrollment poll response" };
}

async function fetchEnrollmentSidecar(
	provider: ExternalProviderConfig,
	request: { method: "GET" | "POST"; path: string; body: string; actorUserId: string },
): Promise<Response> {
	const { url } = await validateProviderBaseUrl(provider.baseUrl);
	const providerUrl = new URL(request.path, url);
	if (providerUrl.origin !== url.origin) {
		throw new Error("Provider enrollment path escaped provider origin");
	}
	const requestPath = `${providerUrl.pathname}${providerUrl.search}`;
	const headers: Record<string, string> = {
		Accept: "application/json",
		"x-actor-user-id": request.actorUserId,
		...(request.method === "POST" ? { "Content-Type": "application/json" } : {}),
		...(await buildRequiredProviderSidecarRelayAuthHeaders({
			provider,
			method: request.method,
			path: requestPath,
			rawBody: request.body,
			actorUserId: request.actorUserId,
		})),
	};

	return fetch(providerUrl.toString(), {
		method: request.method,
		headers,
		body: request.method === "POST" ? request.body : undefined,
		signal: AbortSignal.timeout(DEFAULT_ENROLL_TIMEOUT_MS),
	});
}

function resolveProviderForEnrollment(service: string): ProviderResolution | null {
	const providers = loadConfig().providers ?? [];
	const provider = providers.find((candidate) => candidate.services.includes(service));
	if (!provider) return null;
	return { provider };
}

function validateEnrollmentPollPath(value: string): string | null {
	const trimmed = value.trim();
	if (!trimmed.startsWith(POLL_PATH_PREFIX)) return null;
	if (trimmed.startsWith("//")) return null;
	try {
		const parsed = new URL(trimmed, "http://provider.local");
		if (parsed.origin !== "http://provider.local") return null;
		if (!parsed.pathname.startsWith(POLL_PATH_PREFIX)) return null;
		return `${parsed.pathname}${parsed.search}`;
	} catch {
		return null;
	}
}

async function readJsonResponse(response: Response, providerId: string): Promise<unknown> {
	const contentType = response.headers.get("content-type") || "";
	if (!contentType.includes("application/json")) {
		logger.warn(
			{ providerId, status: response.status, contentType },
			"provider enrollment non-json",
		);
		return undefined;
	}
	try {
		return JSON.parse(await response.text());
	} catch (err) {
		logger.warn(
			{ providerId, status: response.status, error: String(err) },
			"provider enrollment bad json",
		);
		return undefined;
	}
}

function isEnrollmentPending(
	value: unknown,
): value is Extract<ProviderEnrollmentStartResult, { status: "enroll_pending" }> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const fields = value as Record<string, unknown>;
	return (
		fields.status === "enroll_pending" &&
		typeof fields.enrollmentId === "string" &&
		typeof fields.interactUrl === "string" &&
		typeof fields.expiresAt === "number" &&
		typeof fields.pollPath === "string" &&
		validateEnrollmentPollPath(fields.pollPath) !== null
	);
}

function isEnrollmentPollResult(value: unknown): value is ProviderEnrollmentPollResult {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const fields = value as Record<string, unknown>;
	if (fields.status === "pending") return typeof fields.expiresAt === "number";
	if (fields.status === "failed") return typeof fields.error === "string";
	if (fields.status === "expired") return true;
	if (fields.status === "ok") return isEnrollmentSummary(fields.summary);
	if (fields.status === "error") return typeof fields.error === "string";
	return false;
}

function isEnrollmentSummary(
	value: unknown,
): value is Extract<ProviderEnrollmentPollResult, { status: "ok" }>["summary"] {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const fields = value as Record<string, unknown>;
	return (
		typeof fields.service === "string" &&
		typeof fields.owner === "string" &&
		Array.isArray(fields.authorizedOperators) &&
		fields.authorizedOperators.every((item) => typeof item === "string") &&
		Array.isArray(fields.credentialKeys) &&
		fields.credentialKeys.every((item) => typeof item === "string") &&
		typeof fields.hasSession === "boolean" &&
		typeof fields.updatedAt === "string"
	);
}

function extractError(data: unknown): string | undefined {
	if (!data || typeof data !== "object" || Array.isArray(data)) return undefined;
	const error = (data as Record<string, unknown>).error;
	return typeof error === "string" && error.trim() ? error : undefined;
}
