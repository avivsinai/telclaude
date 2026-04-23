import { MoltbookClient } from "../social/backends/moltbook.js";
import type { SocialNotification } from "../social/types.js";
import { untrustedPublicText } from "./live-replay.js";

export type FailureKind =
	| "auth"
	| "approval_required"
	| "rate_limited"
	| "not_found"
	| "validation"
	| "server"
	| "network"
	| "unknown"
	| "skipped";

export type ProbeCheck = {
	name: string;
	status: "passed" | "failed" | "skipped";
	failureKind?: FailureKind;
	detail?: string;
};

export type ProviderProbeResult = {
	target: "provider";
	providerId: string;
	baseUrl: string;
	checks: ProbeCheck[];
	health?: unknown;
	schema?: unknown;
	readAction?: {
		service: string;
		action: string;
		status: number;
		response: unknown;
		failureKind?: FailureKind;
	};
};

export type SocialProbeResult = {
	target: "social";
	serviceId: "moltbook";
	baseUrl: string;
	checks: ProbeCheck[];
	read?: {
		status: "passed" | "failed";
		notificationCount: number;
		notifications: unknown[];
		failureKind?: FailureKind;
		error?: string;
	};
	post?: {
		status: "passed" | "failed" | "skipped";
		httpStatus?: number;
		postId?: string;
		failureKind?: FailureKind;
		error?: string;
	};
};

type FetchLike = typeof fetch;

type ProviderActionSelection = {
	service: string;
	action: string;
};

function safeJsonParse(text: string): unknown {
	try {
		return text ? JSON.parse(text) : null;
	} catch {
		return text;
	}
}

export function classifyHttpFailure(status: number | undefined, error?: string): FailureKind {
	if (status === 401 || status === 403) return "auth";
	if (status === 402) return "approval_required";
	if (status === 404) return "not_found";
	if (status === 408 || status === 429) return "rate_limited";
	if (status !== undefined && status >= 400 && status < 500) return "validation";
	if (status !== undefined && status >= 500) return "server";
	if (error) return "network";
	return "unknown";
}

function asRecord(value: unknown): Record<string, unknown> | null {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function asString(value: unknown): string | null {
	return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function actionList(service: Record<string, unknown>): Record<string, unknown>[] {
	const candidates = [service.actions, service.endpoints];
	for (const candidate of candidates) {
		if (Array.isArray(candidate)) {
			return candidate
				.map((entry) => asRecord(entry))
				.filter((entry): entry is Record<string, unknown> => Boolean(entry));
		}
		if (asRecord(candidate)) {
			return Object.entries(candidate as Record<string, unknown>).map(([id, entry]) => ({
				...(asRecord(entry) ?? {}),
				id,
			}));
		}
	}
	return [];
}

export function selectReadProviderAction(schema: unknown): ProviderActionSelection | null {
	const root = asRecord(schema);
	const services = root?.services;
	if (!Array.isArray(services)) {
		return null;
	}

	for (const rawService of services) {
		const service = asRecord(rawService);
		if (!service) continue;
		const serviceId = asString(service.id) ?? asString(service.service) ?? asString(service.name);
		if (!serviceId) continue;

		for (const action of actionList(service)) {
			const actionId =
				asString(action.id) ??
				asString(action.action) ??
				asString(action.name) ??
				asString(action.key);
			if (!actionId) continue;
			const actionType = asString(action.type) ?? asString(action.mode);
			const method = asString(action.method)?.toUpperCase();
			const requiresAuth = action.requiresAuth === true;
			if (actionType === "read" || method === "GET" || !requiresAuth) {
				return { service: serviceId, action: actionId };
			}
		}
	}

	return null;
}

async function fetchJson(
	fetchImpl: FetchLike,
	url: URL,
	init: RequestInit,
): Promise<{ ok: boolean; status: number; payload: unknown; statusText: string }> {
	const response = await fetchImpl(url, init);
	const text = await response.text();
	return {
		ok: response.ok,
		status: response.status,
		statusText: response.statusText,
		payload: safeJsonParse(text),
	};
}

export async function runProviderProbe(options: {
	providerId: string;
	baseUrl: string;
	readAction?: ProviderActionSelection;
	readParams?: Record<string, unknown>;
	fetchImpl?: FetchLike;
}): Promise<ProviderProbeResult> {
	const fetchImpl = options.fetchImpl ?? fetch;
	const baseUrl = options.baseUrl.replace(/\/+$/, "");
	const checks: ProbeCheck[] = [];
	const result: ProviderProbeResult = {
		target: "provider",
		providerId: options.providerId,
		baseUrl,
		checks,
	};

	try {
		const health = await fetchJson(fetchImpl, new URL("/v1/health", baseUrl), {
			method: "GET",
			headers: { accept: "application/json" },
		});
		result.health = health.payload;
		checks.push(
			health.ok
				? { name: "provider.health", status: "passed" }
				: {
						name: "provider.health",
						status: "failed",
						failureKind: classifyHttpFailure(health.status),
						detail: `HTTP ${health.status}: ${health.statusText}`,
					},
		);
	} catch (error) {
		checks.push({
			name: "provider.health",
			status: "failed",
			failureKind: "network",
			detail: error instanceof Error ? error.message : String(error),
		});
	}

	try {
		const schema = await fetchJson(fetchImpl, new URL("/v1/schema", baseUrl), {
			method: "GET",
			headers: { accept: "application/json" },
		});
		result.schema = schema.payload;
		checks.push(
			schema.ok
				? { name: "provider.schema", status: "passed" }
				: {
						name: "provider.schema",
						status: "failed",
						failureKind: classifyHttpFailure(schema.status),
						detail: `HTTP ${schema.status}: ${schema.statusText}`,
					},
		);

		const selected = options.readAction ?? selectReadProviderAction(schema.payload);
		if (!schema.ok || !selected) {
			checks.push({
				name: "provider.read_action",
				status: "skipped",
				detail: "No read action available from schema.",
			});
			return result;
		}

		const readBody = JSON.stringify({
			service: selected.service,
			action: selected.action,
			params: options.readParams ?? {},
		});
		const read = await fetchJson(fetchImpl, new URL("/v1/fetch", baseUrl), {
			method: "POST",
			headers: {
				accept: "application/json",
				"content-type": "application/json",
				"x-actor-user-id": "integration-harness",
			},
			body: readBody,
		});
		const failureKind = read.ok ? undefined : classifyHttpFailure(read.status);
		result.readAction = {
			service: selected.service,
			action: selected.action,
			status: read.status,
			response: read.payload,
			...(failureKind ? { failureKind } : {}),
		};
		checks.push(
			read.ok
				? { name: "provider.read_action", status: "passed" }
				: {
						name: "provider.read_action",
						status: "failed",
						failureKind,
						detail: `HTTP ${read.status}: ${read.statusText}`,
					},
		);
	} catch (error) {
		checks.push({
			name: "provider.schema_or_read",
			status: "failed",
			failureKind: "network",
			detail: error instanceof Error ? error.message : String(error),
		});
	}

	return result;
}

function markPublicFields(value: unknown, key?: string): unknown {
	const publicTextKeys = new Set([
		"content",
		"text",
		"message",
		"body",
		"authorName",
		"authorHandle",
	]);
	if (typeof value === "string" && key && publicTextKeys.has(key)) {
		return untrustedPublicText(value);
	}
	if (Array.isArray(value)) {
		return value.map((entry) => markPublicFields(entry));
	}
	const record = asRecord(value);
	if (!record) {
		return value;
	}
	const next: Record<string, unknown> = {};
	for (const [childKey, childValue] of Object.entries(record)) {
		next[childKey] = markPublicFields(childValue, childKey);
	}
	return next;
}

export function markSocialNotificationsUntrusted(notifications: SocialNotification[]): unknown[] {
	return notifications.map((notification) => markPublicFields(notification));
}

export async function runMoltbookSocialProbe(options: {
	baseUrl: string;
	apiKey: string;
	fetchImpl?: FetchLike;
	allowPublicMutation?: boolean;
	postContent?: string;
}): Promise<SocialProbeResult> {
	const baseUrl = options.baseUrl.replace(/\/+$/, "");
	const client = new MoltbookClient({
		apiKey: options.apiKey,
		baseUrl,
		fetchImpl: options.fetchImpl ?? fetch,
	});
	const checks: ProbeCheck[] = [];
	const result: SocialProbeResult = {
		target: "social",
		serviceId: "moltbook",
		baseUrl,
		checks,
	};

	try {
		const notifications = await client.fetchNotifications();
		result.read = {
			status: "passed",
			notificationCount: notifications.length,
			notifications: markSocialNotificationsUntrusted(notifications),
		};
		checks.push({ name: "social.read_notifications", status: "passed" });
	} catch (error) {
		const status =
			typeof error === "object" && error !== null
				? (error as { status?: number }).status
				: undefined;
		const message = error instanceof Error ? error.message : String(error);
		const failureKind = classifyHttpFailure(status, message);
		result.read = {
			status: "failed",
			notificationCount: 0,
			notifications: [],
			failureKind,
			error: message,
		};
		checks.push({
			name: "social.read_notifications",
			status: "failed",
			failureKind,
			detail: message,
		});
	}

	if (!options.allowPublicMutation) {
		result.post = {
			status: "skipped",
			failureKind: "skipped",
			error: "Public mutation disabled. Set explicit live test account flags to enable.",
		};
		checks.push({
			name: "social.create_post",
			status: "skipped",
			failureKind: "skipped",
			detail: "Public mutation disabled.",
		});
		return result;
	}

	const postContent =
		options.postContent ?? `telclaude integration harness smoke test ${new Date().toISOString()}`;
	const post = await client.createPost(postContent);
	if (post.ok) {
		result.post = { status: "passed", httpStatus: post.status, postId: post.postId };
		checks.push({ name: "social.create_post", status: "passed" });
		return result;
	}

	const failureKind = post.rateLimited ? "rate_limited" : classifyHttpFailure(post.status);
	result.post = {
		status: "failed",
		httpStatus: post.status,
		failureKind,
		error: post.error,
	};
	checks.push({
		name: "social.create_post",
		status: "failed",
		failureKind,
		detail: post.error,
	});
	return result;
}

export function assertProviderReplayFixture(result: ProviderProbeResult): void {
	const failed = result.checks.filter((check) => check.status === "failed");
	if (failed.length > 0) {
		throw new Error(
			`Provider replay fixture contains failed checks: ${failed.map((c) => c.name).join(", ")}`,
		);
	}
	if (
		!result.checks.some((check) => check.name === "provider.health" && check.status === "passed")
	) {
		throw new Error("Provider replay fixture is missing a passing health probe.");
	}
	if (
		!result.checks.some((check) => check.name === "provider.schema" && check.status === "passed")
	) {
		throw new Error("Provider replay fixture is missing a passing schema probe.");
	}
	if (!result.readAction || result.readAction.status < 200 || result.readAction.status >= 300) {
		throw new Error("Provider replay fixture is missing a successful read action.");
	}
}

function hasUntrustedPublicMarker(value: unknown): boolean {
	if (
		typeof value === "object" &&
		value !== null &&
		(value as { trust?: unknown }).trust === "untrusted_public"
	) {
		return true;
	}
	if (Array.isArray(value)) {
		return value.some(hasUntrustedPublicMarker);
	}
	const record = asRecord(value);
	return record ? Object.values(record).some(hasUntrustedPublicMarker) : false;
}

export function assertSocialReplayFixture(result: SocialProbeResult): void {
	if (!result.read || result.read.status !== "passed") {
		throw new Error("Social replay fixture is missing a passing read probe.");
	}
	if (!hasUntrustedPublicMarker(result.read.notifications)) {
		throw new Error("Social replay fixture must mark public content as untrusted.");
	}
	if (!result.post || result.post.status !== "failed" || !result.post.failureKind) {
		throw new Error("Social replay fixture is missing post failure taxonomy.");
	}
}
