import crypto from "node:crypto";
import type http from "node:http";

import { getChildLogger } from "../logging.js";
import { HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS } from "../providers/household-clalit-policy.js";
import {
	type ProviderProxyRequest,
	type ProviderProxyResponse,
	proxyProviderRequest,
} from "./provider-proxy.js";

const logger = getChildLogger({ module: "tailscale-broker" });

export const BROKER_PROVIDER_READ_PATH = "/v1/broker/provider/read";
export const BROKER_DENIED_PATHS = [
	"/v1/broker/docker",
	"/v1/broker/compose",
	"/v1/broker/vault",
] as const;

const BROKER_ALLOWED_SERVICES = new Set([
	"clalit",
	"poalim",
	"massad",
	"ibi-capital",
	"isracard",
	"visacal",
]);
const BROKER_ALLOWED_READ_ACTIONS = new Set<string>([
	...HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS,
	"home",
	"balance",
	"transactions",
	"portfolio",
	"cards",
	"pending",
	"statements",
]);

export type TailscaleBrokerWhois = {
	readonly loginName: string;
};

export type TailscaleBrokerOptions = {
	readonly whois?: (addr: string) => Promise<TailscaleBrokerWhois | null>;
	readonly nodeToken?: string;
	readonly operatorUserId?: string;
	readonly providerProxy?: (request: ProviderProxyRequest) => Promise<ProviderProxyResponse>;
};

export function isBrokerRequestPath(requestPath: string): boolean {
	return requestPath === BROKER_PROVIDER_READ_PATH || requestPath.startsWith("/v1/broker/");
}

export function normalizeBrokerRemoteAddress(remoteAddress?: string | null): string | null {
	if (!remoteAddress) return null;
	if (remoteAddress.startsWith("::ffff:")) {
		return remoteAddress.slice("::ffff:".length);
	}
	return remoteAddress;
}

export function isBrokerWriteAction(service: string, action: string): boolean {
	if (!BROKER_ALLOWED_SERVICES.has(service) || !BROKER_ALLOWED_READ_ACTIONS.has(action)) {
		return true;
	}
	return false;
}

function extractBearer(header: string | string[] | undefined): string | undefined {
	const raw = Array.isArray(header) ? header[0] : header;
	if (!raw) return undefined;
	const match = /^Bearer\s+(\S+)$/i.exec(raw.trim());
	return match?.[1];
}

function timingSafeEqual(left: string, right: string): boolean {
	const a = Buffer.from(left);
	const b = Buffer.from(right);
	if (a.length !== b.length) return false;
	return crypto.timingSafeEqual(a, b);
}

async function defaultWhois(addr: string): Promise<TailscaleBrokerWhois | null> {
	try {
		const response = await fetch(
			`http://100.100.100.100/localapi/v0/whois?addr=${encodeURIComponent(addr)}`,
			{ signal: AbortSignal.timeout(1_500) },
		);
		if (!response.ok) return null;
		const data = (await response.json()) as { UserProfile?: { LoginName?: string } };
		const loginName = data.UserProfile?.LoginName?.trim();
		return loginName ? { loginName } : null;
	} catch {
		return null;
	}
}

export async function authenticateTailscaleBrokerPeer(
	req: http.IncomingMessage,
	options: TailscaleBrokerOptions = {},
): Promise<{ ok: true; operatorUserId: string } | { ok: false; status: number; error: string }> {
	const operatorUserId =
		options.operatorUserId?.trim() || process.env.TELCLAUDE_BROKER_OPERATOR_USER_ID?.trim() || "admin";
	const configuredToken = options.nodeToken ?? process.env.TELCLAUDE_BROKER_NODE_TOKEN;
	const presented = extractBearer(req.headers.authorization);
	if (configuredToken) {
		if (!presented || !timingSafeEqual(presented, configuredToken)) {
			return { ok: false, status: 401, error: "Unauthorized." };
		}
	}

	const addr = normalizeBrokerRemoteAddress(req.socket.remoteAddress);
	const whois = options.whois ?? defaultWhois;
	const peer = addr ? await whois(addr) : null;
	if (!peer) {
		logger.warn({ addr }, "broker whois failed");
		return { ok: false, status: 401, error: "Unauthorized." };
	}
	return { ok: true, operatorUserId };
}

export function buildBrokerProviderReadBody(
	raw: unknown,
	operatorUserId: string,
): { ok: true; providerId: string; body: string } | { ok: false; status: number; error: string } {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
		return { ok: false, status: 400, error: "Invalid JSON." };
	}
	const fields = raw as Record<string, unknown>;
	const providerId = typeof fields.providerId === "string" ? fields.providerId.trim() : "";
	const service = typeof fields.service === "string" ? fields.service.trim() : "";
	const action = typeof fields.action === "string" ? fields.action.trim() : "";
	const params =
		fields.params && typeof fields.params === "object" && !Array.isArray(fields.params)
			? (fields.params as Record<string, unknown>)
			: {};
	const subjectUserId =
		typeof fields.subjectUserId === "string" && fields.subjectUserId.trim()
			? fields.subjectUserId.trim()
			: operatorUserId;
	if (!providerId || !service || !action) {
		return { ok: false, status: 400, error: "Missing providerId, service, or action." };
	}
	if (isBrokerWriteAction(service, action)) {
		return { ok: false, status: 403, error: "Broker reads cannot execute writes." };
	}
	return {
		ok: true,
		providerId,
		body: JSON.stringify({
			service,
			action,
			params,
			subjectUserId,
			authPolicy: "session_only",
		}),
	};
}

export async function handleTailscaleBrokerRequest(input: {
	req: http.IncomingMessage;
	requestPath: string;
	body: string;
	options?: TailscaleBrokerOptions;
}): Promise<{ status: number; payload: unknown }> {
	if (input.requestPath !== BROKER_PROVIDER_READ_PATH) {
		return { status: 403, payload: { error: "Forbidden." } };
	}

	const auth = await authenticateTailscaleBrokerPeer(input.req, input.options);
	if (!auth.ok) {
		return { status: auth.status, payload: { error: auth.error } };
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(input.body) as unknown;
	} catch {
		return { status: 400, payload: { error: "Invalid JSON." } };
	}

	const built = buildBrokerProviderReadBody(parsed, auth.operatorUserId);
	if (!built.ok) {
		return { status: built.status, payload: { error: built.error } };
	}

	const proxy = input.options?.providerProxy ?? proxyProviderRequest;
	const result = await proxy({
		providerId: built.providerId,
		path: "/v1/fetch",
		method: "POST",
		body: built.body,
		userId: auth.operatorUserId,
	});
	if (result.status === "error") {
		return { status: 502, payload: result };
	}
	return { status: 200, payload: result };
}
