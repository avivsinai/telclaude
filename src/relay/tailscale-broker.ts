import crypto from "node:crypto";
import type http from "node:http";

import { getChildLogger } from "../logging.js";
import { HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS } from "../providers/household-clalit-policy.js";
import {
	type ProviderProxyRequest,
	type ProviderProxyResponse,
	proxyProviderRequest,
} from "./provider-proxy.js";
import {
	defaultTrustedBrokerProxies,
	isTrustedBrokerProxy,
	lookupTailscaleWhois,
	normalizeBrokerRemoteAddress,
	parseForwardedClientAddress,
	parseSingleClientAddress,
	type TailscaleWhois,
	tailscaleLoginsMatch,
} from "./tailscale-whois.js";

const logger = getChildLogger({ module: "tailscale-broker" });

export const BROKER_PROVIDER_READ_PATH = "/v1/broker/provider/read";
/** Tailscale Serve `--set-path=/v1/broker` strips that prefix before proxying. */
export const BROKER_SERVE_STRIPPED_READ_PATH = "/provider/read";
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

export type TailscaleBrokerWhois = TailscaleWhois;

export type TailscaleBrokerOptions = {
	readonly whois?: (addr: string) => Promise<TailscaleBrokerWhois | null>;
	readonly nodeToken?: string;
	readonly operatorUserId?: string;
	readonly trustedProxies?: readonly string[];
	readonly providerProxy?: (request: ProviderProxyRequest) => Promise<ProviderProxyResponse>;
};

export function isBrokerProviderReadPath(requestPath: string): boolean {
	return (
		requestPath === BROKER_PROVIDER_READ_PATH || requestPath === BROKER_SERVE_STRIPPED_READ_PATH
	);
}

export function isBrokerRequestPath(requestPath: string): boolean {
	return isBrokerProviderReadPath(requestPath) || requestPath.startsWith("/v1/broker/");
}

export { normalizeBrokerRemoteAddress };

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

function serveLoginHeader(header: string | string[] | undefined): string | undefined {
	const raw = Array.isArray(header) ? header[0] : header;
	const login = raw?.trim();
	return login || undefined;
}

function forwardedClientAddress(req: http.IncomingMessage): string | null {
	return (
		parseForwardedClientAddress(req.headers["x-forwarded-for"]) ??
		parseSingleClientAddress(
			typeof req.headers["x-real-ip"] === "string" ? req.headers["x-real-ip"] : "",
		)
	);
}

export async function authenticateTailscaleBrokerPeer(
	req: http.IncomingMessage,
	options: TailscaleBrokerOptions = {},
): Promise<{ ok: true; operatorUserId: string } | { ok: false; status: number; error: string }> {
	const operatorUserId = options.operatorUserId?.trim() || "admin";
	const configuredToken = options.nodeToken ?? process.env.TELCLAUDE_BROKER_NODE_TOKEN;
	const presented = extractBearer(req.headers.authorization);
	if (configuredToken) {
		if (!presented || !timingSafeEqual(presented, configuredToken)) {
			return { ok: false, status: 401, error: "Unauthorized." };
		}
	}

	const whois = options.whois ?? lookupTailscaleWhois;
	const trustedProxies = options.trustedProxies ?? defaultTrustedBrokerProxies();
	const peer = normalizeBrokerRemoteAddress(req.socket.remoteAddress);
	const direct = peer ? await whois(peer) : null;
	if (direct) return { ok: true, operatorUserId };

	if (!peer || !isTrustedBrokerProxy(peer, trustedProxies)) {
		logger.warn({ addr: peer }, "broker whois failed");
		return { ok: false, status: 401, error: "Unauthorized." };
	}

	const client = forwardedClientAddress(req);
	if (!client) {
		logger.warn({ addr: peer }, "broker proxy missing client address");
		return { ok: false, status: 401, error: "Unauthorized." };
	}
	const proxied = await whois(client);
	if (!proxied) {
		logger.warn({ addr: peer, client }, "broker proxy whois failed");
		return { ok: false, status: 401, error: "Unauthorized." };
	}
	const serveLogin = serveLoginHeader(req.headers["tailscale-user-login"]);
	if (serveLogin && !tailscaleLoginsMatch(serveLogin, proxied.loginName)) {
		logger.warn({ addr: peer, client }, "broker serve login mismatch");
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
	if (!isBrokerProviderReadPath(input.requestPath)) {
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
