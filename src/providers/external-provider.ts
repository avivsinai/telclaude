import { type ExternalProviderConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import {
	cachedDNSLookup,
	checkPrivateNetworkAccess,
	isPrivateIP,
} from "../sandbox/network-proxy.js";

const logger = getChildLogger({ module: "external-provider" });

export type ProviderResolution = {
	provider: ExternalProviderConfig | null;
	reason?: string;
};

function parseProviderUrl(baseUrl: string): URL {
	const url = new URL(baseUrl);
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new Error(`Unsupported provider URL protocol: ${url.protocol}`);
	}
	return url;
}

async function ensurePrivateProviderUrl(
	provider: ExternalProviderConfig,
): Promise<{ url: URL; port: number }> {
	const cfg = loadConfig();
	const url = parseProviderUrl(provider.baseUrl);
	const port = url.port ? Number.parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;

	const endpoints = cfg.security?.network?.privateEndpoints ?? [];
	if (!endpoints.length) {
		throw new Error(
			"No private endpoints configured. Add a provider endpoint via `telclaude network add`.",
		);
	}

	const privateCheck = await checkPrivateNetworkAccess(url.hostname, port, endpoints);
	if (!privateCheck.allowed || !privateCheck.matchedEndpoint) {
		throw new Error(
			privateCheck.reason || "Provider URL must resolve to an allowlisted private endpoint.",
		);
	}

	const resolved = await cachedDNSLookup(url.hostname);
	const ips = resolved && resolved.length > 0 ? resolved : [url.hostname];
	const nonPrivate = ips.filter((ip) => !isPrivateIP(ip));
	if (nonPrivate.length > 0) {
		throw new Error(
			`Provider URL must resolve to private IPs only (non-private: ${nonPrivate.join(", ")})`,
		);
	}

	return { url, port };
}

export function resolveProviderForService(serviceId: string): ProviderResolution {
	const cfg = loadConfig();
	const providers = cfg.providers ?? [];
	if (!providers.length) {
		return { provider: null, reason: "No providers configured." };
	}

	const matches = providers.filter((p) => p.services?.includes(serviceId));
	if (matches.length === 1) {
		return { provider: matches[0] };
	}
	if (matches.length > 1) {
		return {
			provider: null,
			reason: `Multiple providers match service '${serviceId}'. Configure unique service mapping.`,
		};
	}

	if (providers.length === 1) {
		return { provider: providers[0] };
	}

	return {
		provider: null,
		reason: `No provider found for service '${serviceId}'.`,
	};
}

export type ProviderOtpRequest = {
	service: string;
	code: string;
	challengeId?: string;
	actorUserId: string;
	requestId?: string;
};

export type ProviderOtpResponse = {
	status: string;
	message?: string;
	detail?: string;
	challengeId?: string;
};

export async function sendProviderOtp(request: ProviderOtpRequest): Promise<ProviderOtpResponse> {
	const { provider, reason } = resolveProviderForService(request.service);
	if (!provider) {
		throw new Error(reason || "Provider not found.");
	}

	const { url } = await ensurePrivateProviderUrl(provider);
	const endpoint = new URL("/v1/challenge/respond", url);

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 15000);

	try {
		const response = await fetch(endpoint.toString(), {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-actor-user-id": request.actorUserId,
				"x-request-id": request.requestId ?? "",
			},
			body: JSON.stringify({
				service: request.service,
				code: request.code,
				challengeId: request.challengeId,
				actorUserId: request.actorUserId,
			}),
			signal: controller.signal,
		});

		const text = await response.text();
		if (!response.ok) {
			logger.warn(
				{ status: response.status, provider: provider.id, body: text.slice(0, 200) },
				"provider OTP request failed",
			);
			throw new Error(`Provider responded with ${response.status}.`);
		}

		try {
			return JSON.parse(text) as ProviderOtpResponse;
		} catch {
			return { status: "ok", message: text };
		}
	} finally {
		clearTimeout(timeout);
	}
}
