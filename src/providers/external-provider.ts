import { type ExternalProviderConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { validateProviderBaseUrl } from "./provider-validation.js";

const logger = getChildLogger({ module: "external-provider" });

export type ProviderResolution = {
	provider: ExternalProviderConfig | null;
	reason?: string;
};

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
		const provider = providers[0];
		const hasExplicitServices = Array.isArray(provider.services) && provider.services.length > 0;
		if (!hasExplicitServices) {
			return { provider };
		}
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

	const { url } = await validateProviderBaseUrl(provider.baseUrl);
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
			const snippet = text.replace(/\s+/g, " ").trim().slice(0, 120);
			logger.warn(
				{ status: response.status, provider: provider.id, body: text.slice(0, 200) },
				"provider OTP request failed",
			);
			throw new Error(
				`Provider responded with ${response.status}${snippet ? `: ${snippet}` : ""}.`,
			);
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
