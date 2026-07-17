import type { ExternalProviderConfig } from "../config/config.js";
import { loadConfig } from "../config/config.js";
import { validateProviderBaseUrl } from "../providers/provider-validation.js";
import { buildRequiredProviderSidecarRelayAuthHeaders } from "./provider-sidecar-auth.js";
import type { WhatsAppProviderChallengeResponder } from "./whatsapp-provider-challenge-interceptor.js";

const INITIATE_PATH = "/v1/fetch";
const RESPOND_PATH = "/v1/challenge/respond";
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const CHALLENGE_ID_RE = /^[A-Za-z0-9_-]{1,256}$/;

type FetchLike = typeof fetch;
type Signer = typeof buildRequiredProviderSidecarRelayAuthHeaders;
type ProviderUrlValidator = typeof validateProviderBaseUrl;

export type ProviderChallengeSidecar = {
	initiate(input: { readonly actorUserId: string; readonly subjectUserId: string }): Promise<
		| {
				readonly status: "challenge";
				readonly challengeId: string;
				readonly challengeType: "sms_otp";
		  }
		| { readonly status: "error" }
	>;
	respond(input: {
		readonly actorUserId: string;
		readonly challengeId: string;
		readonly code: string;
	}): Promise<{ readonly status: "success" | "rejected" | "expired" | "error" }>;
};

export function createProviderChallengeSidecar(options: {
	readonly provider: ExternalProviderConfig;
	readonly fetch?: FetchLike;
	readonly sign?: Signer;
	readonly validateUrl?: ProviderUrlValidator;
}): ProviderChallengeSidecar {
	const fetchImpl = options.fetch ?? fetch;
	const sign = options.sign ?? buildRequiredProviderSidecarRelayAuthHeaders;
	const validateUrl = options.validateUrl ?? validateProviderBaseUrl;

	return {
		async initiate(input) {
			const actorUserId = required(input.actorUserId);
			const subjectUserId = required(input.subjectUserId);
			const rawBody = JSON.stringify({
				service: "clalit",
				action: "home",
				params: {},
				subjectUserId,
			});
			const response = await post({
				provider: options.provider,
				fetchImpl,
				sign,
				validateUrl,
				path: INITIATE_PATH,
				rawBody,
				actorUserId,
			});
			if (response?.status !== 202) return { status: "error" };
			const payload = await boundedJson(response);
			const challenge = challengeFrom(payload);
			return challenge ?? { status: "error" };
		},

		async respond(input) {
			const actorUserId = required(input.actorUserId);
			const challengeId = boundedChallengeId(input.challengeId);
			const code = otp(input.code);
			const rawBody = JSON.stringify({ service: "clalit", challengeId, code });
			const response = await post({
				provider: options.provider,
				fetchImpl,
				sign,
				validateUrl,
				path: RESPOND_PATH,
				rawBody,
				actorUserId,
			});
			if (!response) return { status: "error" };
			if (response.status === 404 || response.status === 410) return { status: "expired" };
			if (response.status === 400 || response.status === 401 || response.status === 403) {
				return { status: "rejected" };
			}
			return response.status === 200 ? { status: "success" } : { status: "error" };
		},
	};
}

export function createConfiguredProviderChallengeSidecar(): ProviderChallengeSidecar {
	const provider = (loadConfig().providers ?? []).find(
		(candidate) => candidate.id === "israel-services" && candidate.services.includes("clalit"),
	);
	if (!provider) throw new Error("Clalit provider sidecar is not configured");
	return createProviderChallengeSidecar({ provider });
}

export function createWhatsAppProviderChallengeResponder(
	sidecar: ProviderChallengeSidecar,
): WhatsAppProviderChallengeResponder {
	return ({ claim, code }) =>
		sidecar.respond({
			actorUserId: claim.actorId,
			challengeId: claim.providerChallengeId,
			code,
		});
}

async function post(input: {
	readonly provider: ExternalProviderConfig;
	readonly fetchImpl: FetchLike;
	readonly sign: Signer;
	readonly validateUrl: ProviderUrlValidator;
	readonly path: string;
	readonly rawBody: string;
	readonly actorUserId: string;
}): Promise<Response | null> {
	try {
		const { url } = await input.validateUrl(input.provider.baseUrl);
		const target = new URL(input.path, url);
		if (target.origin !== url.origin || `${target.pathname}${target.search}` !== input.path)
			return null;
		const auth = await input.sign({
			provider: input.provider,
			method: "POST",
			path: input.path,
			rawBody: input.rawBody,
			actorUserId: input.actorUserId,
		});
		return await input.fetchImpl(target.toString(), {
			method: "POST",
			headers: {
				Accept: "application/json",
				"Content-Type": "application/json",
				"x-relay-proxy": "true",
				"x-actor-user-id": input.actorUserId,
				...auth,
			},
			body: input.rawBody,
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
	} catch {
		return null;
	}
}

async function boundedJson(response: Response): Promise<unknown> {
	const contentLength = Number(response.headers.get("content-length") ?? 0);
	if (contentLength > MAX_RESPONSE_BYTES) return null;
	const text = await response.text();
	if (Buffer.byteLength(text) > MAX_RESPONSE_BYTES) return null;
	try {
		return JSON.parse(text);
	} catch {
		return null;
	}
}

function challengeFrom(value: unknown): {
	readonly status: "challenge";
	readonly challengeId: string;
	readonly challengeType: "sms_otp";
} | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const fields = value as Record<string, unknown>;
	if (fields.status !== "challenge_pending") return null;
	if (
		!fields.challenge ||
		typeof fields.challenge !== "object" ||
		Array.isArray(fields.challenge)
	) {
		return null;
	}
	const challenge = fields.challenge as Record<string, unknown>;
	if (challenge.service !== "clalit") return null;
	if (challenge.type !== "otp_sms" && challenge.type !== "sms_otp") return null;
	if (typeof challenge.id !== "string" || !CHALLENGE_ID_RE.test(challenge.id)) return null;
	return { status: "challenge", challengeId: challenge.id, challengeType: "sms_otp" };
}

function required(value: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error("required provider challenge authority field is missing");
	return trimmed;
}

function boundedChallengeId(value: string): string {
	const trimmed = value.trim();
	if (!CHALLENGE_ID_RE.test(trimmed)) throw new Error("invalid provider challenge id");
	return trimmed;
}

function otp(value: string): string {
	if (!/^[0-9]{4,8}$/.test(value)) throw new Error("invalid provider OTP");
	return value;
}
