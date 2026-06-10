import { z } from "zod";
import { type InternalResponseProof, verifyInternalResponseProof } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { buildRpcAuthHeaders } from "./rpc-auth-client.js";

const logger = getChildLogger({ module: "relay-capabilities-client" });

function getCapabilitiesUrl(): string {
	const url = process.env.TELCLAUDE_CAPABILITIES_URL;
	if (!url) {
		throw new Error("TELCLAUDE_CAPABILITIES_URL is not configured");
	}
	return url.replace(/\/+$/, "");
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
	return postJsonWithScope(path, body, "telegram");
}

async function postJsonWithScope<T>(
	path: string,
	body: unknown,
	scope: "telegram" | "operator",
): Promise<T> {
	const baseUrl = getCapabilitiesUrl();
	const payload = JSON.stringify(body);
	const response = await fetch(`${baseUrl}${path}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...buildRpcAuthHeaders("POST", path, payload, scope),
		},
		body: payload,
	});

	if (!response.ok) {
		const text = await response.text();
		let detail = text;
		try {
			const parsed = JSON.parse(text) as { error?: string };
			if (parsed?.error) {
				detail = parsed.error;
			}
		} catch {
			// ignore JSON parse failures
		}
		logger.warn({ path, status: response.status, body: text }, "capability request failed");
		const suffix = detail ? ` - ${detail}` : "";
		throw new Error(
			`Capability request failed: ${response.status} ${response.statusText}${suffix}`,
		);
	}

	return (await response.json()) as T;
}

type RelayProvidersResponse = {
	ok: boolean;
	providers: Array<{
		id: string;
		baseUrl: string;
		services: string[];
		description?: string;
	}>;
	schemaMarkdown?: string;
	providersEpoch: string;
};

type HermesPrivateRuntimeRelayProof = {
	request: {
		method: string;
		path: string;
		body: string;
	};
	responseBody: string;
	proof: InternalResponseProof;
};

type HermesPrivateRuntimeState = {
	ok: true;
	effectiveMode: "hermes";
	effectiveValue: "1";
	controlMode: "hermes";
	controlSource: "hermes-only";
	relayProof: HermesPrivateRuntimeRelayProof;
};

const InternalResponseProofSchema = z
	.object({
		version: z.literal("v1"),
		scope: z.string().min(1),
		timestamp: z.string().min(1),
		nonce: z.string().min(1),
		method: z.string().min(1),
		path: z.string().min(1),
		requestBodySha256: z.string().regex(/^[a-f0-9]{64}$/),
		responseBodySha256: z.string().regex(/^[a-f0-9]{64}$/),
		signature: z.string().min(1),
	})
	.strict();

const HermesPrivateRuntimeStateSchema = z
	.object({
		ok: z.literal(true),
		effectiveMode: z.literal("hermes"),
		effectiveValue: z.literal("1"),
		controlMode: z.literal("hermes"),
		controlSource: z.literal("hermes-only"),
		relayProof: InternalResponseProofSchema,
	})
	.strict();

function parseHermesPrivateRuntimeState(
	payload: unknown,
	request: { method: string; path: string; body: string },
): HermesPrivateRuntimeState {
	const parsed = HermesPrivateRuntimeStateSchema.parse(payload);
	const { relayProof, ...unsigned } = parsed;
	const unsignedBody = JSON.stringify(unsigned);
	if (
		!verifyInternalResponseProof(
			relayProof as InternalResponseProof,
			request.method,
			request.path,
			request.body,
			unsignedBody,
			{ scope: "operator" },
		)
	) {
		throw new Error("Capability response failed relay proof verification");
	}
	return {
		...unsigned,
		relayProof: {
			request,
			responseBody: unsignedBody,
			proof: relayProof as InternalResponseProof,
		},
	};
}

export async function relayGetProviders(): Promise<RelayProvidersResponse> {
	return postJson("/v1/config.providers", {});
}

export async function relayRefreshProviders(): Promise<RelayProvidersResponse> {
	return postJsonWithScope("/v1/config.providers.refresh", {}, "operator");
}

export async function relayUpsertProvider(input: {
	provider: {
		id: string;
		baseUrl: string;
		services: string[];
		description?: string;
		endpointLabel?: string;
		endpointDescription?: string;
	};
}): Promise<
	RelayProvidersResponse & {
		doctorResults: Array<{
			providerId: string;
			baseUrl: string;
			checks: Array<{ name: string; status: "pass" | "warn" | "fail"; detail: string }>;
		}>;
	}
> {
	return postJsonWithScope("/v1/config.providers.upsert", input, "operator");
}

export async function relayRemoveProvider(input: { providerId: string }): Promise<
	RelayProvidersResponse & {
		removedProvider: boolean;
		removedPrivateEndpoint: boolean;
	}
> {
	return postJsonWithScope("/v1/config.providers.remove", input, "operator");
}

export async function relayGetHermesPrivateRuntimeState(): Promise<HermesPrivateRuntimeState> {
	const path = "/v1/hermes.private-runtime.status";
	const body = "{}";
	const payload = await postJsonWithScope<unknown>(path, {}, "operator");
	return parseHermesPrivateRuntimeState(payload, { method: "POST", path, body });
}

export async function relayGenerateImage(input: {
	prompt: string;
	size?: "auto" | "1024x1024" | "1536x1024" | "1024x1536";
	quality?: "low" | "medium" | "high";
	userId?: string;
}): Promise<{ path: string; bytes: number; model: string; quality: string }> {
	return postJson("/v1/image.generate", input);
}

export async function relayTextToSpeech(input: {
	text: string;
	voice?: "alloy" | "echo" | "fable" | "onyx" | "nova" | "shimmer";
	speed?: number;
	voiceMessage?: boolean;
	userId?: string;
}): Promise<{ path: string; bytes: number; format: string; voice: string; speed: number }> {
	return postJson("/v1/tts.speak", input);
}

export async function relayTranscribe(input: {
	path: string;
	language?: string;
	model?: string;
	userId?: string;
}): Promise<{ text: string; language?: string; durationSeconds?: number }> {
	return postJson("/v1/transcribe", input);
}

export async function relayFetchAttachment(input: {
	providerId: string;
	attachmentId: string;
	filename?: string;
	mimeType?: string;
	size?: number;
	inlineBase64?: string;
	userId?: string;
}): Promise<{ status: string; path: string; error?: string }> {
	return postJson("/v1/attachment/fetch", input);
}

export async function relayProviderProxy(input: {
	providerId: string;
	path: string;
	method?: string;
	body?: string;
	userId?: string;
	approvalToken?: string;
}): Promise<{
	status: string;
	data?: unknown;
	error?: string;
	errorCode?: string;
	approvalNonce?: string;
}> {
	// Provider proxy errors carry structured metadata (errorCode, approvalNonce)
	// that must survive to the caller, so we handle errors inline instead of
	// letting postJson throw.
	const baseUrl = getCapabilitiesUrl();
	const payload = JSON.stringify(input);
	const response = await fetch(`${baseUrl}/v1/provider/proxy`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...buildRpcAuthHeaders("POST", "/v1/provider/proxy", payload, "telegram"),
		},
		body: payload,
	});

	const data = (await response.json()) as {
		status: string;
		data?: unknown;
		error?: string;
		errorCode?: string;
		approvalNonce?: string;
	};

	if (!response.ok) {
		logger.warn(
			{ path: "/v1/provider/proxy", status: response.status, errorCode: data.errorCode },
			"provider proxy request failed",
		);
	}

	return data;
}

export async function relayValidateAttachment(input: { ref: string; userId?: string }): Promise<{
	status: string;
	attachment?: {
		ref: string;
		filepath: string;
		filename: string;
		mimeType: string | null;
		size: number | null;
	};
	error?: string;
}> {
	return postJson("/v1/attachment/validate", input);
}

export async function relaySummarize(input: {
	url: string;
	maxCharacters?: number;
	timeoutMs?: number;
	format?: "text" | "markdown";
	userId?: string;
}): Promise<{
	url: string;
	title: string | null;
	siteName: string | null;
	content: string;
	wordCount: number;
	truncated: boolean;
	transcriptSource: string | null;
}> {
	return postJson("/v1/summarize", input);
}

export async function relayDeliverLocalFile(input: {
	sourcePath: string;
	filename?: string;
	userId?: string;
}): Promise<{ status: string; path: string; filename: string; size: number; error?: string }> {
	return postJson("/v1/local-file/deliver", input);
}
