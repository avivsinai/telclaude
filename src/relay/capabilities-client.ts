import { buildInternalAuthHeaders } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "relay-capabilities-client" });

function getCapabilitiesUrl(): string {
	const url = process.env.TELCLAUDE_CAPABILITIES_URL;
	if (!url) {
		throw new Error("TELCLAUDE_CAPABILITIES_URL is not configured");
	}
	return url.replace(/\/+$/, "");
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
	const baseUrl = getCapabilitiesUrl();
	const payload = JSON.stringify(body);
	const response = await fetch(`${baseUrl}${path}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...buildInternalAuthHeaders("POST", path, payload),
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
}): Promise<{ status: string; data?: unknown; error?: string }> {
	return postJson("/v1/provider/proxy", input);
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

export async function relayDeliverLocalFile(input: {
	sourcePath: string;
	filename?: string;
	userId?: string;
}): Promise<{ status: string; path: string; filename: string; size: number; error?: string }> {
	return postJson("/v1/local-file/deliver", input);
}
