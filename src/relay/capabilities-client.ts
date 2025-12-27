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
		logger.warn({ path, status: response.status, body: text }, "capability request failed");
		throw new Error(`Capability request failed: ${response.status} ${response.statusText}`);
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

/**
 * Get git credentials from the relay.
 * Used by agent container to get credentials from relay (which has secrets).
 */
export async function relayGitCredentials(): Promise<{
	username: string;
	email: string;
	token: string;
} | null> {
	try {
		return await postJson("/v1/git.credentials", {});
	} catch (err) {
		logger.debug({ error: String(err) }, "failed to get git credentials from relay");
		return null;
	}
}
