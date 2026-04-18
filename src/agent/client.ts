import { isTransientNetworkError } from "../infra/network-errors.js";
import { retryAsync } from "../infra/retry.js";
import { withTimeout } from "../infra/timeout.js";
import { buildInternalAuthHeaders, type InternalAuthScope } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { issueToken, isTokenManagerActive } from "../relay/token-manager.js";
import { isDockerEnvironment } from "../sandbox/mode.js";
import type { ExposedCredentials, PooledQueryOptions, StreamChunk } from "../sdk/client.js";
import { getGitCredentials } from "../services/git-credentials.js";
import { getOpenAIKey } from "../services/openai-client.js";
import { stripTrailingSlash } from "../utils.js";

const logger = getChildLogger({ module: "agent-client" });

/** Per-chunk read timeout — if no data arrives, the stream is likely hung.
 * The agent server sends keepalive newlines every 15s during tool execution,
 * so 30s (2x keepalive) is sufficient to detect a genuinely dead stream. */
const STREAM_READ_TIMEOUT_MS = Number(process.env.TELCLAUDE_AGENT_STREAM_READ_TIMEOUT_MS ?? 30_000);

type RemoteQueryOptions = PooledQueryOptions & {
	agentUrl?: string;
	scope?: InternalAuthScope;
};

export async function* executeRemoteQuery(
	prompt: string,
	options: RemoteQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const agentUrl = options.agentUrl ?? process.env.TELCLAUDE_AGENT_URL;
	if (!agentUrl) {
		throw new Error("TELCLAUDE_AGENT_URL is not configured");
	}

	const controller = new AbortController();
	const externalAbort = options.abortController;

	if (externalAbort) {
		if (externalAbort.signal.aborted) {
			controller.abort();
		} else {
			externalAbort.signal.addEventListener("abort", () => controller.abort(), { once: true });
		}
	}

	let timeoutId: ReturnType<typeof setTimeout> | undefined;
	if (options.timeoutMs && options.timeoutMs > 0) {
		timeoutId = setTimeout(() => controller.abort(), options.timeoutMs);
	}

	try {
		const path = "/v1/query";
		// Mint a session token for the agent subprocess (if vault is active in this process).
		// The agent server passes this to the Claude subprocess env so it can call
		// relay capabilities (TTS, image gen, transcription, memory) without the private key.
		let sessionToken: string | undefined;
		if (isTokenManagerActive()) {
			try {
				const issued = await issueToken(options.scope ?? "telegram");
				if (issued) {
					sessionToken = issued.token;
				}
			} catch {
				// Best-effort; agent falls back to static auth if available
			}
		}
		// Native/dev escape hatch: gated behind TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS=1.
		// Violates the "agents never see raw credentials" invariant (architecture.md), so default
		// is OFF. Docker keeps raw credentials inside the relay and routes via the git proxy /
		// HTTP credential proxy; native mode should do the same unless the operator explicitly
		// opts in here.
		// Scope gate still applies: credentials never enter a social agent container — the agent
		// server downgrades non-telegram scopes to SOCIAL tier, but that happens AFTER this
		// payload is serialized, so we enforce telegram-only here too.
		const effectiveScope = options.scope ?? "telegram";
		const insecureExposeOptIn = process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS === "1";
		let exposedCredentials: ExposedCredentials | undefined;
		if (
			insecureExposeOptIn &&
			!isDockerEnvironment() &&
			options.tier === "FULL_ACCESS" &&
			effectiveScope === "telegram"
		) {
			logger.warn(
				{
					tier: options.tier,
					scope: effectiveScope,
				},
				"INSECURE: exposing native credentials to agent subprocess (TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS=1). This violates the 'agents never see raw credentials' invariant.",
			);
			const creds: ExposedCredentials = {};
			try {
				const gitCreds = await getGitCredentials();
				if (gitCreds?.token) {
					creds.githubToken = gitCreds.token;
				}
			} catch {
				// Best-effort; agent falls back to env vars
			}
			try {
				const openaiKey = await getOpenAIKey();
				// Don't inject the credential-proxy sentinel — only real keys
				if (openaiKey && openaiKey !== "credential-proxy") {
					creds.openaiApiKey = openaiKey;
				}
			} catch {
				// Best-effort; agent uses credential proxy for OpenAI
			}
			if (creds.githubToken || creds.openaiApiKey) {
				exposedCredentials = creds;
			}
		}

		const payload = JSON.stringify({
			prompt,
			cwd: options.cwd,
			tier: options.tier,
			poolKey: options.poolKey,
			enableSkills: options.enableSkills,
			allowedSkills: options.allowedSkills,
			timeoutMs: options.timeoutMs,
			resumeSessionId: options.resumeSessionId,
			betas: options.betas,
			userId: options.userId,
			systemPromptAppend: options.systemPromptAppend,
			sessionToken,
			outputFormat: options.outputFormat,
			exposedCredentials,
			compiledMemoryMd: options.compiledMemoryMd,
		});
		const endpoint = `${stripTrailingSlash(agentUrl)}${path}`;
		const scope = options.scope ?? "telegram";

		// Retry the initial fetch on transient network errors (2 attempts, 1s base delay)
		const response = await retryAsync(
			() =>
				fetch(endpoint, {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
						...buildInternalAuthHeaders("POST", path, payload, { scope }),
					},
					body: payload,
					signal: controller.signal,
				}),
			{
				maxAttempts: 2,
				baseDelayMs: 1000,
				shouldRetry: (err) => isTransientNetworkError(err),
				onRetry: (err, info) =>
					logger.warn({ error: String(err), attempt: info.attempt }, "retrying agent fetch"),
				label: "agent-fetch",
			},
		);

		if (!response.ok || !response.body) {
			const message = await response.text();
			throw new Error(`Agent query failed (${response.status} ${response.statusText}): ${message}`);
		}

		const reader = response.body.getReader();
		const decoder = new TextDecoder();
		let buffer = "";

		try {
			while (true) {
				// Per-chunk read timeout: detect dead streams (keepalive resets this)
				const { value, done } = await withTimeout(
					reader.read(),
					STREAM_READ_TIMEOUT_MS,
					"stream-read",
				);
				if (done) {
					break;
				}
				buffer += decoder.decode(value, { stream: true });

				let newlineIndex = buffer.indexOf("\n");
				while (newlineIndex >= 0) {
					const line = buffer.slice(0, newlineIndex).trim();
					buffer = buffer.slice(newlineIndex + 1);
					if (line.length > 0) {
						try {
							const chunk = JSON.parse(line) as StreamChunk;
							yield chunk;
						} catch (err) {
							logger.warn({ error: String(err), line }, "failed to parse agent chunk");
						}
					}
					newlineIndex = buffer.indexOf("\n");
				}
			}
		} catch (err) {
			// On timeout or abort, clean up the stream reader
			try {
				reader.cancel().catch(() => {});
			} catch {
				// best-effort cleanup
			}
			controller.abort();
			throw err;
		}

		// Process any remaining content in buffer after stream ends
		const remaining = buffer.trim();
		if (remaining.length > 0) {
			try {
				const chunk = JSON.parse(remaining) as StreamChunk;
				yield chunk;
			} catch (err) {
				logger.warn({ error: String(err), remaining }, "failed to parse trailing agent chunk");
			}
		}
	} finally {
		if (timeoutId) {
			clearTimeout(timeoutId);
		}
	}
}
