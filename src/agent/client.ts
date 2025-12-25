import { getChildLogger } from "../logging.js";
import type { PooledQueryOptions, StreamChunk } from "../sdk/client.js";

const logger = getChildLogger({ module: "agent-client" });

type RemoteQueryOptions = PooledQueryOptions & {
	agentUrl?: string;
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
		const response = await fetch(`${agentUrl.replace(/\/+$/, "")}/v1/query`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				prompt,
				tier: options.tier,
				poolKey: options.poolKey,
				enableSkills: options.enableSkills,
				timeoutMs: options.timeoutMs,
				resumeSessionId: options.resumeSessionId,
				betas: options.betas,
			}),
			signal: controller.signal,
		});

		if (!response.ok || !response.body) {
			const message = await response.text();
			throw new Error(`Agent query failed (${response.status} ${response.statusText}): ${message}`);
		}

		const reader = response.body.getReader();
		const decoder = new TextDecoder();
		let buffer = "";

		while (true) {
			const { value, done } = await reader.read();
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
