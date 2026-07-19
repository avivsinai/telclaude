import { isUuidV4, redactStructuredSecrets } from "../security/structured-redaction.js";
import {
	TELCLAUDE_MCP_AUTHORITY_ENDPOINT_HEADER,
	TELCLAUDE_MCP_AUTHORITY_HEADER,
	TELCLAUDE_MCP_AUTHORITY_NETWORK_NAMESPACE_HEADER,
	TELCLAUDE_MCP_AUTHORITY_PROFILE_HEADER,
	TELCLAUDE_MCP_AUTHORITY_SESSION_KEY_HEADER,
} from "./mcp/authority-registry.js";
import {
	type HermesRuntimeAdapter,
	type HermesRuntimeEvent,
	type HermesRuntimeRequest,
	redactHermesRuntimeText,
} from "./private-runtime.js";

// These top-level Hermes API envelope fields are minted by the server, not by
// tool/model payloads. Nested IDs and approval action/outbound refs remain
// default-redacted because this unknown event schema cannot prove provenance.
const HERMES_API_APPROVAL_EVENT_ID_FIELDS = [
	"approvalRequestId",
	"requestId",
	"request_id",
	"runId",
	"run_id",
] as const;

export type HermesApiFetchInit = {
	method: "GET" | "POST";
	headers: Record<string, string>;
	body?: string;
	signal?: AbortSignal;
};

export type HermesApiResponseReader = {
	read(): Promise<{ done: boolean; value?: Uint8Array | string }>;
	releaseLock?: () => void;
};

export type HermesApiResponse = {
	status: number;
	ok: boolean;
	json(): Promise<unknown>;
	text(): Promise<string>;
	body?: { getReader(): HermesApiResponseReader } | null;
};

export type HermesApiFetch = (url: string, init: HermesApiFetchInit) => Promise<HermesApiResponse>;

export type HermesApiRuntimeAdapterOptions = {
	baseUrl: string;
	apiKey: string;
	fetch?: HermesApiFetch;
};

type HermesRunStartResponse = {
	run_id?: unknown;
	status?: unknown;
};

type HermesRunSseEvent = Record<string, unknown> & {
	event?: string;
};

export class HermesApiRuntimeAdapter implements HermesRuntimeAdapter {
	private readonly baseUrl: string;
	private readonly apiKey: string;
	private readonly fetcher: HermesApiFetch;

	constructor(options: HermesApiRuntimeAdapterOptions) {
		this.baseUrl = normalizeBaseUrl(options.baseUrl);
		this.apiKey = requireApiKey(options.apiKey);
		this.fetcher = options.fetch ?? defaultFetch;
	}

	async *run(request: HermesRuntimeRequest): AsyncIterable<HermesRuntimeEvent> {
		const hermesSessionId = request.resumeHermesSessionId ?? request.telclaudeSessionId;
		let runId: string;
		try {
			runId = await this.startRun(request, hermesSessionId);
		} catch (error) {
			yield failedDone(errorMessage(error));
			return;
		}

		yield { type: "session", hermesSessionId };

		let response = "";
		let sawTerminalEvent = false;
		try {
			for await (const event of this.streamRunEvents(runId, request.signal)) {
				const mapped = mapRunEvent(event);
				if (!mapped) continue;
				if (mapped.type === "text_delta") {
					response += mapped.text;
					yield mapped;
					continue;
				}
				if (mapped.type === "done") {
					sawTerminalEvent = true;
					yield {
						...mapped,
						response: mapped.response ?? response,
					};
					continue;
				}
				yield mapped;
			}
		} catch (error) {
			if (request.signal.aborted) {
				await this.stopRunBestEffort(runId);
			}
			yield failedDone(errorMessage(error), response);
			return;
		}

		if (!sawTerminalEvent) {
			yield failedDone("Hermes API event stream ended without a terminal run event", response);
		}
	}

	private async startRun(request: HermesRuntimeRequest, hermesSessionId: string): Promise<string> {
		const response = await this.fetcher(this.url("/v1/runs"), {
			method: "POST",
			headers: this.headers(request),
			body: JSON.stringify({
				input: request.prompt,
				session_id: hermesSessionId,
				...(request.model ? { model: request.model } : {}),
				...buildInstructionsField(request),
			}),
			signal: request.signal,
		});

		if (response.status !== 202 || !response.ok) {
			throw new Error(
				`Hermes API POST /v1/runs failed with HTTP ${response.status}: ${await redactedResponseText(response)}`,
			);
		}

		const body = (await response.json()) as HermesRunStartResponse;
		if (typeof body.run_id !== "string" || body.run_id.trim() === "") {
			throw new Error("Hermes API POST /v1/runs did not return a run_id");
		}
		return body.run_id;
	}

	private async *streamRunEvents(
		runId: string,
		signal: AbortSignal,
	): AsyncIterable<HermesRunSseEvent> {
		const response = await this.fetcher(this.url(`/v1/runs/${encodeURIComponent(runId)}/events`), {
			method: "GET",
			headers: this.headers(),
			signal,
		});
		if (!response.ok) {
			throw new Error(
				`Hermes API GET /v1/runs/${runId}/events failed with HTTP ${response.status}: ${await redactedResponseText(response)}`,
			);
		}
		yield* readSseEvents(response);
	}

	private async stopRunBestEffort(runId: string): Promise<void> {
		try {
			await this.fetcher(this.url(`/v1/runs/${encodeURIComponent(runId)}/stop`), {
				method: "POST",
				headers: this.headers(),
				body: "{}",
			});
		} catch {
			// Best effort only. The caller already receives the abort/failure.
		}
	}

	private headers(request?: HermesRuntimeRequest): Record<string, string> {
		return {
			Authorization: `Bearer ${this.apiKey}`,
			"Content-Type": "application/json",
			...(request ? { "X-Hermes-Session-Key": safeSessionKey(request.sessionKey) } : {}),
			...(request?.mcpAuthority
				? {
						[TELCLAUDE_MCP_AUTHORITY_HEADER]: safeHeaderValue(request.mcpAuthority.handle),
						[TELCLAUDE_MCP_AUTHORITY_SESSION_KEY_HEADER]: safeHeaderValue(
							request.mcpAuthority.connection.sessionKey,
						),
						[TELCLAUDE_MCP_AUTHORITY_PROFILE_HEADER]: safeHeaderValue(
							request.mcpAuthority.connection.profileId,
						),
						[TELCLAUDE_MCP_AUTHORITY_ENDPOINT_HEADER]: safeHeaderValue(
							request.mcpAuthority.connection.endpointId,
						),
						[TELCLAUDE_MCP_AUTHORITY_NETWORK_NAMESPACE_HEADER]: safeHeaderValue(
							request.mcpAuthority.connection.networkNamespace,
						),
					}
				: {}),
		};
	}

	private url(path: string): string {
		return `${this.baseUrl}${path}`;
	}
}

function buildInstructionsField(request: HermesRuntimeRequest): { instructions?: string } {
	const sections: string[] = [];
	if (request.systemPromptAppend?.trim()) {
		sections.push(request.systemPromptAppend.trim());
	}
	sections.push(
		[
			"# Telclaude wrapper context",
			JSON.stringify(
				{
					tier: request.tier,
					profileId: request.profileId,
					identity: request.identity,
					allowedSkills: request.allowedSkills ?? [],
					isNewSession: request.isNewSession,
				},
				null,
				2,
			),
		].join("\n"),
	);
	if (request.memory?.compiledMemoryMd?.trim()) {
		sections.push(["# Telclaude scoped memory", request.memory.compiledMemoryMd.trim()].join("\n"));
	}
	const instructions = redactHermesRuntimeText(sections.join("\n\n")).trim();
	return instructions ? { instructions } : {};
}

async function* readSseEvents(response: HermesApiResponse): AsyncIterable<HermesRunSseEvent> {
	const reader = response.body?.getReader();
	if (!reader) {
		yield* parseSseText(await response.text());
		return;
	}

	const decoder = new TextDecoder();
	let buffer = "";
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			buffer += typeof value === "string" ? value : decoder.decode(value, { stream: true });
			const frames = buffer.split(/\r?\n\r?\n/);
			buffer = frames.pop() ?? "";
			for (const frame of frames) {
				const event = parseSseFrame(frame);
				if (event) yield event;
			}
		}
		buffer += decoder.decode();
		if (buffer.trim()) {
			const event = parseSseFrame(buffer);
			if (event) yield event;
		}
	} finally {
		reader.releaseLock?.();
	}
}

function* parseSseText(text: string): Iterable<HermesRunSseEvent> {
	for (const frame of text.split(/\r?\n\r?\n/)) {
		const event = parseSseFrame(frame);
		if (event) yield event;
	}
}

function parseSseFrame(frame: string): HermesRunSseEvent | null {
	const data = frame
		.split(/\r?\n/)
		.filter((line) => line.startsWith("data:"))
		.map((line) => line.slice("data:".length).trimStart())
		.join("\n")
		.trim();
	if (!data) return null;
	try {
		const parsed = JSON.parse(data);
		return isRecord(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

function mapRunEvent(event: HermesRunSseEvent): HermesRuntimeEvent | null {
	switch (event.event) {
		case "message.delta":
			return typeof event.delta === "string"
				? { type: "text_delta", text: redactHermesRuntimeText(event.delta) }
				: null;
		case "tool.started":
			return typeof event.tool === "string"
				? {
						type: "tool_use",
						toolName: event.tool,
						input: { preview: redactStructuredSecrets(event.preview ?? null) },
					}
				: null;
		case "tool.completed":
			return typeof event.tool === "string"
				? {
						type: "tool_result",
						toolName: event.tool,
						output: {
							...(typeof event.duration === "number" ? { duration: event.duration } : {}),
							...(typeof event.error === "boolean" ? { error: event.error } : {}),
						},
					}
				: null;
		case "approval.request":
			return {
				type: "tool_use",
				toolName: "hermes_approval_request",
				input: redactApprovalEvent(event),
			};
		case "approval.responded":
			return {
				type: "tool_result",
				toolName: "hermes_approval_request",
				output: redactApprovalEvent(event),
			};
		case "run.completed":
			return {
				type: "done",
				response:
					typeof event.output === "string" ? redactHermesRuntimeText(event.output) : undefined,
				success: true,
				numTurns: 1,
			};
		case "run.failed":
			return {
				type: "done",
				success: false,
				error:
					typeof event.error === "string"
						? redactHermesRuntimeText(event.error)
						: "Hermes API run failed",
			};
		case "run.cancelled":
			return {
				type: "done",
				success: false,
				error: "Hermes API run cancelled",
			};
		default:
			return null;
	}
}

function redactApprovalEvent(value: unknown): unknown {
	const redacted = redactStructuredSecrets(value);
	if (!isRecord(value) || !isRecord(redacted)) return redacted;
	const result = { ...redacted };
	for (const field of HERMES_API_APPROVAL_EVENT_ID_FIELDS) {
		const candidate = value[field];
		if (typeof candidate === "string" && isUuidV4(candidate)) result[field] = candidate;
	}
	return result;
}

async function redactedResponseText(response: HermesApiResponse): Promise<string> {
	try {
		return redactHermesRuntimeText((await response.text()).trim());
	} catch {
		return "";
	}
}

function normalizeBaseUrl(raw: string): string {
	const value = raw.trim();
	if (!value) throw new Error("Hermes API base URL is required");
	const url = new URL(value);
	if (!["http:", "https:"].includes(url.protocol)) {
		throw new Error("Hermes API base URL must use http or https");
	}
	if (url.username || url.password || url.search || url.hash) {
		throw new Error("Hermes API base URL must not contain credentials, query, or fragment");
	}
	return url.toString().replace(/\/$/, "");
}

function requireApiKey(raw: string): string {
	const value = raw.trim();
	if (!value) throw new Error("Hermes API key is required");
	if (containsHeaderUnsafeChar(value))
		throw new Error("Hermes API key contains invalid characters");
	return value;
}

function safeSessionKey(value: string): string {
	if (containsHeaderUnsafeChar(value) || value.length > 256) {
		throw new Error("Hermes API session key is invalid");
	}
	return value;
}

function safeHeaderValue(value: string): string {
	if (containsHeaderUnsafeChar(value) || value.length > 512) {
		throw new Error("Hermes API header value is invalid");
	}
	return value;
}

function containsHeaderUnsafeChar(value: string): boolean {
	for (const char of value) {
		const code = char.charCodeAt(0);
		if (code === 0 || code === 10 || code === 13) return true;
	}
	return false;
}

function failedDone(error: string, response = ""): HermesRuntimeEvent {
	return {
		type: "done",
		response: redactHermesRuntimeText(response),
		success: false,
		error: redactHermesRuntimeText(error),
	};
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const defaultFetch: HermesApiFetch = async (url, init) => {
	const fetcher = globalThis.fetch as unknown as HermesApiFetch | undefined;
	if (!fetcher) throw new Error("global fetch is unavailable");
	return fetcher(url, init);
};
