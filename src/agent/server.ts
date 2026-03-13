import fs from "node:fs";
import http from "node:http";
import path from "node:path";

import type { OutputFormat, SdkBeta } from "@anthropic-ai/claude-agent-sdk";
import type { PermissionTier } from "../config/config.js";
import { verifyInternalAuth } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { getCachedProviderSummary } from "../providers/provider-skill.js";
import { getSandboxMode } from "../sandbox/index.js";
import type { ExposedCredentials } from "../sdk/client.js";
import { executePooledQuery, type StreamChunk } from "../sdk/client.js";
import { loadSocialContractPrompt } from "../social-contract.js";
import { loadSoul } from "../soul.js";
import { buildRuntimeSnapshot } from "../system-metadata.js";

const logger = getChildLogger({ module: "agent-server" });

const MAX_BODY_BYTES = Number(process.env.TELCLAUDE_AGENT_MAX_BODY_BYTES ?? 262144);
const MAX_PROMPT_CHARS = Number(process.env.TELCLAUDE_AGENT_MAX_PROMPT_CHARS ?? 100_000);
const MAX_TIMEOUT_MS = Number(process.env.TELCLAUDE_AGENT_MAX_TIMEOUT_MS ?? 600_000);
const DEFAULT_TIMEOUT_MS = Number(process.env.TELCLAUDE_AGENT_DEFAULT_TIMEOUT_MS ?? 600_000);
const AGENT_WORKDIR = process.env.TELCLAUDE_AGENT_WORKDIR ?? process.cwd();
const RESOLVED_AGENT_WORKDIR = path.resolve(AGENT_WORKDIR);
export const AGENT_STARTED_AT = Date.now();

type QueryRequest = {
	prompt: string;
	tier: PermissionTier;
	poolKey: string;
	cwd?: string;
	enableSkills?: boolean;
	/** When set, only these skills can be invoked. Requires enableSkills: true. */
	allowedSkills?: string[];
	timeoutMs?: number;
	resumeSessionId?: string;
	betas?: SdkBeta[];
	userId?: string;
	systemPromptAppend?: string;
	/** Pre-minted session token from relay for agent subprocess relay capabilities. */
	sessionToken?: string;
	/** Structured output format (JSON Schema). Agent returns validated data instead of free-form text. */
	outputFormat?: OutputFormat;
	/** Relay-resolved credentials for tier-based key exposure (Docker mode). */
	exposedCredentials?: ExposedCredentials;
};

type AgentServerOptions = {
	port?: number;
	host?: string;
};

function isPermissionTier(value: unknown): value is PermissionTier {
	return (
		value === "READ_ONLY" ||
		value === "WRITE_LOCAL" ||
		value === "FULL_ACCESS" ||
		value === "SOCIAL"
	);
}

function writeJson(res: http.ServerResponse, status: number, payload: unknown): void {
	const body = JSON.stringify(payload);
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(body),
	});
	res.end(body);
}

function clampTimeout(value: number): number {
	if (Number.isNaN(value) || value <= 0) return DEFAULT_TIMEOUT_MS;
	return Math.min(Math.max(value, 1000), MAX_TIMEOUT_MS);
}

function resolveCwd(requested?: string): string {
	if (!requested) return RESOLVED_AGENT_WORKDIR;
	const trimmed = requested.trim();
	if (!trimmed) return RESOLVED_AGENT_WORKDIR;

	const candidateRaw = path.isAbsolute(trimmed)
		? trimmed
		: path.join(RESOLVED_AGENT_WORKDIR, trimmed);
	let candidate = path.resolve(candidateRaw);

	if (fs.existsSync(candidate)) {
		try {
			const real = fs.realpathSync(candidate);
			const stat = fs.statSync(real);
			if (!stat.isDirectory()) {
				return RESOLVED_AGENT_WORKDIR;
			}
			candidate = real;
		} catch {
			return RESOLVED_AGENT_WORKDIR;
		}
	}

	const rootWithSep = RESOLVED_AGENT_WORKDIR.endsWith(path.sep)
		? RESOLVED_AGENT_WORKDIR
		: `${RESOLVED_AGENT_WORKDIR}${path.sep}`;
	if (candidate !== RESOLVED_AGENT_WORKDIR && !candidate.startsWith(rootWithSep)) {
		return RESOLVED_AGENT_WORKDIR;
	}

	return candidate;
}

/** Keepalive interval — write empty newlines so the relay knows we're alive. */
const KEEPALIVE_INTERVAL_MS = 15_000;

/** First-chunk watchdog: abort if the SDK produces no real output within this window.
 *  Generous default (90s) to accommodate slow startup on loaded hosts.
 *  The watchdog fires once — after the first real chunk, the overall session timeout governs. */
const FIRST_CHUNK_TIMEOUT_MS = (() => {
	const raw = Number(process.env.TELCLAUDE_AGENT_FIRST_CHUNK_TIMEOUT_MS ?? 90_000);
	return Number.isNaN(raw) || raw < 0 ? 90_000 : raw;
})();

async function streamQuery(
	req: QueryRequest,
	res: http.ServerResponse,
	abortController: AbortController,
): Promise<void> {
	res.writeHead(200, {
		"Content-Type": "application/x-ndjson; charset=utf-8",
		"Cache-Control": "no-cache",
		Connection: "keep-alive",
		"X-Content-Type-Options": "nosniff",
	});

	// Send periodic keepalive newlines so the relay's per-chunk read timeout
	// doesn't fire during long tool executions (Bash, memory read, etc.).
	// The client already ignores empty lines after trim.
	const keepalive = setInterval(() => {
		if (!res.closed && !abortController.signal.aborted) {
			res.write("\n");
		}
	}, KEEPALIVE_INTERVAL_MS);

	// First-chunk watchdog: detect hung SDK sessions where keepalives mask
	// a dead API connection (e.g. repeated ERR_STREAM_PREMATURE_CLOSE).
	// Clears on first real chunk; only the overall timeout applies after that.
	let firstChunkReceived = false;
	const firstChunkWatchdog =
		FIRST_CHUNK_TIMEOUT_MS > 0
			? setTimeout(() => {
					if (!firstChunkReceived && !abortController.signal.aborted) {
						logger.warn(
							{ timeoutMs: FIRST_CHUNK_TIMEOUT_MS },
							"first-chunk watchdog fired: no SDK output, aborting session",
						);
						abortController.abort();
					}
				}, FIRST_CHUNK_TIMEOUT_MS)
			: null;

	try {
		for await (const chunk of executePooledQuery(req.prompt, {
			cwd: req.cwd ?? RESOLVED_AGENT_WORKDIR,
			tier: req.tier,
			poolKey: req.poolKey,
			userId: req.userId,
			resumeSessionId: req.resumeSessionId,
			enableSkills: req.enableSkills ?? req.tier !== "READ_ONLY",
			allowedSkills: req.allowedSkills,
			sessionToken: req.sessionToken,
			timeoutMs: req.timeoutMs,
			abortController,
			betas: req.betas,
			systemPromptAppend: req.systemPromptAppend,
			outputFormat: req.outputFormat,
			exposedCredentials: req.exposedCredentials,
		})) {
			if (!firstChunkReceived) {
				firstChunkReceived = true;
				if (firstChunkWatchdog) clearTimeout(firstChunkWatchdog);
			}
			// Always write the chunk before checking abort — the SDK emits a
			// done chunk with success:false on abort, and the relay needs it
			// to clean up the Telegram "Thinking..." message.
			res.write(`${JSON.stringify(chunk)}\n`);
			if (abortController.signal.aborted) {
				break;
			}
		}
	} finally {
		if (firstChunkWatchdog) clearTimeout(firstChunkWatchdog);
		clearInterval(keepalive);
	}

	res.end();
}

export function startAgentServer(options: AgentServerOptions = {}): http.Server {
	const port = options.port ?? Number(process.env.TELCLAUDE_AGENT_PORT ?? 8788);
	const host = options.host ?? (getSandboxMode() === "docker" ? "0.0.0.0" : "127.0.0.1");

	const server = http.createServer((req, res) => {
		if (!req.url) {
			writeJson(res, 400, { error: "Missing request URL." });
			return;
		}

		if (req.method === "GET" && req.url === "/health") {
			writeJson(res, 200, {
				ok: true,
				service: "agent",
				runtime: buildRuntimeSnapshot(AGENT_STARTED_AT),
			});
			return;
		}

		if (req.method !== "POST" || req.url !== "/v1/query") {
			writeJson(res, 404, { error: "Not found." });
			return;
		}

		const contentType = req.headers["content-type"] ?? "";
		if (!contentType.includes("application/json")) {
			writeJson(res, 415, { error: "Content-Type must be application/json." });
			return;
		}

		let received = 0;
		const chunks: Buffer[] = [];

		req.on("data", (chunk: Buffer) => {
			received += chunk.length;
			if (received > MAX_BODY_BYTES) {
				writeJson(res, 413, { error: "Request body too large." });
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});

		req.on("end", () => {
			try {
				const body = Buffer.concat(chunks).toString("utf-8");
				const authResult = verifyInternalAuth(req, body);
				if (!authResult.ok) {
					logger.warn(
						{ reason: authResult.reason, url: req.url },
						"agent request failed internal auth",
					);
					writeJson(res, authResult.status, { error: authResult.error });
					return;
				}
				const parsed = JSON.parse(body) as QueryRequest;

				if (!parsed.prompt || typeof parsed.prompt !== "string") {
					writeJson(res, 400, { error: "Missing prompt." });
					return;
				}
				if (parsed.prompt.length > MAX_PROMPT_CHARS) {
					writeJson(res, 413, { error: "Prompt too large." });
					return;
				}
				if (!parsed.poolKey || typeof parsed.poolKey !== "string") {
					writeJson(res, 400, { error: "Missing poolKey." });
					return;
				}
				if (!isPermissionTier(parsed.tier)) {
					writeJson(res, 400, { error: "Invalid permission tier." });
					return;
				}
				if (parsed.userId !== undefined && typeof parsed.userId !== "string") {
					writeJson(res, 400, { error: "Invalid userId." });
					return;
				}
				if (parsed.cwd !== undefined && typeof parsed.cwd !== "string") {
					writeJson(res, 400, { error: "Invalid cwd." });
					return;
				}

				const scope = authResult.scope;
				let effectiveTier = parsed.tier;
				const effectiveEnableSkills = parsed.enableSkills;
				let effectiveUserId = parsed.userId;
				const effectiveCwd = resolveCwd(parsed.cwd);

				// Any scope that isn't "telegram" is treated as a social service scope
				if (scope !== "telegram") {
					if (parsed.tier !== "SOCIAL") {
						logger.warn(
							{ requestedTier: parsed.tier, userId: parsed.userId, poolKey: parsed.poolKey, scope },
							"social scope forced to SOCIAL tier",
						);
					}
					effectiveTier = "SOCIAL";
					if (!effectiveUserId?.startsWith(`${scope}:`)) {
						effectiveUserId = `${scope}:${effectiveUserId ?? "agent"}`;
					}
					// Defense-in-depth: strip credentials from social scopes.
					// The relay should never send them for non-telegram scopes, but
					// if it does, drop them here before they reach buildSdkOptions().
					if (parsed.exposedCredentials) {
						logger.warn({ scope }, "stripping exposedCredentials from social scope request");
						parsed.exposedCredentials = undefined;
					}
				}

				logger.info(
					{
						userId: effectiveUserId,
						poolKey: parsed.poolKey,
						scope,
						tier: effectiveTier,
						cwd: effectiveCwd,
					},
					"agent received query request",
				);

				const timeoutMs = clampTimeout(parsed.timeoutMs ?? DEFAULT_TIMEOUT_MS);
				const abortController = new AbortController();
				const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

				res.on("close", () => {
					abortController.abort();
				});

				// Inject cached provider summary into system prompt if available
				let effectiveSystemPromptAppend = parsed.systemPromptAppend;
				if (scope === "telegram") {
					const providerSummary = getCachedProviderSummary();
					if (providerSummary) {
						const providerBlock = `<available-providers>\n${providerSummary}\n</available-providers>`;
						effectiveSystemPromptAppend = effectiveSystemPromptAppend
							? `${effectiveSystemPromptAppend}\n${providerBlock}`
							: providerBlock;
					}
				}

				// Inject soul + social contract with active persona tag
				const soul = loadSoul();
				if (soul) {
					const soulBlock = `<soul>\n${soul}\n</soul>`;
					effectiveSystemPromptAppend = effectiveSystemPromptAppend
						? `${effectiveSystemPromptAppend}\n${soulBlock}`
						: soulBlock;
				}
				const socialPrompt = loadSocialContractPrompt();
				if (socialPrompt) {
					const isSocialScope = scope !== "telegram";
					const persona = isSocialScope ? "public" : "private";
					const personaDescription = isSocialScope
						? `You are operating as telclaude's PUBLIC persona on ${scope}. Your responses are visible to others.`
						: "You are operating as telclaude's PRIVATE persona. This is a direct, confidential conversation with your operator.";
					const personaBlock = `<social-contract>\n${socialPrompt}\n</social-contract>\n<active-persona>${persona}</active-persona>\n${personaDescription}`;
					effectiveSystemPromptAppend = effectiveSystemPromptAppend
						? `${effectiveSystemPromptAppend}\n${personaBlock}`
						: personaBlock;
				}

				streamQuery(
					{
						...parsed,
						cwd: effectiveCwd,
						tier: effectiveTier,
						enableSkills: effectiveEnableSkills,
						userId: effectiveUserId,
						systemPromptAppend: effectiveSystemPromptAppend,
						timeoutMs,
					},
					res,
					abortController,
				)
					.catch((err) => {
						logger.error({ error: String(err) }, "agent query failed");
						if (!res.headersSent) {
							writeJson(res, 500, { error: "Query failed." });
						} else {
							const failure: StreamChunk = {
								type: "done",
								result: {
									response: "",
									success: false,
									error: String(err),
									costUsd: 0,
									numTurns: 0,
									durationMs: 0,
								},
							};
							res.write(`${JSON.stringify(failure)}\n`);
							res.end();
						}
					})
					.finally(() => {
						clearTimeout(timeoutId);
					});
			} catch (err) {
				logger.warn({ error: String(err) }, "failed to parse agent request");
				writeJson(res, 400, { error: "Invalid JSON body." });
			}
		});
	});

	// Override Node.js default request timeout (300000ms = 5 minutes in Node 18+)
	// Set to MAX_TIMEOUT_MS to allow queries to run up to 10 minutes by default
	server.requestTimeout = MAX_TIMEOUT_MS;
	server.headersTimeout = 120000; // 2 minutes for headers
	server.keepAliveTimeout = MAX_TIMEOUT_MS;

	server.listen(port, host, () => {
		logger.info({ host, port, requestTimeout: server.requestTimeout }, "agent server listening");
	});

	return server;
}
