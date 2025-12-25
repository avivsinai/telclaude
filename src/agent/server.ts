import http from "node:http";

import type { SdkBeta } from "@anthropic-ai/claude-agent-sdk";
import type { PermissionTier } from "../config/config.js";
import { verifyInternalAuth } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { getSandboxMode } from "../sandbox/index.js";
import { executePooledQuery, type StreamChunk } from "../sdk/client.js";

const logger = getChildLogger({ module: "agent-server" });

const MAX_BODY_BYTES = Number(process.env.TELCLAUDE_AGENT_MAX_BODY_BYTES ?? 262144);
const MAX_PROMPT_CHARS = Number(process.env.TELCLAUDE_AGENT_MAX_PROMPT_CHARS ?? 100_000);
const MAX_TIMEOUT_MS = Number(process.env.TELCLAUDE_AGENT_MAX_TIMEOUT_MS ?? 600_000);
const DEFAULT_TIMEOUT_MS = Number(process.env.TELCLAUDE_AGENT_DEFAULT_TIMEOUT_MS ?? 600_000);
const AGENT_WORKDIR = process.env.TELCLAUDE_AGENT_WORKDIR ?? process.cwd();

type QueryRequest = {
	prompt: string;
	tier: PermissionTier;
	poolKey: string;
	enableSkills?: boolean;
	timeoutMs?: number;
	resumeSessionId?: string;
	betas?: SdkBeta[];
	userId?: string;
};

type AgentServerOptions = {
	port?: number;
	host?: string;
};

function isPermissionTier(value: unknown): value is PermissionTier {
	return value === "READ_ONLY" || value === "WRITE_LOCAL" || value === "FULL_ACCESS";
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

	for await (const chunk of executePooledQuery(req.prompt, {
		cwd: AGENT_WORKDIR,
		tier: req.tier,
		poolKey: req.poolKey,
		userId: req.userId,
		resumeSessionId: req.resumeSessionId,
		enableSkills: req.enableSkills ?? req.tier !== "READ_ONLY",
		timeoutMs: req.timeoutMs,
		abortController,
		betas: req.betas,
	})) {
		if (abortController.signal.aborted) {
			break;
		}
		res.write(`${JSON.stringify(chunk)}\n`);
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
			writeJson(res, 200, { ok: true });
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

				const timeoutMs = clampTimeout(parsed.timeoutMs ?? DEFAULT_TIMEOUT_MS);
				const abortController = new AbortController();
				const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

				res.on("close", () => {
					abortController.abort();
				});

				streamQuery(
					{
						...parsed,
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

	server.listen(port, host, () => {
		logger.info({ host, port }, "agent server listening");
	});

	return server;
}
