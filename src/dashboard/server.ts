/**
 * Local web dashboard (W15).
 *
 * Design decisions (see CLAUDE.md for context):
 *   - Binds to `127.0.0.1` exclusively. The listen call passes `host: "127.0.0.1"`
 *     and a request-level guard rejects any non-loopback `Host` header. Together
 *     these prevent accidental exposure even if a reverse proxy is misconfigured.
 *   - TOTP-gated: every /api/* route (except /api/auth/verify) requires a
 *     valid dashboard session cookie.
 *   - Mutations: the spec says read-only except `/api/doctor/run`. We enforce
 *     this by route: no route writes to the DB, grants/revokes approvals, or
 *     touches the vault. The only POST endpoints are `/api/auth/*` (auth) and
 *     `/api/doctor/run` (idempotent health probe).
 *   - No CORS: the dashboard is same-origin only. We deliberately omit any
 *     Access-Control-Allow-* headers so a hostile page in another browser tab
 *     cannot fetch-read dashboard data.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { getChildLogger } from "../logging.js";
import { registerApprovalsRoute } from "./routes/approvals.js";
import { registerAuditRoute } from "./routes/audit.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { registerDoctorRoute } from "./routes/doctor.js";
import { registerHealthRoute } from "./routes/health.js";
import { registerProvidersRoute } from "./routes/providers.js";
import { registerSkillsRoute } from "./routes/skills.js";
import { DASHBOARD_COOKIE_NAME, DashboardSessionStore } from "./sessions.js";

const logger = getChildLogger({ module: "dashboard-server" });

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Whitelist of Host header values. The dashboard is reachable ONLY via these
 * names (loopback + localhost aliases). Any other Host is rejected at request
 * time — defence-in-depth against reverse-proxy / DNS-rebinding misconfigs.
 *
 * Ports are tolerated (the request-time parse strips the port before comparing).
 */
const ALLOWED_HOST_NAMES = new Set(["127.0.0.1", "localhost", "::1", "[::1]", "ip6-localhost"]);

export interface DashboardServerOptions {
	port: number;
	/** Bind host. Callers must NOT override unless they really mean it. */
	host?: string;
	logLevel?: string;
}

export interface DashboardServerHandle {
	server: FastifyInstance;
	sessions: DashboardSessionStore;
	port: number;
	host: string;
	close(): Promise<void>;
}

function rejectNonLoopbackHost(request: FastifyRequest, reply: FastifyReply): boolean {
	const raw = request.headers.host;
	if (!raw) {
		reply.status(400).send({ ok: false, error: "missing Host header" });
		return false;
	}
	// Strip port (handles both IPv4 "host:port" and IPv6 "[::1]:port").
	let name: string;
	if (raw.startsWith("[")) {
		const end = raw.indexOf("]");
		name = end > 0 ? raw.slice(0, end + 1) : raw;
	} else {
		name = raw.split(":")[0] ?? raw;
	}
	if (!ALLOWED_HOST_NAMES.has(name)) {
		reply.status(400).send({ ok: false, error: "non-loopback Host rejected" });
		return false;
	}
	return true;
}

function extractSessionIdFromCookie(cookieHeader: string | undefined): string | null {
	if (!cookieHeader) return null;
	for (const part of cookieHeader.split(";")) {
		const trimmed = part.trim();
		const eq = trimmed.indexOf("=");
		if (eq <= 0) continue;
		const name = trimmed.slice(0, eq);
		const value = trimmed.slice(eq + 1);
		if (name === DASHBOARD_COOKIE_NAME && value) return value;
	}
	return null;
}

/**
 * Routes that are always reachable without a session cookie.
 * Keep this list tiny: only auth + the static login page + a public
 * health-check ping that reveals nothing sensitive.
 */
const PUBLIC_PATHS = new Set([
	"/api/auth/verify",
	"/",
	"/index.html",
	"/app.js",
	"/styles.css",
	"/favicon.ico",
	"/api/ping",
]);

function isPublicPath(url: string): boolean {
	// Strip query string.
	const q = url.indexOf("?");
	const p = q >= 0 ? url.slice(0, q) : url;
	return PUBLIC_PATHS.has(p);
}

export async function buildDashboardServer(
	opts: DashboardServerOptions,
): Promise<DashboardServerHandle> {
	const sessions = new DashboardSessionStore();
	const server = Fastify({
		logger: { level: opts.logLevel ?? "warn" },
		// Disable request-id generation — we're localhost-only.
		disableRequestLogging: true,
	});

	// ─── Security hooks ──────────────────────────────────────────────────────
	server.addHook("onRequest", async (request, reply) => {
		if (!rejectNonLoopbackHost(request, reply)) return;

		// Auth gate: everything except the whitelist above requires a session.
		if (isPublicPath(request.url)) return;

		const sessionId = extractSessionIdFromCookie(request.headers.cookie);
		const row = sessions.lookup(sessionId ?? undefined);
		if (!row) {
			reply.status(401).send({ ok: false, error: "authentication required" });
			return;
		}
		// Attach for downstream logging only.
		(request as FastifyRequest & { dashUser?: string }).dashUser = row.localUserId;
	});

	// Defensive: explicitly strip any CORS headers that might be added upstream.
	server.addHook("onSend", async (_request, reply, payload) => {
		reply.removeHeader("access-control-allow-origin");
		reply.removeHeader("access-control-allow-credentials");
		reply.removeHeader("access-control-allow-methods");
		reply.removeHeader("access-control-allow-headers");
		return payload;
	});

	// ─── Trivial liveness (no auth) ──────────────────────────────────────────
	server.get("/api/ping", async () => ({ ok: true }));

	// ─── Routes ──────────────────────────────────────────────────────────────
	await registerAuthRoutes(server, { sessions });
	await registerHealthRoute(server);
	await registerProvidersRoute(server);
	await registerSkillsRoute(server);
	await registerApprovalsRoute(server);
	await registerAuditRoute(server);
	await registerDoctorRoute(server);

	// ─── Static UI (shipped under assets/dashboard-ui/) ─────────────────────
	const uiDir = path.resolve(__dirname, "..", "..", "assets", "dashboard-ui");
	server.get("/", async (_request, reply) => {
		return serveStatic(reply, uiDir, "index.html", "text/html; charset=utf-8");
	});
	server.get("/index.html", async (_request, reply) => {
		return serveStatic(reply, uiDir, "index.html", "text/html; charset=utf-8");
	});
	server.get("/app.js", async (_request, reply) => {
		return serveStatic(reply, uiDir, "app.js", "application/javascript; charset=utf-8");
	});
	server.get("/styles.css", async (_request, reply) => {
		return serveStatic(reply, uiDir, "styles.css", "text/css; charset=utf-8");
	});

	const host = opts.host ?? "127.0.0.1";
	// Explicitly forbid non-loopback binds — the spec makes this non-negotiable.
	if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
		throw new Error(`dashboard refuses to bind to non-loopback host ${host}; use 127.0.0.1`);
	}

	await server.listen({ port: opts.port, host });
	const address = server.addresses()[0];
	const actualPort = address?.port ?? opts.port;
	logger.info({ host, port: actualPort }, "dashboard listening");

	return {
		server,
		sessions,
		port: actualPort,
		host,
		async close() {
			await server.close();
		},
	};
}

/**
 * Safe static file loader. Only serves files that live in `dir` and whose
 * basename appears in a closed allowlist (see routes above). We re-check the
 * resolved path to make sure traversal segments in `name` cannot escape.
 */
async function serveStatic(
	reply: FastifyReply,
	dir: string,
	name: string,
	contentType: string,
): Promise<FastifyReply> {
	const abs = path.resolve(dir, name);
	const relative = path.relative(dir, abs);
	if (relative.startsWith("..") || path.isAbsolute(relative)) {
		return reply.status(403).send({ ok: false, error: "forbidden" });
	}
	try {
		const buf = await fs.promises.readFile(abs);
		reply.header("content-type", contentType);
		// The content we ship is static and author-controlled; disable inline
		// caches so operators see dashboard changes immediately after upgrade.
		reply.header("cache-control", "no-store");
		return reply.send(buf);
	} catch (err) {
		return reply.status(404).send({
			ok: false,
			error: err instanceof Error ? err.message : "not found",
		});
	}
}
