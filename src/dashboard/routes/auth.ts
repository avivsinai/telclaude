/**
 * Dashboard auth routes.
 *
 * POST /api/auth/verify { localUserId, code } → sets session cookie
 * POST /api/auth/logout                       → clears session cookie
 */

import type { FastifyInstance } from "fastify";
import { getChildLogger } from "../../logging.js";
import { getTOTPClient } from "../../totp-client/client.js";
import {
	DASHBOARD_COOKIE_NAME,
	DASHBOARD_SESSION_TTL_MS,
	type DashboardSessionStore,
} from "../sessions.js";

const logger = getChildLogger({ module: "dashboard-auth" });

type VerifyBody = {
	localUserId?: unknown;
	code?: unknown;
};

function isNonEmptyString(value: unknown): value is string {
	return typeof value === "string" && value.trim().length > 0;
}

/**
 * Build a Set-Cookie header value. We write this manually rather than pulling
 * in @fastify/cookie to keep the dashboard dependency-free.
 *
 * - `HttpOnly`: not readable from JS
 * - `SameSite=Strict`: dashboard is strictly same-origin
 * - `Secure` is intentionally omitted because the dashboard binds to
 *   `127.0.0.1` and is HTTP-only. Adding `Secure` would cause browsers to
 *   silently reject the cookie on plain http://localhost.
 * - `Max-Age` matches session TTL; also set expiry on the server side.
 */
function buildCookie(name: string, value: string, maxAgeMs: number): string {
	const parts = [
		`${name}=${value}`,
		"Path=/",
		"HttpOnly",
		"SameSite=Strict",
		`Max-Age=${Math.floor(maxAgeMs / 1000)}`,
	];
	return parts.join("; ");
}

function buildClearCookie(name: string): string {
	return [`${name}=`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"].join("; ");
}

export interface AuthRoutesDeps {
	sessions: DashboardSessionStore;
}

export async function registerAuthRoutes(
	server: FastifyInstance,
	deps: AuthRoutesDeps,
): Promise<void> {
	const { sessions } = deps;
	const totp = getTOTPClient();

	server.post("/api/auth/verify", async (request, reply) => {
		const body = request.body as VerifyBody | undefined;
		const localUserId = isNonEmptyString(body?.localUserId) ? body.localUserId.trim() : null;
		const code = isNonEmptyString(body?.code) ? body.code.trim() : null;

		if (!localUserId || !code) {
			return reply.status(400).send({ ok: false, error: "localUserId and code required" });
		}

		// Per-request; the TOTP daemon is idempotent for rapid verify calls.
		let valid = false;
		try {
			valid = await totp.verify(localUserId, code);
		} catch (err) {
			logger.warn({ error: String(err), localUserId }, "TOTP verify threw");
			return reply.status(502).send({ ok: false, error: "TOTP daemon unavailable" });
		}

		if (!valid) {
			return reply.status(401).send({ ok: false, error: "invalid code" });
		}

		const session = sessions.create(localUserId);
		reply.header(
			"Set-Cookie",
			buildCookie(DASHBOARD_COOKIE_NAME, session.id, DASHBOARD_SESSION_TTL_MS),
		);
		return reply.send({ ok: true, expiresAt: session.expiresAt });
	});

	server.post("/api/auth/logout", async (request, reply) => {
		// Best-effort revoke: if the caller holds a cookie, invalidate it.
		const cookie = request.headers.cookie;
		if (cookie) {
			for (const part of cookie.split(";")) {
				const [name, value] = part.trim().split("=");
				if (name === DASHBOARD_COOKIE_NAME && value) {
					sessions.revoke(value);
				}
			}
		}
		reply.header("Set-Cookie", buildClearCookie(DASHBOARD_COOKIE_NAME));
		return reply.send({ ok: true });
	});
}
