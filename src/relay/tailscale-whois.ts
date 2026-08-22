import fs from "node:fs";
import http from "node:http";
import net from "node:net";

const LOCALAPI_WHOIS_PATH = "/localapi/v0/whois";
const LOCALAPI_HTTP_WHOIS_URL = "http://100.100.100.100/localapi/v0/whois";
const WHOIS_TIMEOUT_MS = 1_500;

export type TailscaleWhois = {
	readonly loginName: string;
};

export function normalizeBrokerRemoteAddress(remoteAddress?: string | null): string | null {
	if (!remoteAddress) return null;
	if (remoteAddress.startsWith("::ffff:")) {
		return remoteAddress.slice("::ffff:".length);
	}
	return remoteAddress;
}

export function isLoopbackBrokerAddress(addr: string): boolean {
	return addr === "127.0.0.1" || addr === "::1" || addr === "localhost";
}

export function parseForwardedClientAddress(header: string | string[] | undefined): string | null {
	const raw = Array.isArray(header) ? header[0] : header;
	if (!raw) return null;
	const first = raw.split(",")[0]?.trim();
	if (!first) return null;
	return parseSingleClientAddress(first);
}

export function parseSingleClientAddress(value: string): string | null {
	const trimmed = value.trim();
	if (!trimmed) return null;
	if (trimmed.startsWith("[")) {
		const end = trimmed.indexOf("]");
		if (end < 1) return null;
		const ip = trimmed.slice(1, end);
		return net.isIP(ip) !== 0 ? ip : null;
	}
	if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(trimmed)) {
		const ip = trimmed.slice(0, trimmed.lastIndexOf(":"));
		return net.isIP(ip) !== 0 ? ip : null;
	}
	return net.isIP(trimmed) !== 0 ? trimmed : null;
}

export function readDefaultIpv4Gateway(routeTable = "/proc/net/route"): string | null {
	if (!fs.existsSync(routeTable)) return null;
	const text = fs.readFileSync(routeTable, "utf8");
	for (const line of text.split("\n").slice(1)) {
		const cols = line.trim().split(/\s+/);
		if (cols[1] !== "00000000" || !cols[2] || cols[2] === "00000000") continue;
		const bytes = Buffer.from(cols[2], "hex");
		if (bytes.length !== 4) continue;
		return `${bytes[3]}.${bytes[2]}.${bytes[1]}.${bytes[0]}`;
	}
	return null;
}

export function defaultTrustedBrokerProxies(
	env: NodeJS.ProcessEnv = process.env,
): readonly string[] {
	const extras = (env.TELCLAUDE_BROKER_TRUSTED_PROXIES ?? "")
		.split(",")
		.map((value) => value.trim())
		.filter(Boolean);
	const gateway = readDefaultIpv4Gateway();
	return ["127.0.0.1", "::1", ...(gateway ? [gateway] : []), ...extras];
}

export function isTrustedBrokerProxy(addr: string, trustedProxies: readonly string[]): boolean {
	if (isLoopbackBrokerAddress(addr)) return true;
	return trustedProxies.includes(addr);
}

export function tailscaleLoginsMatch(left: string, right: string): boolean {
	return left.trim().toLowerCase() === right.trim().toLowerCase();
}

export async function lookupTailscaleWhois(
	addr: string,
	env: NodeJS.ProcessEnv = process.env,
): Promise<TailscaleWhois | null> {
	const socketPath = resolveTailscaledSocketPath(env);
	if (socketPath) {
		const viaSocket = await whoisViaUnixSocket(socketPath, addr);
		if (viaSocket) return viaSocket;
	}
	return whoisViaLocalapiHttp(addr);
}

function resolveTailscaledSocketPath(env: NodeJS.ProcessEnv): string | null {
	const configured = env.TELCLAUDE_TAILSCALED_SOCKET?.trim();
	const candidates = [
		configured,
		"/run/tailscale/tailscaled.sock",
		"/var/run/tailscale/tailscaled.sock",
	];
	for (const candidate of candidates) {
		if (candidate && fs.existsSync(candidate)) return candidate;
	}
	return null;
}

function loginFromWhoisPayload(payload: unknown): string | null {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
	const profile = (payload as { UserProfile?: { LoginName?: unknown } }).UserProfile;
	const loginName = typeof profile?.LoginName === "string" ? profile.LoginName.trim() : "";
	return loginName || null;
}

async function whoisViaUnixSocket(
	socketPath: string,
	addr: string,
): Promise<TailscaleWhois | null> {
	return await new Promise((resolve) => {
		const req = http.request(
			{
				socketPath,
				path: `${LOCALAPI_WHOIS_PATH}?addr=${encodeURIComponent(addr)}`,
				method: "GET",
				headers: { Host: "local-tailscaled.sock" },
				timeout: WHOIS_TIMEOUT_MS,
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (chunk) => {
					chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
				});
				res.on("end", () => {
					if ((res.statusCode ?? 500) >= 300) {
						resolve(null);
						return;
					}
					try {
						const loginName = loginFromWhoisPayload(
							JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown,
						);
						resolve(loginName ? { loginName } : null);
					} catch {
						resolve(null);
					}
				});
			},
		);
		req.on("error", () => resolve(null));
		req.on("timeout", () => {
			req.destroy();
			resolve(null);
		});
		req.end();
	});
}

async function whoisViaLocalapiHttp(addr: string): Promise<TailscaleWhois | null> {
	try {
		const response = await fetch(`${LOCALAPI_HTTP_WHOIS_URL}?addr=${encodeURIComponent(addr)}`, {
			signal: AbortSignal.timeout(WHOIS_TIMEOUT_MS),
		});
		if (!response.ok) return null;
		const loginName = loginFromWhoisPayload(await response.json());
		return loginName ? { loginName } : null;
	} catch {
		return null;
	}
}
