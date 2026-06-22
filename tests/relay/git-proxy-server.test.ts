import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { gzipSync } from "node:zlib";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { mintGitProxyToken } from "../../src/relay/git-proxy-auth.js";
import { startGitProxyServer, type ReceivePackCommand } from "../../src/relay/git-proxy.js";

const getInstallationTokenMock = vi.hoisted(() => vi.fn());
const getGitHubAppIdentityMock = vi.hoisted(() => vi.fn());
const loggerMock = vi.hoisted(() => ({
	debug: vi.fn(),
	error: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
}));

vi.mock("../../src/services/github-app.js", () => ({
	getInstallationToken: getInstallationTokenMock,
	getGitHubAppIdentity: getGitHubAppIdentityMock,
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => loggerMock,
}));

const SECRET = "git-proxy-server-test-secret";
const PEER = "127.0.0.1";

function scopedToken(
	input: {
		sessionId?: string;
		permissions?: Array<"fetch" | "push">;
		allowedRefs?: string[];
		deniedRefs?: string[];
		repositories?: string[];
	} = {},
): string {
	return mintGitProxyToken({
		secret: SECRET,
		peerAddress: PEER,
		sessionId: input.sessionId ?? "server-test-session",
		repositories: input.repositories ?? ["owner/repo"],
		permissions: input.permissions ?? ["fetch", "push"],
		allowedRefs: input.allowedRefs ?? ["refs/heads/*"],
		deniedRefs: input.deniedRefs ?? ["refs/heads/main", "refs/heads/master"],
		ttlMs: 60_000,
	});
}

function pktLine(payload: string): Buffer {
	const length = Buffer.byteLength(payload) + 4;
	return Buffer.from(`${length.toString(16).padStart(4, "0")}${payload}`, "utf8");
}

function receivePackBody(commands: ReceivePackCommand[]): Buffer {
	return Buffer.concat([
		...commands.map((command) =>
			pktLine(`${command.oldId} ${command.newId} ${command.ref}\0 report-status\n`),
		),
		Buffer.from("0000", "utf8"),
	]);
}

function receivePackPushCertificateBody(commands: ReceivePackCommand[]): Buffer {
	return Buffer.concat([
		pktLine("push-cert\0 report-status\n"),
		pktLine("certificate version 0.1\n"),
		pktLine("pusher Test User <test@example.com>\n"),
		pktLine("pushee https://github.com/owner/repo.git\n"),
		pktLine("nonce test-nonce\n"),
		pktLine("\n"),
		...commands.map((command) => pktLine(`${command.oldId} ${command.newId} ${command.ref}\n`)),
		pktLine("-----BEGIN PGP SIGNATURE-----\n"),
		pktLine("not-a-signature\n"),
		pktLine("push-cert-end\n"),
		Buffer.from("0000PACKbinary-data", "utf8"),
	]);
}

async function request(
	port: number,
	path: string,
	options: {
		method?: string;
		token?: string;
		body?: Buffer | string;
		headers?: Record<string, string>;
	} = {},
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
	const body = options.body;
	const headers = {
		...(options.token ? { "X-Telclaude-Session": options.token } : {}),
		...(body ? { "Content-Length": String(Buffer.byteLength(body)) } : {}),
		...options.headers,
	};

	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				host: "127.0.0.1",
				port,
				path,
				method: options.method ?? "GET",
				headers,
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (chunk: Buffer) => chunks.push(chunk));
				res.on("end", () => {
					resolve({
						status: res.statusCode ?? 0,
						body: Buffer.concat(chunks).toString("utf8"),
						headers: res.headers,
					});
				});
			},
		);
		req.on("error", reject);
		if (body) req.end(body);
		else req.end();
	});
}

async function requestWithChunks(
	port: number,
	path: string,
	options: {
		method?: string;
		token?: string;
		chunks: Buffer[];
		headers?: Record<string, string>;
	},
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
	const contentLength = options.chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
	const headers = {
		...(options.token ? { "X-Telclaude-Session": options.token } : {}),
		"Content-Length": String(contentLength),
		...options.headers,
	};

	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				host: "127.0.0.1",
				port,
				path,
				method: options.method ?? "GET",
				headers,
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (chunk: Buffer) => chunks.push(chunk));
				res.on("end", () => {
					resolve({
						status: res.statusCode ?? 0,
						body: Buffer.concat(chunks).toString("utf8"),
						headers: res.headers,
					});
				});
			},
		);
		req.on("error", reject);
		req.on("socket", (socket) => socket.setNoDelay(true));

		(async () => {
			for (const chunk of options.chunks) {
				if (!req.write(chunk)) await once(req, "drain");
				await delay(5);
			}
			req.end();
		})().catch(reject);
	});
}

async function requestWithIncompleteBody(
	port: number,
	path: string,
	options: {
		method?: string;
		token?: string;
		chunk: Buffer | string;
		declaredLength: number;
		headers?: Record<string, string>;
	},
): Promise<{
	status: number;
	body: string;
	headers: http.IncomingHttpHeaders;
	socketClosed: boolean;
}> {
	const headers = {
		...(options.token ? { "X-Telclaude-Session": options.token } : {}),
		"Content-Length": String(options.declaredLength),
		...options.headers,
	};

	return new Promise((resolve, reject) => {
		let response: {
			status: number;
			body: string;
			headers: http.IncomingHttpHeaders;
		} | null = null;
		let socketClosed = false;
		let settled = false;
		let req: http.ClientRequest | null = null;
		let timer: ReturnType<typeof setTimeout>;

		const finish = () => {
			if (settled || !response || !socketClosed) return;
			settled = true;
			clearTimeout(timer);
			resolve({ ...response, socketClosed });
		};

		timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			req?.destroy();
			reject(new Error("timed out waiting for incomplete request socket closure"));
		}, 1_000);

		req = http.request(
			{
				host: "127.0.0.1",
				port,
				path,
				method: options.method ?? "POST",
				headers,
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (chunk: Buffer) => chunks.push(chunk));
				res.on("end", () => {
					response = {
						status: res.statusCode ?? 0,
						body: Buffer.concat(chunks).toString("utf8"),
						headers: res.headers,
					};
					finish();
				});
			},
		);
		req.on("error", (err) => {
			if (response) return;
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				reject(err);
			}
		});
		req.on("socket", (socket) => {
			socket.setNoDelay(true);
			socket.on("close", () => {
				socketClosed = true;
				finish();
			});
		});
		req.write(options.chunk);
	});
}

async function readWebBody(body: unknown): Promise<Buffer> {
	const reader = (body as ReadableStream<Uint8Array> | undefined)?.getReader?.();
	if (!reader) throw new Error("expected readable request body");
	const chunks: Buffer[] = [];
	while (true) {
		const next = await reader.read();
		if (next.done) break;
		chunks.push(Buffer.from(next.value));
	}
	return Buffer.concat(chunks);
}

function redirectResponseWithCancel(
	status: number,
	headers: Record<string, string>,
): { response: Response; cancel: ReturnType<typeof vi.fn> } {
	const cancel = vi.fn();
	const body = new ReadableStream<Uint8Array>({ cancel });
	return { response: new Response(body, { status, headers }), cancel };
}

function lfsUploadBatchObjects(count: number) {
	return Array.from({ length: count }, (_, index) => {
		const oid = index.toString(16).padStart(64, "0");
		return {
			oid,
			size: index + 1,
			actions: {
				upload: {
					href: `https://1.1.1.1/lfs/upload/${index}`,
					expires_in: 900,
				},
				verify: {
					href: `https://1.1.1.1/lfs/verify/${index}`,
					expires_in: 900,
				},
			},
		};
	});
}

function lfsSingleActionBatchObjects(
	count: number,
	action: "download" | "verify",
	pathPrefix: string,
	expiresIn: number,
	oidOffset = 0,
) {
	return Array.from({ length: count }, (_, index) => {
		const oid = (oidOffset + index).toString(16).padStart(64, "0");
		return {
			oid,
			size: index + 1,
			actions: {
				[action]: {
					href: `https://1.1.1.1/lfs/${pathPrefix}/${index}`,
					expires_in: expiresIn,
				},
			},
		};
	});
}

async function consumeLfsActionPaths(
	port: number,
	token: string,
	paths: string[],
	method: "GET" | "POST" | "PUT",
	expectedStatus = 200,
): Promise<void> {
	for (let start = 0; start < paths.length; start += 50) {
		const responses = await Promise.all(
			paths.slice(start, start + 50).map((actionPath) =>
				request(port, actionPath, {
					method,
					token,
				}),
			),
		);
		for (const response of responses) {
			expect(response.status).toBe(expectedStatus);
		}
	}
}

describe("git proxy server", () => {
	let server: http.Server | null = null;
	let port = 0;
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		getInstallationTokenMock.mockReset().mockResolvedValue("github-installation-token");
		getGitHubAppIdentityMock.mockReset().mockResolvedValue({
			username: "telclaude[bot]",
			email: "123+telclaude[bot]@users.noreply.github.com",
		});
		loggerMock.debug.mockReset();
		loggerMock.error.mockReset();
		loggerMock.info.mockReset();
		loggerMock.warn.mockReset();
		fetchMock = vi.fn().mockResolvedValue(
			new Response("upstream-ok", {
				status: 200,
				headers: {
					"Content-Type": "application/x-git-upload-pack-result",
					Connection: "close",
					"Set-Cookie": "do-not-forward=1",
				},
			}),
		);
		vi.stubGlobal("fetch", fetchMock);

		server = startGitProxyServer({
			port: 0,
			host: "127.0.0.1",
			tokenSecret: SECRET,
			defaultPolicy: {
				repositories: ["owner/repo"],
				permissions: ["fetch", "push"],
				allowedRefs: ["refs/heads/*"],
				deniedRefs: ["refs/heads/main", "refs/heads/master"],
			},
		});
		await once(server, "listening");
		port = (server.address() as AddressInfo).port;
	});

	afterEach(async () => {
		vi.unstubAllGlobals();
		if (server) {
			await new Promise<void>((resolve, reject) => {
				server?.close((error) => (error ? reject(error) : resolve()));
			});
			server = null;
		}
	});

	it("forwards authorized fetch requests with a repo-scoped read installation token", async () => {
		const response = await request(
			port,
			"/github.com/owner/repo.git/info/refs?service=git-upload-pack",
			{ token: scopedToken() },
		);

		expect(response.status).toBe(200);
		expect(response.body).toBe("upstream-ok");
		expect(response.headers["set-cookie"]).toBeUndefined();
		expect(getInstallationTokenMock).toHaveBeenCalledWith({
			repository: "owner/repo",
			contentsPermission: "read",
		});
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0] as [
			string,
			{ method: string; headers: Record<string, string> },
		];
		expect(url).toBe("https://github.com/owner/repo.git/info/refs?service=git-upload-pack");
		expect(init.method).toBe("GET");
		expect(init.headers.Authorization).toBe(
			`Basic ${Buffer.from("x-access-token:github-installation-token").toString("base64")}`,
		);
		expect(init.headers["Accept-Encoding"]).toBe("identity");
	});

	it("strips stale gzip response headers from decoded Smart HTTP responses", async () => {
		const decodedBody = "upload-pack-ok";
		const gzippedBody = gzipSync(decodedBody);
		fetchMock.mockResolvedValueOnce(
			new Response(decodedBody, {
				status: 200,
				headers: {
					"Content-Type": "application/x-git-upload-pack-result",
					"Content-Encoding": "gzip",
					"Content-Length": String(gzippedBody.byteLength),
				},
			}),
		);

		const response = await request(
			port,
			"/github.com/owner/repo.git/info/refs?service=git-upload-pack",
			{ token: scopedToken() },
		);

		expect(response.status).toBe(200);
		expect(response.body).toBe(decodedBody);
		expect(response.headers["content-encoding"]).toBeUndefined();
		expect(response.headers["content-length"]).toBeUndefined();
	});

	it("preserves request Content-Encoding for gzip Smart HTTP POSTs", async () => {
		const gzippedBody = gzipSync("git-upload-pack-request");
		let forwardedBody: Buffer | undefined;
		fetchMock.mockImplementationOnce(
			async (_url: string, init: { body?: ReadableStream<Uint8Array> }) => {
				forwardedBody = await readWebBody(init.body);
				return new Response("upload-pack-ok", { status: 200 });
			},
		);

		const response = await request(port, "/github.com/owner/repo.git/git-upload-pack", {
			method: "POST",
			token: scopedToken(),
			headers: {
				"Content-Type": "application/x-git-upload-pack-request",
				"Content-Encoding": "gzip",
			},
			body: gzippedBody,
		});

		expect(response.status).toBe(200);
		expect(response.body).toBe("upload-pack-ok");

		const forwarded = fetchMock.mock.calls[0]?.[1] as {
			body?: ReadableStream<Uint8Array>;
			headers: Record<string, string>;
		};
		expect(forwarded.headers["Content-Encoding"]).toBe("gzip");
		expect(forwarded.headers["Content-Length"]).toBe(String(gzippedBody.byteLength));
		expect(forwardedBody).toEqual(gzippedBody);
	});

	it("closes incomplete request bodies when installation token lookup throws", async () => {
		getInstallationTokenMock.mockRejectedValueOnce(new Error("token backend unavailable"));

		const response = await requestWithIncompleteBody(
			port,
			"/github.com/owner/repo.git/info/refs?service=git-upload-pack",
			{
				method: "GET",
				token: scopedToken(),
				chunk: "partial-token-lookup-body",
				declaredLength: 2048,
			},
		);

		expect(response.status).toBe(503);
		expect(response.body).toContain("authentication not configured");
		expect(response.headers.connection).toBe("close");
		expect(response.socketClosed).toBe(true);
		expect(getInstallationTokenMock).toHaveBeenCalledTimes(1);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("closes incomplete health request bodies", async () => {
		const response = await requestWithIncompleteBody(port, "/health", {
			method: "GET",
			chunk: "partial-health-body",
			declaredLength: 2048,
		});

		expect(response.status).toBe(200);
		expect(JSON.parse(response.body)).toEqual({ ok: true, service: "git-proxy" });
		expect(response.headers.connection).toBe("close");
		expect(response.socketClosed).toBe(true);
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("closes incomplete identity request bodies", async () => {
		const response = await requestWithIncompleteBody(port, "/identity", {
			method: "GET",
			chunk: "partial-identity-body",
			declaredLength: 2048,
		});

		expect(response.status).toBe(200);
		expect(JSON.parse(response.body)).toEqual({
			username: "telclaude[bot]",
			email: "123+telclaude[bot]@users.noreply.github.com",
		});
		expect(response.headers.connection).toBe("close");
		expect(response.socketClosed).toBe(true);
		expect(getGitHubAppIdentityMock).toHaveBeenCalledTimes(1);
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("closes incomplete identity request bodies when GitHub App identity is unavailable", async () => {
		getGitHubAppIdentityMock.mockResolvedValueOnce(null);

		const response = await requestWithIncompleteBody(port, "/identity", {
			method: "GET",
			chunk: "partial-identity-body",
			declaredLength: 2048,
		});

		expect(response.status).toBe(503);
		expect(JSON.parse(response.body)).toEqual({ error: "GitHub App not configured" });
		expect(response.headers.connection).toBe("close");
		expect(response.socketClosed).toBe(true);
		expect(getGitHubAppIdentityMock).toHaveBeenCalledTimes(1);
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("closes incomplete identity request bodies when GitHub App identity lookup throws", async () => {
		getGitHubAppIdentityMock.mockRejectedValueOnce(new Error("identity backend unavailable"));

		const response = await requestWithIncompleteBody(port, "/identity", {
			method: "GET",
			chunk: "partial-identity-body",
			declaredLength: 2048,
		});

		expect(response.status).toBe(503);
		expect(JSON.parse(response.body)).toEqual({ error: "GitHub App not configured" });
		expect(response.headers.connection).toBe("close");
		expect(response.socketClosed).toBe(true);
		expect(getGitHubAppIdentityMock).toHaveBeenCalledTimes(1);
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks denied receive-pack refs before asking GitHub for a token", async () => {
		const zero = "0".repeat(40);
		const commit = "1".repeat(40);
		const response = await request(port, "/github.com/owner/repo.git/git-receive-pack", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			body: receivePackBody([{ oldId: zero, newId: commit, ref: "refs/heads/main" }]),
		});

		expect(response.status).toBe(403);
		expect(response.body).toContain("push ref is denied");
		expect(response.body).not.toContain("refs/heads/main");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("forwards exact receive-pack flush-only probes without ref updates", async () => {
		const forwardedBodies: Buffer[] = [];
		fetchMock.mockImplementationOnce(async (_url, init: { body?: unknown }) => {
			forwardedBodies.push(await readWebBody(init.body));
			return new Response("probe-ok", { status: 200 });
		});

		const response = await request(port, "/github.com/owner/repo.git/git-receive-pack", {
			method: "POST",
			token: scopedToken({
				allowedRefs: ["refs/heads/codex/*"],
				deniedRefs: ["refs/heads/*"],
			}),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			body: Buffer.from("0000", "utf8"),
		});

		expect(response.status).toBe(200);
		expect(response.body).toBe("probe-ok");
		expect(forwardedBodies).toEqual([Buffer.from("0000", "utf8")]);
		expect(getInstallationTokenMock).toHaveBeenCalledWith({
			repository: "owner/repo",
			contentsPermission: "write",
		});
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects receive-pack flush prefixes with extra bytes before GitHub auth", async () => {
		const response = await request(port, "/github.com/owner/repo.git/git-receive-pack", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			body: Buffer.from("0000PACK", "utf8"),
		});

		expect(response.status).toBe(400);
		expect(response.body).toContain("invalid receive-pack request");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects receive-pack without push permission before parsing the body", async () => {
		const response = await request(port, "/github.com/owner/repo.git/git-receive-pack", {
			method: "POST",
			token: scopedToken({ permissions: ["fetch"] }),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			body: "not-a-pkt-line",
		});

		expect(response.status).toBe(403);
		expect(response.body).toContain("push is not allowed");
		expect(response.headers.connection).toBe("close");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("preserves receive-pack body bytes when pack data arrives after split command chunks", async () => {
		const zero = "0".repeat(40);
		const commit = "1".repeat(40);
		const command = pktLine(`${zero} ${commit} refs/heads/codex/full-git-proxy\0 report-status\n`);
		const flush = Buffer.from("0000", "utf8");
		const packHead = Buffer.from("PACK\x00\x00\x00\x02", "binary");
		const packTail = Buffer.from("tail-bytes-after-command-list", "utf8");
		const originalBody = Buffer.concat([command, flush, packHead, packTail]);
		const forwardedBodies: Buffer[] = [];

		fetchMock.mockImplementationOnce(async (_url, init: { body?: unknown }) => {
			forwardedBodies.push(await readWebBody(init.body));
			return new Response("push-ok", { status: 200 });
		});

		const response = await requestWithChunks(port, "/github.com/owner/repo.git/git-receive-pack", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			chunks: [
				command.subarray(0, 8),
				command.subarray(8),
				Buffer.concat([flush, packHead.subarray(0, 4)]),
				packHead.subarray(4),
				packTail,
			],
		});

		expect(response.status).toBe(200);
		expect(response.body).toBe("push-ok");
		expect(forwardedBodies).toEqual([originalBody]);
		expect(getInstallationTokenMock).toHaveBeenCalledWith({
			repository: "owner/repo",
			contentsPermission: "write",
		});
	});

	it("rejects receive-pack push certificates before GitHub auth", async () => {
		const zero = "0".repeat(40);
		const commit = "1".repeat(40);
		const response = await request(port, "/github.com/owner/repo.git/git-receive-pack", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			body: receivePackPushCertificateBody([
				{ oldId: zero, newId: commit, ref: "refs/heads/codex/full-git-proxy" },
				{ oldId: zero, newId: commit, ref: "refs/heads/secret@x" },
			]),
		});

		expect(response.status).toBe(400);
		expect(response.body).toContain("invalid receive-pack request");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects dot-segment receive-pack route bypasses before GitHub auth", async () => {
		const zero = "0".repeat(40);
		const commit = "1".repeat(40);
		const response = await request(port, "/github.com/owner/repo.git/foo/../git-receive-pack", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			body: receivePackBody([{ oldId: zero, newId: commit, ref: "refs/heads/main" }]),
		});

		expect(response.status).toBe(400);
		expect(response.body).toContain("invalid git URL");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects encoded route bypasses before GitHub auth", async () => {
		const response = await request(port, "/github.com/owner/repo.git/%2e%2e/git-receive-pack", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/x-git-receive-pack-request" },
			body: Buffer.from("0000", "utf8"),
		});

		expect(response.status).toBe(400);
		expect(response.body).toContain("invalid git URL");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects LFS batch requests for unauthorized repositories before parsing the body", async () => {
		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken({ repositories: ["other/repo"] }),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: "not-json",
		});

		expect(response.status).toBe(403);
		expect(response.body).toContain("repository is not allowed");
		expect(response.body).not.toContain("owner/repo");
		expect(response.headers.connection).toBe("close");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rewrites LFS batch action URLs and mediates stored upstream action headers", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						transfer: "basic",
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								authenticated: true,
								actions: {
									upload: {
										href: "https://1.1.1.1/lfs/upload/a",
										header: {
											Authorization: "Basic upstream-lfs-secret",
											"X-Amz-Test": "stored-action-header",
										},
										expires_in: 900,
									},
									verify: {
										href: "https://1.1.1.1/lfs/verify",
										header: { Authorization: "Basic verify-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(new Response("upload-ok", { status: 200 }));

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: {
				"Content-Type": "application/vnd.git-lfs+json",
				Host: "attacker.example",
			},
			body: JSON.stringify({
				operation: "upload",
				ref: { name: "refs/heads/codex/full-git-proxy" },
				objects: [{ oid: "a".repeat(64), size: 1 }],
			}),
		});

		expect(response.status).toBe(200);
		expect(response.headers["cache-control"]).toBe("no-store");
		expect(response.body).not.toContain("upstream-lfs-secret");
		expect(response.body).not.toContain("verify-secret");
		expect(response.body).not.toContain("https://1.1.1.1");
		expect(response.body).not.toContain("attacker.example");

		const payload = JSON.parse(response.body) as {
			objects: Array<{
				actions: {
					upload: { href: string; header?: Record<string, string> };
					verify: { href: string; header?: Record<string, string> };
				};
			}>;
		};
		const uploadAction = payload.objects[0].actions.upload;
		const verifyAction = payload.objects[0].actions.verify;
		expect(uploadAction.href).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:${port}/__lfs/actions/`));
		expect(verifyAction.href).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:${port}/__lfs/actions/`));
		expect(uploadAction.header).toBeUndefined();
		expect(verifyAction.header).toBeUndefined();

		const uploadPath = new URL(uploadAction.href).pathname;
		const actionResponse = await request(port, uploadPath, {
			method: "PUT",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/octet-stream" },
			body: "lfs-bytes",
		});

		expect(actionResponse.status).toBe(200);
		expect(actionResponse.body).toBe("upload-ok");
		expect(getInstallationTokenMock).toHaveBeenCalledWith({
			repository: "owner/repo",
			contentsPermission: "write",
		});
		expect(fetchMock).toHaveBeenNthCalledWith(
			1,
			"https://github.com/owner/repo.git/info/lfs/objects/batch",
			expect.objectContaining({ method: "POST" }),
		);
		expect(fetchMock).toHaveBeenNthCalledWith(
			2,
			"https://1.1.1.1/lfs/upload/a",
			expect.objectContaining({
				method: "PUT",
				headers: expect.objectContaining({
					Authorization: "Basic upstream-lfs-secret",
					"X-Amz-Test": "stored-action-header",
					"content-type": "application/octet-stream",
				}),
				dispatcher: expect.any(Object),
			}),
		);
	});

	it("merges LFS action headers case-insensitively with stored action precedence", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									upload: {
										href: "https://1.1.1.1/lfs/upload/a",
										header: {
											Authorization: "Basic upstream-lfs-secret",
											"Content-Type": "application/vnd.git-lfs-stored",
										},
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(new Response("upload-ok", { status: 200 }));

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "upload",
				ref: { name: "refs/heads/codex/full-git-proxy" },
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { upload: { href: string } } }>;
		};
		const uploadPath = new URL(payload.objects[0].actions.upload.href).pathname;
		const actionResponse = await request(port, uploadPath, {
			method: "PUT",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/octet-stream" },
			body: "lfs-bytes",
		});

		expect(actionResponse.status).toBe(200);
		const forwarded = fetchMock.mock.calls[1]?.[1] as { headers?: Record<string, string> };
		const headerNames = Object.keys(forwarded.headers ?? {}).filter(
			(name) => name.toLowerCase() === "content-type",
		);
		expect(headerNames).toEqual(["Content-Type"]);
		expect(forwarded.headers?.["Content-Type"]).toBe("application/vnd.git-lfs-stored");
		expect(forwarded.headers?.["content-type"]).toBeUndefined();
	});

	it("retires completed LFS action handles so a max-size batch can reuse capacity", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									download: {
										href: "https://1.1.1.1/lfs/download/a",
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(new Response("download-ok", { status: 200 }));

		const firstBatchResponse = await request(
			port,
			"/github.com/owner/repo.git/info/lfs/objects/batch",
			{
				method: "POST",
				token: scopedToken(),
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
				body: JSON.stringify({
					operation: "download",
					objects: [{ oid: "a".repeat(64), size: 12 }],
				}),
			},
		);

		expect(firstBatchResponse.status).toBe(200);
		const firstPayload = JSON.parse(firstBatchResponse.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(firstPayload.objects[0].actions.download.href).pathname;
		const actionResponse = await request(port, actionPath, {
			method: "GET",
			token: scopedToken(),
		});

		expect(actionResponse.status).toBe(200);
		expect(actionResponse.body).toBe("download-ok");
		expect(fetchMock).toHaveBeenCalledTimes(2);

		const reuseResponse = await request(port, actionPath, {
			method: "GET",
			token: scopedToken(),
		});

		expect(reuseResponse.status).toBe(404);
		expect(fetchMock).toHaveBeenCalledTimes(2);

		const maxBatchObjects = lfsUploadBatchObjects(1_000);
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ objects: maxBatchObjects }), {
				status: 200,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
			}),
		);

		const maxBatchResponse = await request(
			port,
			"/github.com/owner/repo.git/info/lfs/objects/batch",
			{
				method: "POST",
				token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
				body: JSON.stringify({
					operation: "upload",
					ref: { name: "refs/heads/codex/full-git-proxy" },
					objects: maxBatchObjects.map(({ oid, size }) => ({ oid, size })),
				}),
			},
		);

		expect(maxBatchResponse.status).toBe(200);
		const maxPayload = JSON.parse(maxBatchResponse.body) as {
			objects: Array<{ actions: { upload: { href: string }; verify: { href: string } } }>;
		};
		expect(maxPayload.objects).toHaveLength(1_000);
		expect(maxPayload.objects[0].actions.upload.href).toMatch(
			new RegExp(`^http://127\\.0\\.0\\.1:${port}/__lfs/actions/`),
		);
		expect(maxPayload.objects[0].actions.verify.href).toMatch(
			new RegExp(`^http://127\\.0\\.0\\.1:${port}/__lfs/actions/`),
		);
		expect(fetchMock).toHaveBeenCalledTimes(3);
	});

	it("does not reclaim in-flight LFS action handles when checking store capacity", async () => {
		const sessionId = "lfs-in-flight-supersession-session";
		const token = scopedToken({
			sessionId,
			allowedRefs: ["refs/heads/codex/*"],
			deniedRefs: [],
		});
		const oid = "f".repeat(64);
		const size = 123;
		const uploadObject = {
			oid,
			size,
			actions: {
				upload: {
					href: "https://1.1.1.1/lfs/upload/in-flight",
					expires_in: 900,
				},
			},
		};
		const uploadBatchRequestBody = JSON.stringify({
			operation: "upload",
			ref: { name: "refs/heads/codex/full-git-proxy" },
			objects: [{ oid, size }],
		});
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ objects: [uploadObject] }), {
				status: 200,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
			}),
		);

		const firstBatchResponse = await request(
			port,
			"/github.com/owner/repo.git/info/lfs/objects/batch",
			{
				method: "POST",
				token,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
				body: uploadBatchRequestBody,
			},
		);

		expect(firstBatchResponse.status).toBe(200);
		const firstPayload = JSON.parse(firstBatchResponse.body) as {
			objects: Array<{ actions: { upload: { href: string } } }>;
		};
		const actionPath = new URL(firstPayload.objects[0].actions.upload.href).pathname;
		let finishActionFetch!: (response: Response) => void;
		const actionFetchStarted = new Promise<void>((resolve) => {
			fetchMock.mockImplementationOnce(
				() =>
					new Promise<Response>((finish) => {
						finishActionFetch = finish;
						resolve();
					}),
			);
		});
		const inFlightActionResponse = request(port, actionPath, {
			method: "PUT",
			token,
			headers: { "Content-Type": "application/octet-stream" },
			body: "lfs-bytes",
		});
		await actionFetchStarted;

		let actionResponse: Awaited<ReturnType<typeof request>> | null = null;
		try {
			async function addFillerBatch(count: number, offset: number): Promise<void> {
				const fillerObjects = lfsSingleActionBatchObjects(count, "download", "filler", 900, offset);
				fetchMock.mockResolvedValueOnce(
					new Response(JSON.stringify({ objects: fillerObjects }), {
						status: 200,
						headers: { "Content-Type": "application/vnd.git-lfs+json" },
					}),
				);
				const fillerResponse = await request(
					port,
					"/github.com/owner/repo.git/info/lfs/objects/batch",
					{
						method: "POST",
						token,
						headers: { "Content-Type": "application/vnd.git-lfs+json" },
						body: JSON.stringify({
							operation: "download",
							objects: fillerObjects.map((object) => ({
								oid: object.oid,
								size: object.size,
							})),
						}),
					},
				);
				expect(fillerResponse.status).toBe(200);
			}

			await addFillerBatch(1_000, 1_000);
			await addFillerBatch(999, 2_000);

			fetchMock.mockResolvedValueOnce(
				new Response(JSON.stringify({ objects: [uploadObject] }), {
					status: 200,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
				}),
			);
			const retryResponse = await request(
				port,
				"/github.com/owner/repo.git/info/lfs/objects/batch",
				{
					method: "POST",
					token,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
					body: uploadBatchRequestBody,
				},
			);

			expect(retryResponse.status).toBe(502);
			expect(retryResponse.body).toContain("invalid lfs batch response");
		} finally {
			finishActionFetch(new Response("upload-ok", { status: 200 }));
			actionResponse = await inFlightActionResponse;
		}
		expect(actionResponse.status).toBe(200);
		expect(actionResponse.body).toBe("upload-ok");
	}, 10_000);

	it("reclaims superseded verify handles when retrying a full upload batch", async () => {
		const sessionId = "lfs-full-upload-retry-session";
		const token = scopedToken({
			sessionId,
			allowedRefs: ["refs/heads/codex/*"],
			deniedRefs: [],
		});
		const maxBatchObjects = lfsUploadBatchObjects(1_000);
		const uploadBatchRequestBody = JSON.stringify({
			operation: "upload",
			ref: { name: "refs/heads/codex/full-git-proxy" },
			objects: maxBatchObjects.map(({ oid, size }) => ({ oid, size })),
		});
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ objects: maxBatchObjects }), {
				status: 200,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
			}),
		);

		const firstBatchResponse = await request(
			port,
			"/github.com/owner/repo.git/info/lfs/objects/batch",
			{
				method: "POST",
				token,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
				body: uploadBatchRequestBody,
			},
		);

		expect(firstBatchResponse.status).toBe(200);
		const firstPayload = JSON.parse(firstBatchResponse.body) as {
			objects: Array<{ actions: { upload: { href: string }; verify: { href: string } } }>;
		};
		const uploadPaths = firstPayload.objects.map(
			(object) => new URL(object.actions.upload.href).pathname,
		);
		const verifyPaths = firstPayload.objects.map(
			(object) => new URL(object.actions.verify.href).pathname,
		);
		await consumeLfsActionPaths(port, token, uploadPaths, "PUT");

		const verifyAttempts = new Map<string, number>();
		fetchMock.mockImplementation(async (url: string) => {
			if (url.includes("/lfs/verify/")) {
				const attempt = (verifyAttempts.get(url) ?? 0) + 1;
				verifyAttempts.set(url, attempt);
				return new Response(attempt < 6 ? "verify-retry" : "verify-ok", {
					status: attempt < 6 ? 429 : 200,
				});
			}
			return new Response("upstream-ok", { status: 200 });
		});
		await consumeLfsActionPaths(port, token, verifyPaths, "POST", 429);
		await consumeLfsActionPaths(port, token, verifyPaths, "POST", 429);
		await consumeLfsActionPaths(port, token, verifyPaths, "POST", 429);

		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ objects: maxBatchObjects }), {
				status: 200,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
			}),
		);

		const retryBatchResponse = await request(
			port,
			"/github.com/owner/repo.git/info/lfs/objects/batch",
			{
				method: "POST",
				token,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
				body: uploadBatchRequestBody,
			},
		);

		expect(retryBatchResponse.status).toBe(200);
		const retryPayload = JSON.parse(retryBatchResponse.body) as {
			objects: Array<{ actions: { upload: { href: string }; verify: { href: string } } }>;
		};
		expect(retryPayload.objects).toHaveLength(1_000);
		expect(retryPayload.objects[0].actions.upload.href).toMatch(
			new RegExp(`^http://127\\.0\\.0\\.1:${port}/__lfs/actions/`),
		);
		expect(retryPayload.objects[0].actions.verify.href).toMatch(
			new RegExp(`^http://127\\.0\\.0\\.1:${port}/__lfs/actions/`),
		);
		const retryUploadPaths = retryPayload.objects.map(
			(object) => new URL(object.actions.upload.href).pathname,
		);
		const retryVerifyPaths = retryPayload.objects.map(
			(object) => new URL(object.actions.verify.href).pathname,
		);
		await consumeLfsActionPaths(port, token, retryUploadPaths, "PUT");
		await consumeLfsActionPaths(port, token, retryVerifyPaths, "POST", 429);
		await consumeLfsActionPaths(port, token, retryVerifyPaths, "POST", 429);
		await consumeLfsActionPaths(port, token, retryVerifyPaths, "POST");
		expect(verifyAttempts.size).toBe(1_000);
		expect(Array.from(verifyAttempts.values()).every((attempts) => attempts === 6)).toBe(true);
		expect(fetchMock).toHaveBeenCalledTimes(8_002);
	}, 20_000);

	it("does not credit expired superseded handles when checking LFS action store capacity", async () => {
		const dateNow = vi.spyOn(Date, "now").mockReturnValue(0);
		try {
			const token = scopedToken({
				sessionId: "lfs-expired-supersession-capacity-session",
				allowedRefs: ["refs/heads/codex/*"],
				deniedRefs: [],
			});
			const liveDownloadObjects = lfsSingleActionBatchObjects(
				1_000,
				"download",
				"live",
				900,
				10_000,
			);
			fetchMock.mockResolvedValueOnce(
				new Response(JSON.stringify({ objects: liveDownloadObjects }), {
					status: 200,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
				}),
			);

			const liveResponse = await request(
				port,
				"/github.com/owner/repo.git/info/lfs/objects/batch",
				{
					method: "POST",
					token,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
					body: JSON.stringify({
						operation: "download",
						objects: liveDownloadObjects.map(({ oid, size }) => ({ oid, size })),
					}),
				},
			);
			expect(liveResponse.status).toBe(200);

			const expiringVerifyObjects = lfsSingleActionBatchObjects(1_000, "verify", "verify", 1);
			fetchMock.mockResolvedValueOnce(
				new Response(JSON.stringify({ objects: expiringVerifyObjects }), {
					status: 200,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
				}),
			);

			const expiringResponse = await request(
				port,
				"/github.com/owner/repo.git/info/lfs/objects/batch",
				{
					method: "POST",
					token,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
					body: JSON.stringify({
						operation: "upload",
						ref: { name: "refs/heads/codex/full-git-proxy" },
						objects: expiringVerifyObjects.map(({ oid, size }) => ({ oid, size })),
					}),
				},
			);
			expect(expiringResponse.status).toBe(200);

			let retryClockCalls = 0;
			dateNow.mockImplementation(() => {
				retryClockCalls += 1;
				return retryClockCalls < 100 ? 0 : 2_000;
			});
			const retryObjects = lfsUploadBatchObjects(1_000);
			fetchMock.mockResolvedValueOnce(
				new Response(JSON.stringify({ objects: retryObjects }), {
					status: 200,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
				}),
			);

			const retryResponse = await request(
				port,
				"/github.com/owner/repo.git/info/lfs/objects/batch",
				{
					method: "POST",
					token,
					headers: { "Content-Type": "application/vnd.git-lfs+json" },
					body: JSON.stringify({
						operation: "upload",
						ref: { name: "refs/heads/codex/full-git-proxy" },
						objects: retryObjects.map(({ oid, size }) => ({ oid, size })),
					}),
				},
			);

			expect(retryResponse.status).toBe(502);
			expect(retryResponse.body).toContain("invalid lfs batch response");
		} finally {
			dateNow.mockRestore();
		}
	});

	it("uses a separate LFS action rate budget above the default session request limit", async () => {
		const sessionId = "lfs-action-rate-budget-session";
		const batchObjects = Array.from({ length: 61 }, (_, index) => ({
			oid: index.toString(16).padStart(64, "0"),
			size: index + 1,
			actions: {
				download: {
					href: `https://1.1.1.1/lfs/download/${index}`,
					expires_in: 900,
				},
			},
		}));
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ objects: batchObjects }), {
				status: 200,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
			}),
		);

		const token = scopedToken({ sessionId });
		const batchResponse = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token,
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: batchObjects.map(({ oid, size }) => ({ oid, size })),
			}),
		});

		expect(batchResponse.status).toBe(200);
		const payload = JSON.parse(batchResponse.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		expect(payload.objects).toHaveLength(61);

		for (const object of payload.objects) {
			const actionPath = new URL(object.actions.download.href).pathname;
			const actionResponse = await request(port, actionPath, {
				method: "GET",
				token,
			});

			expect(actionResponse.status).toBe(200);
		}

		expect(fetchMock).toHaveBeenCalledTimes(62);
	});

	it("rejects oversized upstream LFS batch responses before parsing", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response("x".repeat(4 * 1024 * 1024 + 1), {
				status: 200,
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
			}),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("cancels upstream LFS batch bodies rejected by content length", async () => {
		const oversized = redirectResponseWithCancel(200, {
			"Content-Type": "application/vnd.git-lfs+json",
			"Content-Length": String(4 * 1024 * 1024 + 1),
		});
		fetchMock.mockResolvedValueOnce(oversized.response);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(oversized.cancel).toHaveBeenCalledTimes(1);
	});

	it("rejects upstream LFS batch responses with too many objects", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: Array.from({ length: 1001 }, (_, index) => ({
						oid: String(index).padStart(64, "a"),
						size: 12,
					})),
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects malformed upstream LFS action header names without normalizing them", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://1.1.1.1/lfs/download/a",
									header: { " Authorization": "Basic upstream-lfs-secret" },
									expires_in: 900,
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(response.body).not.toContain("upstream-lfs-secret");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects invalid upstream LFS action header values before storing them", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://1.1.1.1/lfs/download/a",
									header: { Authorization: "Basic upstream-lfs-secret\u0000" },
									expires_in: 900,
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(response.body).not.toContain("upstream-lfs-secret");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects duplicate upstream LFS action header names after case folding", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://1.1.1.1/lfs/download/a",
									header: {
										Authorization: "Basic first-secret",
										authorization: "Basic second-secret",
									},
									expires_in: 900,
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(response.body).not.toContain("first-secret");
		expect(response.body).not.toContain("second-secret");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("requires a scoped session token for mediated LFS action URLs", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://1.1.1.1/lfs/download/a",
									header: { Authorization: "Basic upstream-lfs-secret" },
									expires_in: 900,
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(200);
		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.download.href).pathname;
		const actionResponse = await request(port, actionPath, { method: "GET" });

		expect(actionResponse.status).toBe(401);
		expect(actionResponse.body).toContain("missing session token");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("mediates LFS download actions without forwarding runtime-supplied auth", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									download: {
										href: "https://1.1.1.1/lfs/download/a",
										header: {
											Authorization: "Basic upstream-lfs-secret",
											"Content-Length": "999",
											"X-Telclaude-Session": "upstream-supplied-session",
										},
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(
				new Response("lfs-bytes", {
					status: 206,
					headers: { "Content-Type": "application/octet-stream" },
				}),
			);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.download.href).pathname;
		const actionResponse = await request(port, actionPath, {
			method: "GET",
			token: scopedToken(),
			headers: {
				Authorization: "Bearer runtime-supplied-token",
				Range: "bytes=0-3",
				Accept: "application/octet-stream",
			},
		});

		expect(actionResponse.status).toBe(206);
		expect(actionResponse.body).toBe("lfs-bytes");
		const forwarded = fetchMock.mock.calls[1]?.[1] as { headers?: Record<string, string> };
		expect(forwarded.headers).toMatchObject({
			Authorization: "Basic upstream-lfs-secret",
			range: "bytes=0-3",
			accept: "application/octet-stream",
		});
		expect(Object.values(forwarded.headers ?? {})).not.toContain("Bearer runtime-supplied-token");
		expect(Object.keys(forwarded.headers ?? {}).map((name) => name.toLowerCase())).not.toContain(
			"content-length",
		);
		expect(Object.values(forwarded.headers ?? {})).not.toContain("upstream-supplied-session");
	});

	it("retains download action handles after upstream 416 so Git LFS can retry", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "c".repeat(64),
								size: 12,
								actions: {
									download: {
										href: "https://1.1.1.1/lfs/download/range-retry",
										header: { Authorization: "Basic download-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(new Response("range-not-satisfiable", { status: 416 }))
			.mockResolvedValueOnce(new Response("download-ok", { status: 200 }));

		const token = scopedToken();
		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token,
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "c".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(200);
		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.download.href).pathname;
		const firstDownloadResponse = await request(port, actionPath, {
			method: "GET",
			token,
			headers: { Range: "bytes=12-" },
		});
		const secondDownloadResponse = await request(port, actionPath, {
			method: "GET",
			token,
		});
		const thirdDownloadResponse = await request(port, actionPath, {
			method: "GET",
			token,
		});

		expect(firstDownloadResponse.status).toBe(416);
		expect(firstDownloadResponse.body).toBe("range-not-satisfiable");
		expect(secondDownloadResponse.status).toBe(200);
		expect(secondDownloadResponse.body).toBe("download-ok");
		expect(thirdDownloadResponse.status).toBe(404);
		expect(fetchMock).toHaveBeenCalledTimes(3);
		expect(fetchMock).toHaveBeenNthCalledWith(
			2,
			"https://1.1.1.1/lfs/download/range-retry",
			expect.objectContaining({
				method: "GET",
				headers: expect.objectContaining({
					Authorization: "Basic download-secret",
					range: "bytes=12-",
				}),
			}),
		);
		expect(fetchMock).toHaveBeenNthCalledWith(
			3,
			"https://1.1.1.1/lfs/download/range-retry",
			expect.objectContaining({
				method: "GET",
				headers: expect.objectContaining({ Authorization: "Basic download-secret" }),
			}),
		);
	});

	it("retains verify action handles after failed upstream attempts so Git LFS can retry", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "b".repeat(64),
								size: 12,
								actions: {
									verify: {
										href: "https://1.1.1.1/lfs/verify/retry",
										header: { Authorization: "Basic verify-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(new Response("verify-temporary-failure", { status: 503 }))
			.mockResolvedValueOnce(new Response("verify-ok", { status: 200 }));

		const token = scopedToken({
			allowedRefs: ["refs/heads/codex/*"],
			deniedRefs: [],
		});
		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token,
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "upload",
				ref: { name: "refs/heads/codex/full-git-proxy" },
				objects: [{ oid: "b".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(200);
		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { verify: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.verify.href).pathname;
		const verifyBody = JSON.stringify({ oid: "b".repeat(64), size: 12 });
		const firstVerifyResponse = await request(port, actionPath, {
			method: "POST",
			token,
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: verifyBody,
		});
		const secondVerifyResponse = await request(port, actionPath, {
			method: "POST",
			token,
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: verifyBody,
		});
		const thirdVerifyResponse = await request(port, actionPath, {
			method: "POST",
			token,
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: verifyBody,
		});

		expect(firstVerifyResponse.status).toBe(503);
		expect(firstVerifyResponse.body).toBe("verify-temporary-failure");
		expect(secondVerifyResponse.status).toBe(200);
		expect(secondVerifyResponse.body).toBe("verify-ok");
		expect(thirdVerifyResponse.status).toBe(404);
		expect(fetchMock).toHaveBeenCalledTimes(3);
		expect(fetchMock).toHaveBeenNthCalledWith(
			2,
			"https://1.1.1.1/lfs/verify/retry",
			expect.objectContaining({
				method: "POST",
				headers: expect.objectContaining({ Authorization: "Basic verify-secret" }),
			}),
		);
		expect(fetchMock).toHaveBeenNthCalledWith(
			3,
			"https://1.1.1.1/lfs/verify/retry",
			expect.objectContaining({
				method: "POST",
				headers: expect.objectContaining({ Authorization: "Basic verify-secret" }),
			}),
		);
	});

	it("does not log stored LFS action auth when the action fetch throws", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									download: {
										href: "https://1.1.1.1/lfs/download/a?signature=secret",
										header: { Authorization: "Basic upstream-lfs-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockRejectedValueOnce(new Error("invalid header: Basic upstream-lfs-secret"));

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(200);
		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.download.href).pathname;
		const actionResponse = await request(port, actionPath, {
			method: "GET",
			token: scopedToken(),
		});

		expect(actionResponse.status).toBe(502);
		expect(actionResponse.body).not.toContain("upstream-lfs-secret");
		const errorLogText = JSON.stringify(loggerMock.error.mock.calls);
		expect(errorLogText).not.toContain("upstream-lfs-secret");
		expect(errorLogText).not.toContain("signature=secret");
		expect(errorLogText).toContain("https://1.1.1.1");
	});

	it("blocks mediated LFS action redirects and cancels the upstream body", async () => {
		const redirect = redirectResponseWithCancel(307, {
			Location: "https://objects.example.test/other?signature=secret",
		});
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									download: {
										href: "https://1.1.1.1/lfs/download/a?signature=secret",
										header: { Authorization: "Basic upstream-lfs-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(redirect.response);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.download.href).pathname;
		const actionResponse = await request(port, actionPath, {
			method: "GET",
			token: scopedToken(),
		});

		expect(actionResponse.status).toBe(502);
		expect(actionResponse.body).toContain("upstream redirect blocked");
		expect(actionResponse.headers.location).toBeUndefined();
		expect(redirect.cancel).toHaveBeenCalledTimes(1);
	});

	it("closes incomplete mediated LFS PUT bodies when upstream redirects", async () => {
		const redirect = redirectResponseWithCancel(307, {
			Location: "https://objects.example.test/other?signature=secret",
		});
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									upload: {
										href: "https://1.1.1.1/lfs/upload/a?signature=secret",
										header: { Authorization: "Basic upstream-lfs-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(redirect.response);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "upload",
				ref: { name: "refs/heads/codex/full-git-proxy" },
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { upload: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.upload.href).pathname;
		const actionResponse = await requestWithIncompleteBody(port, actionPath, {
			method: "PUT",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/octet-stream" },
			chunk: "partial-lfs",
			declaredLength: 2048,
		});

		expect(actionResponse.status).toBe(502);
		expect(actionResponse.body).toContain("upstream redirect blocked");
		expect(actionResponse.headers.connection).toBe("close");
		expect(actionResponse.headers.location).toBeUndefined();
		expect(actionResponse.socketClosed).toBe(true);
		expect(redirect.cancel).toHaveBeenCalledTimes(1);
	});

	it("closes incomplete mediated LFS PUT bodies after ordinary upstream responses", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									upload: {
										href: "https://1.1.1.1/lfs/upload/a",
										header: { Authorization: "Basic upstream-lfs-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(new Response("upload-ok", { status: 200 }));

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "upload",
				ref: { name: "refs/heads/codex/full-git-proxy" },
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { upload: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.upload.href).pathname;
		const actionResponse = await requestWithIncompleteBody(port, actionPath, {
			method: "PUT",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/octet-stream" },
			chunk: "partial-lfs",
			declaredLength: 2048,
		});

		expect(actionResponse.status).toBe(200);
		expect(actionResponse.body).toBe("upload-ok");
		expect(actionResponse.headers.connection).toBe("close");
		expect(actionResponse.socketClosed).toBe(true);
	});

	it("re-checks scoped policy before forwarding mediated LFS action URLs", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								upload: {
									href: "https://1.1.1.1/lfs/upload/a",
									header: { Authorization: "Basic upstream-lfs-secret" },
									expires_in: 900,
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "upload",
				ref: { name: "refs/heads/codex/full-git-proxy" },
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(200);
		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { upload: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.upload.href).pathname;
		const actionResponse = await request(port, actionPath, {
			method: "PUT",
			token: scopedToken({ permissions: ["fetch"] }),
			body: "lfs-bytes",
		});

		expect(actionResponse.status).toBe(403);
		expect(actionResponse.body).toContain("push is not allowed");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("binds mediated LFS action URLs to the session that created them", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://1.1.1.1/lfs/download/a",
									header: { Authorization: "Basic upstream-lfs-secret" },
									expires_in: 900,
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken({ sessionId: "creator-session" }),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(200);
		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.download.href).pathname;
		const actionResponse = await request(port, actionPath, {
			method: "GET",
			token: scopedToken({ sessionId: "different-session" }),
		});

		expect(actionResponse.status).toBe(403);
		expect(actionResponse.body).toContain("different session");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects private-network LFS action URLs from upstream batch responses", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://127.0.0.1/lfs/download/a",
									header: { Authorization: "Basic upstream-lfs-secret" },
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(response.body).not.toContain("upstream-lfs-secret");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects CGNAT LFS action URLs from upstream batch responses", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://100.64.0.1/lfs/download/a",
									header: { Authorization: "Basic upstream-lfs-secret" },
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(response.body).not.toContain("upstream-lfs-secret");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("mediates public bracketed IPv6 literal LFS action URLs", async () => {
		fetchMock
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						objects: [
							{
								oid: "a".repeat(64),
								size: 12,
								actions: {
									download: {
										href: "https://[2606:4700:4700::1111]/lfs/download/a",
										header: { Authorization: "Basic upstream-lfs-secret" },
										expires_in: 900,
									},
								},
							},
						],
					}),
					{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
				),
			)
			.mockResolvedValueOnce(new Response("ipv6-lfs-ok", { status: 200 }));

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(200);
		const payload = JSON.parse(response.body) as {
			objects: Array<{ actions: { download: { href: string } } }>;
		};
		const actionPath = new URL(payload.objects[0].actions.download.href).pathname;
		const actionResponse = await request(port, actionPath, {
			method: "GET",
			token: scopedToken(),
		});

		expect(actionResponse.status).toBe(200);
		expect(actionResponse.body).toBe("ipv6-lfs-ok");
		expect(fetchMock).toHaveBeenNthCalledWith(
			2,
			"https://[2606:4700:4700::1111]/lfs/download/a",
			expect.objectContaining({ dispatcher: expect.any(Object) }),
		);
	});

	it("rejects IPv4-compatible private bracketed IPv6 literal LFS action URLs", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://[::192.168.1.1]/lfs/download/a",
									header: { Authorization: "Basic upstream-lfs-secret" },
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(response.body).not.toContain("upstream-lfs-secret");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects IPv6 unspecified bracketed literal LFS action URLs", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					objects: [
						{
							oid: "a".repeat(64),
							size: 12,
							actions: {
								download: {
									href: "https://[::]/lfs/download/a",
									header: { Authorization: "Basic upstream-lfs-secret" },
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/vnd.git-lfs+json" } },
			),
		);

		const response = await request(port, "/github.com/owner/repo.git/info/lfs/objects/batch", {
			method: "POST",
			token: scopedToken(),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				operation: "download",
				objects: [{ oid: "a".repeat(64), size: 12 }],
			}),
		});

		expect(response.status).toBe(502);
		expect(response.body).toContain("invalid lfs batch response");
		expect(response.body).not.toContain("upstream-lfs-secret");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("rejects all LFS lock routes before GitHub auth", async () => {
		const cases = [
			{ method: "GET", path: "/github.com/owner/repo.git/info/lfs/locks" },
			{
				method: "POST",
				path: "/github.com/owner/repo.git/info/lfs/locks",
				body: JSON.stringify({
					path: "asset.bin",
					ref: { name: "refs/heads/codex/full-git-proxy" },
				}),
			},
			{
				method: "POST",
				path: "/github.com/owner/repo.git/info/lfs/locks/verify",
				body: JSON.stringify({ ref: { name: "refs/heads/codex/full-git-proxy" } }),
			},
			{
				method: "POST",
				path: "/github.com/owner/repo.git/info/lfs/locks/123/unlock",
				body: JSON.stringify({ ref: { name: "refs/heads/codex/full-git-proxy" } }),
			},
		];

		for (const item of cases) {
			const response = await request(port, item.path, {
				method: item.method,
				token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
				headers: { "Content-Type": "application/vnd.git-lfs+json" },
				...(item.body ? { body: item.body } : {}),
			});

			expect(response.status).toBe(501);
			expect(response.body).toContain("git lfs locking is disabled");
		}

		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects raw fragment delimiters before they can bypass LFS lock routing", async () => {
		const response = await request(port, "/github.com/owner/repo.git/info/lfs/locks#x", {
			method: "POST",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
			headers: { "Content-Type": "application/vnd.git-lfs+json" },
			body: JSON.stringify({
				path: "asset.bin",
				ref: { name: "refs/heads/codex/full-git-proxy" },
			}),
		});

		expect(response.status).toBe(400);
		expect(response.body).toContain("invalid git URL format");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects HEAD LFS lock routes before GitHub auth", async () => {
		const response = await request(port, "/github.com/owner/repo.git/info/lfs/locks", {
			method: "HEAD",
			token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
		});

		expect(response.status).toBe(501);
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("closes sockets for pre-body rejections with incomplete request bodies", async () => {
		const cases = [
			{
				path: "/github.com/owner/repo.git/git-receive-pack",
				status: 401,
				body: "missing session token",
			},
			{
				path: "/github.com/owner/repo.git/info/lfs/locks",
				token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
				status: 501,
				body: "git lfs locking is disabled",
			},
			{
				path: "/github.com/owner/repo.git/custom",
				token: scopedToken(),
				status: 403,
				body: "unknown git operation",
			},
		];

		for (const item of cases) {
			const response = await requestWithIncompleteBody(port, item.path, {
				method: "POST",
				...(item.token ? { token: item.token } : {}),
				headers: { "Content-Type": "application/octet-stream" },
				chunk: "partial-body",
				declaredLength: 2048,
			});

			expect(response.status).toBe(item.status);
			expect(response.body).toContain(item.body);
			expect(response.headers.connection).toBe("close");
			expect(response.socketClosed).toBe(true);
		}

		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects unknown POST paths before GitHub auth", async () => {
		const response = await request(port, "/github.com/owner/repo.git/custom", {
			method: "POST",
			token: scopedToken(),
			body: "body",
		});

		expect(response.status).toBe(403);
		expect(response.body).toContain("unknown git operation");
		expect(getInstallationTokenMock).not.toHaveBeenCalled();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks upstream redirects without forwarding Location", async () => {
		const redirect = redirectResponseWithCancel(302, {
			Location: "https://github.com/owner/repo.git/info/lfs/objects/secret",
		});
		fetchMock.mockResolvedValueOnce(redirect.response);

		const response = await request(
			port,
			"/github.com/owner/repo.git/info/refs?service=git-upload-pack",
			{ token: scopedToken() },
		);

		expect(response.status).toBe(502);
		expect(response.body).toContain("upstream redirect blocked");
		expect(response.headers.location).toBeUndefined();
		expect(redirect.cancel).toHaveBeenCalledTimes(1);
	});

	it("closes incomplete receive-pack bodies when upstream redirects", async () => {
		const zero = "0".repeat(40);
		const commit = "1".repeat(40);
		const bodyPrefix = receivePackBody([
			{ oldId: zero, newId: commit, ref: "refs/heads/codex/full-git-proxy" },
		]);
		const redirect = redirectResponseWithCancel(302, {
			Location: "https://github.com/owner/repo.git/info/lfs/objects/secret",
		});
		fetchMock.mockResolvedValueOnce(redirect.response);

		const response = await requestWithIncompleteBody(
			port,
			"/github.com/owner/repo.git/git-receive-pack",
			{
				method: "POST",
				token: scopedToken({ allowedRefs: ["refs/heads/codex/*"], deniedRefs: [] }),
				headers: { "Content-Type": "application/x-git-receive-pack-request" },
				chunk: bodyPrefix,
				declaredLength: bodyPrefix.byteLength + 2048,
			},
		);

		expect(response.status).toBe(502);
		expect(response.body).toContain("upstream redirect blocked");
		expect(response.headers.connection).toBe("close");
		expect(response.headers.location).toBeUndefined();
		expect(response.socketClosed).toBe(true);
		expect(redirect.cancel).toHaveBeenCalledTimes(1);
	});

	it("closes incomplete Smart HTTP request bodies after ordinary upstream responses", async () => {
		fetchMock.mockResolvedValueOnce(new Response("upload-pack-ok", { status: 200 }));

		const response = await requestWithIncompleteBody(
			port,
			"/github.com/owner/repo.git/git-upload-pack",
			{
				method: "POST",
				token: scopedToken(),
				headers: { "Content-Type": "application/x-git-upload-pack-request" },
				chunk: "partial-upload-pack",
				declaredLength: 2048,
			},
		);

		expect(response.status).toBe(200);
		expect(response.body).toBe("upload-pack-ok");
		expect(response.headers.connection).toBe("close");
		expect(response.socketClosed).toBe(true);
	});
});
