/**
 * Git Proxy Server
 *
 * Transparent proxy for git operations that keeps credentials outside the agent container.
 * Agent's git is configured to route through this proxy, which adds authentication
 * before forwarding requests to GitHub.
 *
 * Architecture:
 * - Agent git → http://relay:8791/github.com/owner/repo.git/...
 * - Proxy validates session token, adds GitHub App token, forwards to GitHub
 * - Agent NEVER sees the real GitHub token
 *
 * Supported git operations:
 * - GET  /{host}/{owner}/{repo}.git/info/refs?service=git-upload-pack (clone/fetch discovery)
 * - GET  /{host}/{owner}/{repo}.git/info/refs?service=git-receive-pack (push discovery)
 * - POST /{host}/{owner}/{repo}.git/git-upload-pack (clone/fetch)
 * - POST /{host}/{owner}/{repo}.git/git-receive-pack (push)
 */

import { randomBytes } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { Agent } from "undici";

import { getChildLogger } from "../logging.js";
import { createPinnedLookup } from "../sandbox/fetch-guard.js";
import { getSandboxMode } from "../sandbox/index.js";
import { cachedDNSLookup, isBlockedIP, isNonOverridableBlock } from "../sandbox/network-proxy.js";
import { getGitHubAppIdentity, getInstallationToken } from "../services/github-app.js";
import {
	GIT_PROXY_TOKEN_PREFIX,
	type GitProxyPermission,
	type GitProxyTokenPolicy,
	type SessionTokenPayload,
	validateSessionTokenV3,
	verifyGitProxyToken,
} from "./git-proxy-auth.js";
import { DEFAULT_GIT_PROXY_TOKEN_POLICY, resolveGitProxyTokenPolicy } from "./git-proxy-policy.js";
import { forwardResponseHeaders } from "./proxy-headers.js";
import { SlidingWindowRateLimiter } from "./shared-rate-limiter.js";
import { getPublicKey } from "./token-manager.js";

const logger = getChildLogger({ module: "git-proxy" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface GitProxyConfig {
	port: number;
	host: string;
	allowedHosts: string[];
	rateLimitPerMinute: number;
	lfsActionRateLimitPerMinute: number;
	tokenSecret?: string;
	publicUrl?: string;
	defaultPolicy: GitProxyTokenPolicy;
}

interface ParsedGitUrl {
	host: string;
	owner: string;
	repo: string;
	path: string; // e.g., /info/refs, /git-upload-pack
	repository: string;
}

interface GitOperation {
	type: GitProxyPermission | "unknown";
	repo: string;
	service?: string;
}

export interface ReceivePackCommand {
	oldId: string;
	newId: string;
	ref: string;
}

export interface LfsBatchOperation {
	type: GitProxyPermission;
	ref?: string;
}

type LfsActionKind = "download" | "upload" | "verify";

interface LfsActionRecord {
	id: string;
	action: LfsActionKind;
	sessionId: string;
	repository: string;
	operation: GitProxyPermission;
	ref?: string;
	objectOid?: string;
	objectSize?: number;
	href: string;
	headers: Record<string, string>;
	expiresAtMs: number;
	inFlight: boolean;
}

interface PreparedLfsActionRewrite {
	id: string;
	record: LfsActionRecord;
	actionKind: LfsActionKind;
	actions: Record<string, unknown>;
	rewritten: Record<string, unknown>;
}

interface ValidatedLfsActionTarget {
	target: URL;
	hostname: string;
	addresses: string[];
}

type GitProxySession = SessionTokenPayload & GitProxyTokenPolicy;

// ═══════════════════════════════════════════════════════════════════════════════
// Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════════

const rateLimiter = new SlidingWindowRateLimiter();
rateLimiter.startCleanup();
const lfsActionRateLimiter = new SlidingWindowRateLimiter();
lfsActionRateLimiter.startCleanup();

const LFS_ACTION_PATH_PREFIX = "/__lfs/actions/";
const LFS_ACTION_DEFAULT_TTL_MS = 15 * 60 * 1000;
const LFS_ACTION_MAX_TTL_MS = 60 * 60 * 1000;
const LFS_ACTION_ID_BYTES = 24;
const LFS_ACTION_STORE_MAX_ENTRIES = 2_000;
const LFS_BATCH_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;
const LFS_BATCH_OBJECT_MAX_COUNT = 1_000;
const LFS_BATCH_ACTION_MAX_COUNT = 2_000;
// Supports a failed max upload/verify cycle plus a full retry with default verify retries.
const LFS_ACTION_RATE_LIMIT_PER_MINUTE = 8 * LFS_BATCH_OBJECT_MAX_COUNT;
const lfsActionStore = new Map<string, LfsActionRecord>();
let activeGitProxyServerCount = 0;

// ═══════════════════════════════════════════════════════════════════════════════
// URL Parsing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Parse a git proxy URL into components.
 * Input: /github.com/owner/repo.git/info/refs
 * Output: { host: "github.com", owner: "owner", repo: "repo", path: "/info/refs" }
 */
// Allowed upstream hosts - prevents SSRF by restricting to known git hosts
const ALLOWED_GIT_HOSTS = new Set(["github.com"]);
const SAFE_GITHUB_SEGMENT = /^[A-Za-z0-9_.-]+$/;

function isSafeGitHubSegment(segment: string): boolean {
	return SAFE_GITHUB_SEGMENT.test(segment) && segment !== "." && segment !== "..";
}

function hasUnsafeGitRoute(route: string): boolean {
	if (!route.startsWith("/")) return true;
	if (route.includes("%") || route.includes("#") || route.includes("\\") || route.includes("//")) {
		return true;
	}
	return route.split("/").some((segment) => segment === "." || segment === "..");
}

function parseGitUrl(url: string): ParsedGitUrl | null {
	// Remove query string for parsing, but preserve for path
	const queryStart = url.indexOf("?");
	const pathPart = queryStart >= 0 ? url.slice(0, queryStart) : url;
	const query = queryStart >= 0 ? url.slice(queryStart) : "";

	// Expected format: /{host}/{owner}/{repo}.git/{git-path}
	// e.g., /github.com/avivsinai/telclaude.git/info/refs
	const match = pathPart.match(/^\/([^/]+)\/([^/]+)\/([^/]+?)(\.git)?(\/.*)$/);
	if (!match) {
		return null;
	}

	const [, host, owner, repo, , gitPath] = match;
	const normalizedHost = host.toLowerCase();
	const normalizedRepo = repo.replace(/\.git$/, "");

	// SECURITY: Validate host against allowlist to prevent SSRF
	if (!ALLOWED_GIT_HOSTS.has(normalizedHost)) {
		logger.warn({ host, url }, "git proxy: blocked request to non-allowed host");
		return null;
	}
	if (!isSafeGitHubSegment(owner) || !isSafeGitHubSegment(normalizedRepo)) {
		logger.warn({ owner, repo: normalizedRepo }, "git proxy: invalid repository path");
		return null;
	}
	if (hasUnsafeGitRoute(gitPath)) {
		logger.warn({ path: gitPath }, "git proxy: unsafe git route");
		return null;
	}

	return {
		host: normalizedHost,
		owner,
		repo: normalizedRepo,
		path: gitPath + query,
		repository: `${owner}/${normalizedRepo}`,
	};
}

function splitRouteAndQuery(path: string): { route: string; query: string } {
	const queryStart = path.indexOf("?");
	return {
		route: queryStart >= 0 ? path.slice(0, queryStart) : path,
		query: queryStart >= 0 ? path.slice(queryStart + 1) : "",
	};
}

function getGitService(path: string): "upload-pack" | "receive-pack" | undefined {
	const { query } = splitRouteAndQuery(path);
	if (!query) return undefined;
	const service = new URLSearchParams(query).get("service");
	if (service === "git-upload-pack") return "upload-pack";
	if (service === "git-receive-pack") return "receive-pack";
	return undefined;
}

/**
 * Determine the git operation type from the request.
 */
function getGitOperation(_method: string, path: string, url: string): GitOperation {
	const parsed = parseGitUrl(url);
	const repo = parsed ? parsed.repository : "unknown";
	const method = _method.toUpperCase();
	const route = splitRouteAndQuery(path).route;
	const service = getGitService(path);

	if (route === "/git-upload-pack") {
		return { type: "fetch", repo, service: "upload-pack" };
	}
	if (route === "/git-receive-pack") {
		return { type: "push", repo, service: "receive-pack" };
	}
	if (route === "/info/refs") {
		return {
			type: service === "receive-pack" ? "push" : "fetch",
			repo,
			service,
		};
	}
	const lfsLockOperation = getLfsLockOperation(method, path);
	if (lfsLockOperation) {
		return { type: lfsLockOperation, repo, service: "lfs-locks" };
	}

	if (method === "POST") {
		return { type: "unknown", repo };
	}
	return { type: "fetch", repo };
}

function getLfsLockOperation(method: string, path: string): GitProxyPermission | null {
	const route = splitRouteAndQuery(path).route;
	if (
		route !== "/info/lfs/locks" &&
		route !== "/info/lfs/locks/verify" &&
		!/^\/info\/lfs\/locks\/[^/]+\/unlock$/.test(route)
	) {
		return null;
	}
	return method === "GET" || method === "HEAD" ? "fetch" : "push";
}

function matchesPattern(value: string, pattern: string): boolean {
	if (pattern === "*" || pattern === "*/*") return true;
	if (pattern.endsWith("/*")) {
		return value.startsWith(pattern.slice(0, -1));
	}
	return value === pattern;
}

function matchesAnyPattern(value: string, patterns: string[]): boolean {
	return patterns.some((pattern) => matchesPattern(value, pattern));
}

function authorizeRepository(
	repository: string,
	policy: GitProxyTokenPolicy,
): { ok: true } | { ok: false; reason: string } {
	if (matchesAnyPattern(repository, policy.repositories)) return { ok: true };
	return { ok: false, reason: "repository is not allowed by git proxy policy" };
}

function authorizeOperation(
	parsed: ParsedGitUrl,
	operation: GitOperation,
	policy: GitProxyTokenPolicy,
): { ok: true } | { ok: false; reason: string } {
	const repoAuth = authorizeRepository(parsed.repository, policy);
	if (!repoAuth.ok) return repoAuth;
	if (operation.type === "unknown") return { ok: false, reason: "unknown git operation" };
	if (policy.permissions.includes(operation.type)) return { ok: true };
	return { ok: false, reason: `${operation.type} is not allowed by git proxy policy` };
}

export function authorizeReceivePackCommands(
	commands: ReceivePackCommand[],
	policy: Pick<GitProxyTokenPolicy, "permissions" | "allowedRefs" | "deniedRefs" | "repositories">,
): { ok: true } | { ok: false; reason: string } {
	return authorizePushRefs(
		commands.map((command) => command.ref),
		policy,
		"receive-pack request did not include ref updates",
	);
}

export function authorizePushRefs(
	refs: string[],
	policy: Pick<GitProxyTokenPolicy, "permissions" | "allowedRefs" | "deniedRefs" | "repositories">,
	emptyReason = "push request did not include refs",
): { ok: true } | { ok: false; reason: string } {
	if (!policy.permissions.includes("push")) {
		return { ok: false, reason: "push is not allowed by git proxy policy" };
	}
	if (refs.length === 0) {
		return { ok: false, reason: emptyReason };
	}
	for (const ref of refs) {
		if (matchesAnyPattern(ref, policy.deniedRefs)) {
			return { ok: false, reason: "push ref is denied by git proxy policy" };
		}
		if (!matchesAnyPattern(ref, policy.allowedRefs)) {
			return { ok: false, reason: "push ref is not allowed by git proxy policy" };
		}
	}
	return { ok: true };
}

function parsePktLineLength(buffer: Buffer, offset: number): number | null {
	if (offset + 4 > buffer.length) return null;
	const raw = buffer.subarray(offset, offset + 4).toString("ascii");
	if (!/^[0-9a-fA-F]{4}$/.test(raw)) {
		throw new Error("invalid pkt-line length");
	}
	return Number.parseInt(raw, 16);
}

const oidPattern = /^[0-9a-fA-F]{40,64}$/;

function receivePackLineText(payload: Buffer): string {
	const nul = payload.indexOf(0);
	const commandBytes = nul >= 0 ? payload.subarray(0, nul) : payload;
	return commandBytes.toString("utf8").replace(/\n$/, "");
}

function parseReceivePackPayload(payload: Buffer): ReceivePackCommand {
	const commandText = receivePackLineText(payload);
	const parts = commandText.split(" ");
	if (parts.length !== 3) {
		throw new Error("invalid receive-pack command");
	}
	const [oldId, newId, ref] = parts as [string, string, string];
	if (!oidPattern.test(oldId) || !oidPattern.test(newId) || !isValidGitRefName(ref)) {
		throw new Error("invalid receive-pack command");
	}
	return { oldId, newId, ref };
}

function isValidShallowLine(payload: Buffer): boolean {
	const text = receivePackLineText(payload);
	const [, oid] = text.match(/^shallow ([0-9a-fA-F]{40,64})$/) ?? [];
	return Boolean(oid);
}

export function parseReceivePackCommands(buffer: Buffer): {
	complete: boolean;
	commands: ReceivePackCommand[];
} {
	const commands: ReceivePackCommand[] = [];
	let offset = 0;

	while (offset < buffer.length) {
		const length = parsePktLineLength(buffer, offset);
		if (length === null) return { complete: false, commands };
		if (length === 0) {
			return { complete: true, commands };
		}
		if (length < 4) throw new Error("invalid pkt-line length");
		if (offset + length > buffer.length) return { complete: false, commands };
		const payload = buffer.subarray(offset + 4, offset + length);
		const line = receivePackLineText(payload);
		if (line.startsWith("shallow ")) {
			if (!isValidShallowLine(payload)) throw new Error("invalid shallow line");
		} else if (line === "push-cert") {
			throw new Error("receive-pack push certificates are not supported");
		} else {
			commands.push(parseReceivePackPayload(payload));
		}
		offset += length;
	}

	return { complete: false, commands };
}

const RECEIVE_PACK_PREFIX_LIMIT_BYTES = 1024 * 1024;
const RECEIVE_PACK_FLUSH_PACKET = Buffer.from("0000", "utf8");

function createReceivePackBody(
	chunks: Buffer[],
	iterator: AsyncIterableIterator<Buffer>,
): Readable {
	return Readable.from(
		(async function* () {
			for (const buffered of chunks) yield buffered;
			while (true) {
				const remaining = await iterator.next();
				if (remaining.done) return;
				yield remaining.value;
			}
		})(),
	);
}

function parseContentLength(req: http.IncomingMessage): number | null {
	const raw = req.headers["content-length"];
	if (raw === undefined) return null;
	if (Array.isArray(raw) || !/^\d+$/.test(raw)) {
		throw new Error("invalid content-length");
	}
	return Number(raw);
}

async function prepareChunkedFlushOnlyProbeBody(
	iterator: AsyncIterableIterator<Buffer>,
	buffered: Buffer,
): Promise<Readable> {
	while (true) {
		const remaining = await iterator.next();
		if (remaining.done) return Readable.from([buffered]);
		const buffer = Buffer.isBuffer(remaining.value)
			? remaining.value
			: Buffer.from(remaining.value);
		if (buffer.byteLength > 0) {
			throw new Error("receive-pack flush-only probe included extra bytes");
		}
	}
}

async function prepareReceivePackBody(req: http.IncomingMessage): Promise<{
	body: Readable;
	commands: ReceivePackCommand[];
	isFlushOnlyProbe: boolean;
}> {
	const iterator = req.iterator({ destroyOnReturn: false }) as AsyncIterableIterator<Buffer>;
	const chunks: Buffer[] = [];
	let bufferedBytes = 0;

	while (true) {
		const next = await iterator.next();
		if (next.done) break;

		const chunk = next.value;
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		chunks.push(buffer);
		bufferedBytes += buffer.byteLength;
		if (bufferedBytes > RECEIVE_PACK_PREFIX_LIMIT_BYTES) {
			throw new Error("receive-pack command prefix too large");
		}

		const parsed = parseReceivePackCommands(Buffer.concat(chunks, bufferedBytes));
		if (parsed.complete) {
			const buffered = Buffer.concat(chunks, bufferedBytes);
			if (parsed.commands.length === 0) {
				if (!buffered.equals(RECEIVE_PACK_FLUSH_PACKET)) {
					throw new Error("receive-pack empty command list must be exact flush packet");
				}
				const contentLength = parseContentLength(req);
				if (contentLength !== null) {
					if (contentLength !== RECEIVE_PACK_FLUSH_PACKET.byteLength) {
						throw new Error("receive-pack empty command list must be exact flush packet");
					}
					return {
						body: createReceivePackBody(chunks, iterator),
						commands: parsed.commands,
						isFlushOnlyProbe: true,
					};
				}
				return {
					body: await prepareChunkedFlushOnlyProbeBody(iterator, buffered),
					commands: parsed.commands,
					isFlushOnlyProbe: true,
				};
			}
			return {
				body: createReceivePackBody(chunks, iterator),
				commands: parsed.commands,
				isFlushOnlyProbe: false,
			};
		}
	}

	throw new Error("receive-pack command list did not complete");
}

function isValidGitRefName(value: unknown): value is string {
	if (typeof value !== "string") return false;
	if (!/^refs\/[A-Za-z0-9._/-]+$/.test(value)) return false;
	if (value.includes("..") || value.endsWith("/") || value.endsWith(".lock")) return false;
	return true;
}

export function parseLfsBatchOperation(buffer: Buffer): LfsBatchOperation {
	const parsed = JSON.parse(buffer.toString("utf8")) as {
		operation?: unknown;
		ref?: { name?: unknown } | null;
	};
	if (parsed.operation !== "download" && parsed.operation !== "upload") {
		throw new Error("invalid lfs batch operation");
	}
	const ref = parsed.ref?.name;
	if (ref !== undefined && !isValidGitRefName(ref)) {
		throw new Error("invalid lfs batch ref");
	}
	return {
		type: parsed.operation === "upload" ? "push" : "fetch",
		...(typeof ref === "string" ? { ref } : {}),
	};
}

const LFS_BATCH_BODY_LIMIT_BYTES = 4 * 1024 * 1024;

async function prepareLfsBatchBody(req: http.IncomingMessage): Promise<{
	body: Readable;
	operation: LfsBatchOperation;
}> {
	const chunks: Buffer[] = [];
	let bufferedBytes = 0;
	for await (const chunk of req) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		chunks.push(buffer);
		bufferedBytes += buffer.byteLength;
		if (bufferedBytes > LFS_BATCH_BODY_LIMIT_BYTES) {
			throw new Error("lfs batch request body too large");
		}
	}
	const bodyBuffer = Buffer.concat(chunks, bufferedBytes);
	return {
		body: Readable.from(chunks),
		operation: parseLfsBatchOperation(bodyBuffer),
	};
}

function isLfsBatchPath(path: string): boolean {
	return path.split("?")[0] === "/info/lfs/objects/batch";
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isLfsActionKind(value: string): value is LfsActionKind {
	return value === "download" || value === "upload" || value === "verify";
}

function lfsActionOperation(action: LfsActionKind): GitProxyPermission {
	return action === "download" ? "fetch" : "push";
}

const EXCLUDED_LFS_ACTION_REQUEST_HEADERS = new Set([
	"authorization",
	"connection",
	"cookie",
	"host",
	"keep-alive",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"x-telclaude-session",
]);

const EXCLUDED_LFS_STORED_ACTION_HEADERS = new Set([
	"connection",
	"content-length",
	"cookie",
	"host",
	"keep-alive",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"x-telclaude-session",
]);

const FORWARDED_LFS_ACTION_CLIENT_HEADERS = new Set([
	"accept",
	"content-length",
	"content-range",
	"content-type",
	"range",
]);

function normalizeLfsActionHeaders(value: unknown): Record<string, string> {
	if (value === undefined || value === null) return Object.create(null) as Record<string, string>;
	if (!isObjectRecord(value)) {
		throw new Error("invalid lfs action headers");
	}

	const headers = Object.create(null) as Record<string, string>;
	const seenHeaderNames = new Set<string>();
	for (const [rawName, rawValue] of Object.entries(value)) {
		if (typeof rawValue !== "string") {
			throw new Error("invalid lfs action header value");
		}
		if (rawName !== rawName.trim()) {
			throw new Error("invalid lfs action header name");
		}
		const lowerName = rawName.toLowerCase();
		if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(rawName)) {
			throw new Error("invalid lfs action header name");
		}
		try {
			http.validateHeaderName(rawName);
			http.validateHeaderValue(rawName, rawValue);
		} catch {
			throw new Error("invalid lfs action header");
		}
		if (seenHeaderNames.has(lowerName)) {
			throw new Error("duplicate lfs action header name");
		}
		seenHeaderNames.add(lowerName);
		if (EXCLUDED_LFS_STORED_ACTION_HEADERS.has(lowerName)) continue;
		headers[rawName] = rawValue;
	}
	return headers;
}

async function validateLfsActionTarget(href: string): Promise<ValidatedLfsActionTarget> {
	let target: URL;
	try {
		target = new URL(href);
	} catch {
		throw new Error("invalid lfs action href");
	}

	if (target.protocol !== "https:") {
		throw new Error("lfs action href must use https");
	}
	if (target.username || target.password) {
		throw new Error("lfs action href must not include credentials");
	}
	const port = target.port ? Number(target.port) : 443;
	if (port !== 443) {
		throw new Error("lfs action href must use port 443");
	}

	const hostname = normalizeUrlHostnameForIP(target.hostname);
	const addresses = net.isIP(hostname) ? [hostname] : await cachedDNSLookup(hostname);
	if (!addresses || addresses.length === 0) {
		throw new Error("lfs action href host did not resolve");
	}
	for (const address of addresses) {
		if (isNonOverridableBlock(address) || isBlockedIP(address)) {
			throw new Error("lfs action href resolves to a private or metadata address");
		}
	}

	return { target, hostname, addresses };
}

function normalizeUrlHostnameForIP(hostname: string): string {
	if (hostname.startsWith("[") && hostname.endsWith("]")) {
		return hostname.slice(1, -1);
	}
	return hostname;
}

function resolveLfsActionExpiresAt(action: Record<string, unknown>): number {
	const now = Date.now();
	const expiresAt = action.expires_at;
	if (typeof expiresAt === "string") {
		const parsed = Date.parse(expiresAt);
		if (Number.isFinite(parsed) && parsed > now) {
			return now + Math.min(parsed - now, LFS_ACTION_MAX_TTL_MS);
		}
	}

	const expiresIn = action.expires_in;
	if (typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0) {
		return now + Math.min(expiresIn * 1000, LFS_ACTION_MAX_TTL_MS);
	}

	return now + LFS_ACTION_DEFAULT_TTL_MS;
}

function normalizeProxyPublicOrigin(value: string): string {
	const parsed = new URL(value);
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new Error("git proxy public URL must use http or https");
	}
	if (parsed.username || parsed.password || parsed.search || parsed.hash) {
		throw new Error("git proxy public URL must not include credentials, query, or fragment");
	}
	if (parsed.pathname !== "/" && parsed.pathname !== "") {
		throw new Error("git proxy public URL must not include a path");
	}
	return parsed.origin;
}

function formatProxyOriginHost(host: string): string {
	if (host === "0.0.0.0" || host === "::") return "127.0.0.1";
	if (net.isIP(host) === 6 && !host.startsWith("[")) return `[${host}]`;
	return host;
}

function resolveProxyOrigin(config: GitProxyConfig, server: http.Server): string {
	if (config.publicUrl) return config.publicUrl;
	const address = server.address();
	if (typeof address === "object" && address) {
		const host = formatProxyOriginHost(config.host);
		return `http://${host}:${address.port}`;
	}
	return `http://${formatProxyOriginHost(config.host)}:${config.port}`;
}

function sweepExpiredLfsActions(now = Date.now()): void {
	for (const [id, record] of lfsActionStore) {
		if (!record.inFlight && record.expiresAtMs <= now) {
			lfsActionStore.delete(id);
		}
	}
}

function assertLfsActionStoreCapacity(supersededIds: Set<string>, createdCount: number): void {
	sweepExpiredLfsActions();
	let reclaimedCount = 0;
	for (const id of supersededIds) {
		if (lfsActionStore.has(id)) reclaimedCount += 1;
	}
	if (lfsActionStore.size - reclaimedCount + createdCount > LFS_ACTION_STORE_MAX_ENTRIES) {
		throw new Error("lfs action store capacity exceeded");
	}
}

async function readResponseTextWithLimit(response: Response, maxBytes: number): Promise<string> {
	const contentLength = response.headers.get("content-length");
	if (contentLength) {
		const parsed = Number(contentLength);
		if (Number.isFinite(parsed) && parsed > maxBytes) {
			await response.body?.cancel().catch(() => {});
			throw new Error("lfs batch response body too large");
		}
	}

	if (!response.body) return "";
	const reader = response.body.getReader();
	const chunks: Buffer[] = [];
	let total = 0;
	try {
		while (true) {
			const next = await reader.read();
			if (next.done) break;
			total += next.value.byteLength;
			if (total > maxBytes) {
				await reader.cancel().catch(() => {});
				throw new Error("lfs batch response body too large");
			}
			chunks.push(Buffer.from(next.value));
		}
	} finally {
		reader.releaseLock();
	}
	return Buffer.concat(chunks, total).toString("utf8");
}

function getLfsObjectIdentity(object: Record<string, unknown>): {
	objectOid?: string;
	objectSize?: number;
} {
	const oid = object.oid;
	const size = object.size;
	if (typeof oid !== "string" || oid.length === 0) return {};
	if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) return {};
	return { objectOid: oid, objectSize: size };
}

async function prepareLfsActionRewrite(
	actionKind: LfsActionKind,
	rawAction: unknown,
	context: {
		repository: string;
		sessionId: string;
		batchOperation: LfsBatchOperation;
		proxyOrigin: string;
		objectOid?: string;
		objectSize?: number;
	},
): Promise<{ id: string; record: LfsActionRecord; rewritten: Record<string, unknown> }> {
	if (!isObjectRecord(rawAction)) {
		throw new Error("invalid lfs action object");
	}
	const href = rawAction.href;
	if (typeof href !== "string") {
		throw new Error("invalid lfs action href");
	}

	const operation = lfsActionOperation(actionKind);
	if (operation !== context.batchOperation.type) {
		throw new Error("lfs action operation does not match batch operation");
	}

	const { target } = await validateLfsActionTarget(href);
	const id = randomBytes(LFS_ACTION_ID_BYTES).toString("base64url");
	const record: LfsActionRecord = {
		id,
		action: actionKind,
		sessionId: context.sessionId,
		repository: context.repository,
		operation,
		...(context.batchOperation.ref ? { ref: context.batchOperation.ref } : {}),
		...(context.objectOid ? { objectOid: context.objectOid } : {}),
		...(context.objectSize !== undefined ? { objectSize: context.objectSize } : {}),
		href: target.toString(),
		headers: normalizeLfsActionHeaders(rawAction.header),
		expiresAtMs: resolveLfsActionExpiresAt(rawAction),
		inFlight: false,
	};

	const rewritten: Record<string, unknown> = {
		...rawAction,
		href: `${context.proxyOrigin}${LFS_ACTION_PATH_PREFIX}${id}`,
	};
	delete rewritten.header;
	return { id, record, rewritten };
}

function hasSameLfsActionSupersessionKey(
	existing: LfsActionRecord,
	replacement: LfsActionRecord,
): boolean {
	if (!existing.objectOid || !replacement.objectOid) return false;
	if (existing.objectSize === undefined || replacement.objectSize === undefined) return false;
	return (
		existing.sessionId === replacement.sessionId &&
		existing.repository === replacement.repository &&
		existing.operation === replacement.operation &&
		existing.ref === replacement.ref &&
		existing.action === replacement.action &&
		existing.objectOid === replacement.objectOid &&
		existing.objectSize === replacement.objectSize
	);
}

function findSupersededLfsActionIds(replacements: LfsActionRecord[]): Set<string> {
	const superseded = new Set<string>();
	for (const [existingId, existing] of lfsActionStore) {
		if (
			!existing.inFlight &&
			replacements.some((replacement) => hasSameLfsActionSupersessionKey(existing, replacement))
		) {
			superseded.add(existingId);
		}
	}
	return superseded;
}

async function rewriteLfsBatchResponse(
	parsed: ParsedGitUrl,
	batchOperation: LfsBatchOperation,
	session: GitProxySession,
	proxyOrigin: string,
	rawBody: string,
): Promise<string> {
	const payload = JSON.parse(rawBody) as unknown;
	if (!isObjectRecord(payload) || !Array.isArray(payload.objects)) {
		throw new Error("invalid lfs batch response");
	}
	if (payload.objects.length > LFS_BATCH_OBJECT_MAX_COUNT) {
		throw new Error("lfs batch response has too many objects");
	}
	sweepExpiredLfsActions();
	const preparedActions: PreparedLfsActionRewrite[] = [];
	let actionCount = 0;

	for (const object of payload.objects) {
		if (!isObjectRecord(object)) continue;
		const actions = object.actions;
		if (actions === undefined) continue;
		if (!isObjectRecord(actions)) {
			throw new Error("invalid lfs object actions");
		}
		const objectIdentity = getLfsObjectIdentity(object);
		for (const [actionKind, rawAction] of Object.entries(actions)) {
			if (!isLfsActionKind(actionKind)) {
				throw new Error("unsupported lfs action");
			}
			actionCount += 1;
			if (actionCount > LFS_BATCH_ACTION_MAX_COUNT) {
				throw new Error("lfs batch response has too many actions");
			}
			preparedActions.push({
				...(await prepareLfsActionRewrite(actionKind, rawAction, {
					repository: parsed.repository,
					sessionId: session.sessionId,
					batchOperation,
					proxyOrigin,
					...objectIdentity,
				})),
				actionKind,
				actions,
			});
		}
	}

	const supersededIds = findSupersededLfsActionIds(
		preparedActions.map((prepared) => prepared.record),
	);
	assertLfsActionStoreCapacity(supersededIds, preparedActions.length);

	for (const prepared of preparedActions) {
		prepared.actions[prepared.actionKind] = prepared.rewritten;
	}
	const rewrittenBody = JSON.stringify(payload);

	for (const id of supersededIds) {
		lfsActionStore.delete(id);
	}
	for (const prepared of preparedActions) {
		lfsActionStore.set(prepared.id, prepared.record);
	}

	return rewrittenBody;
}

function parseLfsActionProxyPath(url: string): string | null {
	const route = url.split("?")[0];
	if (!route.startsWith(LFS_ACTION_PATH_PREFIX)) return null;
	const id = route.slice(LFS_ACTION_PATH_PREFIX.length);
	if (!/^[A-Za-z0-9_-]{16,}$/.test(id)) return null;
	return id;
}

function isAllowedLfsActionMethod(action: LfsActionKind, method: string): boolean {
	if (action === "download") return method === "GET" || method === "HEAD";
	if (action === "upload") return method === "PUT";
	return method === "POST";
}

function copyLfsActionClientHeaders(req: http.IncomingMessage): Record<string, string> {
	const headers: Record<string, string> = {};
	for (const [rawName, rawValue] of Object.entries(req.headers)) {
		const lowerName = rawName.toLowerCase();
		if (!FORWARDED_LFS_ACTION_CLIENT_HEADERS.has(lowerName)) continue;
		if (EXCLUDED_LFS_ACTION_REQUEST_HEADERS.has(lowerName)) continue;
		if (Array.isArray(rawValue)) {
			headers[rawName] = rawValue.join(", ");
		} else if (typeof rawValue === "string") {
			headers[rawName] = rawValue;
		}
	}
	return headers;
}

function setHeaderCaseInsensitive(
	headers: Record<string, string>,
	knownNames: Map<string, string>,
	name: string,
	value: string,
): void {
	const lowerName = name.toLowerCase();
	const previousName = knownNames.get(lowerName);
	if (previousName) {
		delete headers[previousName];
	}
	headers[name] = value;
	knownNames.set(lowerName, name);
}

function buildLfsActionRequestHeaders(
	storedHeaders: Record<string, string>,
	clientHeaders: Record<string, string>,
): Record<string, string> {
	const headers: Record<string, string> = {};
	const knownNames = new Map<string, string>();
	setHeaderCaseInsensitive(headers, knownNames, "User-Agent", "telclaude-git-proxy/1.0");
	for (const [name, value] of Object.entries(clientHeaders)) {
		setHeaderCaseInsensitive(headers, knownNames, name, value);
	}
	for (const [name, value] of Object.entries(storedHeaders)) {
		setHeaderCaseInsensitive(headers, knownNames, name, value);
	}
	return headers;
}

function buildGitHubAuthHeaders(
	req: http.IncomingMessage,
	host: string,
	token: string,
): Record<string, string> {
	const basicAuth = Buffer.from(`x-access-token:${token}`).toString("base64");
	const upstreamHeaders: Record<string, string> = {
		Host: host,
		"User-Agent": "telclaude-git-proxy/1.0",
		Authorization: `Basic ${basicAuth}`,
		"Accept-Encoding": "identity",
	};
	if (req.headers["content-type"]) {
		upstreamHeaders["Content-Type"] = req.headers["content-type"] as string;
	}
	if (req.headers["content-encoding"]) {
		upstreamHeaders["Content-Encoding"] = req.headers["content-encoding"] as string;
	}
	if (req.headers["content-length"]) {
		upstreamHeaders["Content-Length"] = req.headers["content-length"] as string;
	}
	if (req.headers.accept) {
		upstreamHeaders.Accept = req.headers.accept as string;
	}
	if (req.headers["git-protocol"]) {
		upstreamHeaders["Git-Protocol"] = req.headers["git-protocol"] as string;
	}
	return upstreamHeaders;
}

async function sendUpstreamResponse(
	upstreamResponse: Response,
	res: http.ServerResponse,
	extraHeaders: Record<string, string> = {},
	req?: http.IncomingMessage,
) {
	const closeIncompleteRequest = req ? !req.complete : false;
	forwardResponseHeaders(upstreamResponse, res);
	for (const [name, value] of Object.entries(extraHeaders)) {
		res.setHeader(name, value);
	}
	if (closeIncompleteRequest) {
		res.setHeader("Connection", "close");
	}
	res.writeHead(upstreamResponse.status);
	try {
		if (upstreamResponse.body) {
			const nodeStream = Readable.fromWeb(upstreamResponse.body);
			await pipeline(nodeStream, res);
		} else {
			res.end();
		}
	} finally {
		if (closeIncompleteRequest) {
			req?.destroy();
		}
	}
}

async function cancelUpstreamBody(upstreamResponse: Response): Promise<void> {
	if (!upstreamResponse.body) return;
	try {
		await upstreamResponse.body.cancel();
	} catch {
		// Best-effort cleanup before returning a locally generated response.
	}
}

function sendLocalPlainTextAndClose(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	status: number,
	message: string,
): void {
	res.writeHead(status, { "Content-Type": "text/plain", Connection: "close" });
	res.end(message, () => {
		req.destroy();
	});
}

function sendLocalJsonAndClose(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	status: number,
	payload: unknown,
): void {
	res.writeHead(status, { "Content-Type": "application/json", Connection: "close" });
	res.end(JSON.stringify(payload), () => {
		req.destroy();
	});
}

function rejectForbiddenAndClose(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	status: number,
	reason: string,
): void {
	sendLocalPlainTextAndClose(req, res, status, `Forbidden: ${reason}`);
}

function authorizeLfsActionRecord(
	record: LfsActionRecord,
	session: GitProxySession,
): { ok: true } | { ok: false; reason: string } {
	const repoAuth = authorizeRepository(record.repository, session);
	if (!repoAuth.ok) return repoAuth;
	if (record.sessionId !== session.sessionId) {
		return { ok: false, reason: "lfs action handle belongs to a different session" };
	}
	if (!session.permissions.includes(record.operation)) {
		return { ok: false, reason: `${record.operation} is not allowed by git proxy policy` };
	}
	if (record.operation === "push") {
		return authorizePushRefs(
			record.ref ? [record.ref] : [],
			session,
			"lfs action request did not include a ref",
		);
	}
	return { ok: true };
}

async function closeLfsActionAgent(agent: Agent | null): Promise<void> {
	if (!agent) return;
	try {
		await agent.close();
	} catch {
		// Best-effort cleanup after a streamed response.
	}
}

function describeLfsActionTargetForLog(href: string): { lfsActionOrigin: string } {
	try {
		return { lfsActionOrigin: new URL(href).origin };
	} catch {
		return { lfsActionOrigin: "invalid-url" };
	}
}

function describeErrorForLog(err: unknown): Record<string, string> {
	if (!err || typeof err !== "object") return { errorName: "NonError" };
	const shaped = err as { name?: unknown; code?: unknown };
	return {
		errorName: typeof shaped.name === "string" ? shaped.name : "Error",
		...(typeof shaped.code === "string" ? { errorCode: shaped.code } : {}),
	};
}

function shouldRetireLfsActionAfterResponse(action: LfsActionKind, status: number): boolean {
	if (action === "download" && status === 416) return false;
	return action !== "verify" || (status >= 200 && status < 300);
}

function shouldRetireLfsActionAfterFailedAttempt(action: LfsActionKind): boolean {
	return action !== "verify";
}

async function proxyLfsActionRequest(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	actionId: string,
	session: GitProxySession,
): Promise<void> {
	sweepExpiredLfsActions();
	const record = lfsActionStore.get(actionId);
	if (!record) {
		sendLocalPlainTextAndClose(
			req,
			res,
			404,
			"Not found: lfs action handle expired or does not exist",
		);
		return;
	}

	const method = (req.method ?? "GET").toUpperCase();
	if (!isAllowedLfsActionMethod(record.action, method)) {
		sendLocalPlainTextAndClose(req, res, 405, "Method not allowed");
		return;
	}

	const auth = authorizeLfsActionRecord(record, session);
	if (!auth.ok) {
		logger.warn(
			{
				sessionId: session.sessionId,
				action: record.action,
				reason: "lfs_action_policy_denied",
			},
			"git proxy lfs action blocked by policy",
		);
		rejectForbiddenAndClose(req, res, 403, auth.reason);
		return;
	}
	if (record.inFlight) {
		sendLocalPlainTextAndClose(req, res, 409, "Conflict: lfs action handle is already in use");
		return;
	}
	record.inFlight = true;

	const requestBody = method === "GET" || method === "HEAD" ? undefined : Readable.toWeb(req);
	const headers = buildLfsActionRequestHeaders(record.headers, copyLfsActionClientHeaders(req));
	let agent: Agent | null = null;
	let shouldRetireAction = false;

	try {
		const { hostname, addresses } = await validateLfsActionTarget(record.href);
		agent = new Agent({
			connect: { lookup: createPinnedLookup(hostname, addresses) },
		});
		shouldRetireAction = shouldRetireLfsActionAfterFailedAttempt(record.action);
		const upstreamResponse = await fetch(record.href, {
			method,
			headers,
			body: requestBody,
			duplex: "half",
			dispatcher: agent as never,
			redirect: "manual",
		});
		shouldRetireAction = shouldRetireLfsActionAfterResponse(record.action, upstreamResponse.status);
		if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
			logger.warn(
				{
					sessionId: session.sessionId,
					repository: record.repository,
					status: upstreamResponse.status,
				},
				"git proxy blocked lfs action redirect",
			);
			await cancelUpstreamBody(upstreamResponse);
			sendLocalPlainTextAndClose(req, res, 502, "Bad gateway: upstream redirect blocked");
			return;
		}
		await sendUpstreamResponse(upstreamResponse, res, { "Cache-Control": "no-store" }, req);
	} catch (err) {
		logger.error(
			{ ...describeErrorForLog(err), ...describeLfsActionTargetForLog(record.href) },
			"git proxy lfs action failed",
		);
		if (!res.headersSent) {
			sendLocalPlainTextAndClose(req, res, 502, "Bad gateway: lfs action request failed");
		} else {
			res.end();
		}
	} finally {
		if (shouldRetireAction) {
			lfsActionStore.delete(actionId);
		} else if (lfsActionStore.get(actionId) === record) {
			record.inFlight = false;
		}
		await closeLfsActionAgent(agent);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Request Handling
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Forward a request to the upstream git server with authentication.
 *
 * SECURITY: Uses streaming to avoid buffering large git operations in memory.
 * Git pushes can be hundreds of megabytes - buffering would cause OOM.
 */
async function proxyRequest(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	parsed: ParsedGitUrl,
	session: GitProxySession,
	proxyOrigin: string,
): Promise<void> {
	let operation = getGitOperation(req.method ?? "GET", parsed.path, req.url ?? "");
	let receivePackCommands: ReceivePackCommand[] | null = null;
	let receivePackIsFlushOnlyProbe = false;
	let lfsBatchOperation: LfsBatchOperation | null = null;

	if (operation.service === "lfs-locks") {
		logger.warn(
			{ sessionId: session.sessionId, repository: operation.repo },
			"git proxy rejected lfs lock request because shared upstream identity cannot mediate lock ownership",
		);
		sendLocalPlainTextAndClose(
			req,
			res,
			501,
			"Not implemented: git lfs locking is disabled by git proxy policy",
		);
		return;
	}

	const repositoryAuth = authorizeRepository(parsed.repository, session);
	if (!repositoryAuth.ok) {
		logger.warn(
			{
				sessionId: session.sessionId,
				operation: operation.type,
				reason: "repository_policy_denied",
			},
			"git proxy request blocked by policy before body read",
		);
		rejectForbiddenAndClose(req, res, 403, repositoryAuth.reason);
		return;
	}
	if (operation.type !== "unknown" && !session.permissions.includes(operation.type)) {
		const reason = `${operation.type} is not allowed by git proxy policy`;
		logger.warn(
			{
				sessionId: session.sessionId,
				repository: parsed.repository,
				operation: operation.type,
				reason,
			},
			"git proxy request blocked by policy before body read",
		);
		rejectForbiddenAndClose(req, res, 403, reason);
		return;
	}
	if (
		operation.type === "unknown" &&
		isLfsBatchPath(parsed.path) &&
		!session.permissions.includes("fetch") &&
		!session.permissions.includes("push")
	) {
		const reason = "lfs batch is not allowed by git proxy policy";
		logger.warn(
			{
				sessionId: session.sessionId,
				repository: parsed.repository,
				operation: "lfs-batch",
				reason,
			},
			"git proxy request blocked by policy before body read",
		);
		rejectForbiddenAndClose(req, res, 403, reason);
		return;
	}

	const earlyOperationAuth = authorizeOperation(parsed, operation, session);
	if (!earlyOperationAuth.ok && operation.type === "unknown" && !isLfsBatchPath(parsed.path)) {
		logger.warn(
			{
				sessionId: session.sessionId,
				operation: operation.type,
				reason: "operation_policy_denied",
			},
			"git proxy request blocked by policy before body read",
		);
		rejectForbiddenAndClose(req, res, 403, earlyOperationAuth.reason);
		return;
	}

	let requestBody: ReadableStream<Uint8Array> | undefined;
	if (req.method === "POST") {
		if (operation.type === "push" && parsed.path.split("?")[0] === "/git-receive-pack") {
			try {
				const prepared = await prepareReceivePackBody(req);
				receivePackCommands = prepared.commands;
				receivePackIsFlushOnlyProbe = prepared.isFlushOnlyProbe;
				requestBody = Readable.toWeb(prepared.body);
			} catch (err) {
				logger.warn(
					{ sessionId: session.sessionId, repository: parsed.repository, error: String(err) },
					"git proxy failed to parse receive-pack request",
				);
				sendLocalPlainTextAndClose(req, res, 400, "Bad request: invalid receive-pack request");
				return;
			}
		} else if (isLfsBatchPath(parsed.path)) {
			try {
				const prepared = await prepareLfsBatchBody(req);
				lfsBatchOperation = prepared.operation;
				operation = {
					type: prepared.operation.type,
					repo: parsed.repository,
					service: "lfs-batch",
				};
				requestBody = Readable.toWeb(prepared.body);
			} catch (err) {
				logger.warn(
					{ sessionId: session.sessionId, repository: parsed.repository, error: String(err) },
					"git proxy failed to parse lfs batch request",
				);
				sendLocalPlainTextAndClose(req, res, 400, "Bad request: invalid lfs batch request");
				return;
			}
		} else {
			requestBody = Readable.toWeb(req);
		}
	}

	const operationAuth = authorizeOperation(parsed, operation, session);
	if (!operationAuth.ok) {
		logger.warn(
			{
				sessionId: session.sessionId,
				operation: operation.type,
				reason: "operation_policy_denied",
			},
			"git proxy request blocked by policy",
		);
		rejectForbiddenAndClose(req, res, 403, operationAuth.reason);
		return;
	}

	if (receivePackCommands && !receivePackIsFlushOnlyProbe) {
		const commandAuth = authorizeReceivePackCommands(receivePackCommands, session);
		if (!commandAuth.ok) {
			logger.warn(
				{
					sessionId: session.sessionId,
					reason: "receive_pack_policy_denied",
				},
				"git proxy receive-pack blocked by policy",
			);
			rejectForbiddenAndClose(req, res, 403, commandAuth.reason);
			return;
		}
	}

	if (lfsBatchOperation?.type === "push") {
		const refAuth = authorizePushRefs(
			lfsBatchOperation.ref ? [lfsBatchOperation.ref] : [],
			session,
			"lfs upload request did not include a ref",
		);
		if (!refAuth.ok) {
			logger.warn(
				{
					sessionId: session.sessionId,
					hasRef: Boolean(lfsBatchOperation.ref),
					reason: "lfs_upload_policy_denied",
				},
				"git proxy lfs upload blocked by policy",
			);
			rejectForbiddenAndClose(req, res, 403, refAuth.reason);
			return;
		}
	}

	// Get a GitHub App token scoped to this repository and operation.
	let token: string | null;
	try {
		token = await getInstallationToken({
			repository: parsed.repository,
			contentsPermission: operation.type === "push" ? "write" : "read",
		});
	} catch (err) {
		logger.error(
			{ sessionId: session.sessionId, repository: parsed.repository, error: String(err) },
			"git proxy failed to get installation token",
		);
		sendLocalPlainTextAndClose(req, res, 503, "Service unavailable: authentication not configured");
		return;
	}
	if (!token) {
		logger.error("failed to get installation token for git proxy");
		sendLocalPlainTextAndClose(req, res, 503, "Service unavailable: authentication not configured");
		return;
	}

	// Build upstream URL
	const upstreamUrl = `https://${parsed.host}/${parsed.owner}/${parsed.repo}.git${parsed.path}`;

	// Build headers for upstream request
	const upstreamHeaders = buildGitHubAuthHeaders(req, parsed.host, token);

	try {
		const upstreamResponse = await fetch(upstreamUrl, {
			method: req.method,
			headers: upstreamHeaders,
			body: requestBody,
			// Required for streaming request body in fetch
			duplex: "half",
			redirect: "manual",
		});
		if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
			logger.warn(
				{
					sessionId: session.sessionId,
					repository: parsed.repository,
					status: upstreamResponse.status,
				},
				"git proxy blocked upstream redirect",
			);
			await cancelUpstreamBody(upstreamResponse);
			sendLocalPlainTextAndClose(req, res, 502, "Bad gateway: upstream redirect blocked");
			return;
		}

		if (lfsBatchOperation) {
			if (!upstreamResponse.ok) {
				await sendUpstreamResponse(upstreamResponse, res, {}, req);
				return;
			}
			let rewrittenBody: string;
			try {
				rewrittenBody = await rewriteLfsBatchResponse(
					parsed,
					lfsBatchOperation,
					session,
					proxyOrigin,
					await readResponseTextWithLimit(upstreamResponse, LFS_BATCH_RESPONSE_MAX_BYTES),
				);
			} catch (err) {
				logger.warn(
					{ sessionId: session.sessionId, repository: parsed.repository, error: String(err) },
					"git proxy failed to rewrite lfs batch response",
				);
				sendLocalPlainTextAndClose(req, res, 502, "Bad gateway: invalid lfs batch response");
				return;
			}
			res.writeHead(upstreamResponse.status, {
				"Content-Type": "application/vnd.git-lfs+json",
				"Content-Length": Buffer.byteLength(rewrittenBody),
				"Cache-Control": "no-store",
			});
			res.end(rewrittenBody);
			return;
		}

		// Log the operation
		logger.info(
			{
				sessionId: session.sessionId,
				operation: operation.type,
				repo: operation.repo,
				status: upstreamResponse.status,
			},
			"git proxy request completed",
		);

		await sendUpstreamResponse(upstreamResponse, res, {}, req);
	} catch (err) {
		logger.error({ error: String(err), url: upstreamUrl }, "git proxy upstream request failed");
		// Only send error response if headers haven't been sent
		if (!res.headersSent) {
			sendLocalPlainTextAndClose(req, res, 502, "Bad gateway: upstream request failed");
		} else {
			res.end();
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG: GitProxyConfig = {
	port: 8791,
	host: "127.0.0.1",
	allowedHosts: ["github.com"],
	rateLimitPerMinute: 60,
	lfsActionRateLimitPerMinute: LFS_ACTION_RATE_LIMIT_PER_MINUTE,
	defaultPolicy: DEFAULT_GIT_PROXY_TOKEN_POLICY,
};

function validateProxySessionToken(
	token: string,
	remoteAddress: string | undefined,
	config: GitProxyConfig,
): GitProxySession | null {
	const secret = config.tokenSecret ?? process.env.TELCLAUDE_GIT_PROXY_SECRET;
	if (token.startsWith(`${GIT_PROXY_TOKEN_PREFIX}.`)) {
		if (!secret) {
			logger.warn("git proxy scoped token received but signing secret is not configured");
			return null;
		}
		const verified = verifyGitProxyToken(token, { secret, peerAddress: remoteAddress });
		if (!verified.ok) {
			logger.warn({ reason: verified.reason }, "git proxy scoped token rejected");
			return null;
		}
		return verified;
	}

	if (process.env.TELCLAUDE_GIT_PROXY_ALLOW_LEGACY_TOKENS === "1") {
		const legacy = validateSessionTokenV3(token, getPublicKey());
		if (!legacy) return null;
		return { ...legacy, ...config.defaultPolicy };
	}

	logger.warn("git proxy rejected legacy session token");
	return null;
}

export function startGitProxyServer(config: Partial<GitProxyConfig> = {}): http.Server {
	const configuredPublicUrl =
		config.publicUrl ??
		process.env.TELCLAUDE_GIT_PROXY_PUBLIC_URL ??
		process.env.TELCLAUDE_GIT_PROXY_URL;
	const finalConfig: GitProxyConfig = {
		port: config.port ?? Number(process.env.TELCLAUDE_GIT_PROXY_PORT ?? DEFAULT_CONFIG.port),
		host: config.host ?? (getSandboxMode() === "docker" ? "0.0.0.0" : DEFAULT_CONFIG.host),
		allowedHosts: config.allowedHosts ?? DEFAULT_CONFIG.allowedHosts,
		rateLimitPerMinute: config.rateLimitPerMinute ?? DEFAULT_CONFIG.rateLimitPerMinute,
		lfsActionRateLimitPerMinute:
			config.lfsActionRateLimitPerMinute ?? DEFAULT_CONFIG.lfsActionRateLimitPerMinute,
		tokenSecret: config.tokenSecret,
		...(configuredPublicUrl ? { publicUrl: normalizeProxyPublicOrigin(configuredPublicUrl) } : {}),
		defaultPolicy: config.defaultPolicy ?? resolveGitProxyTokenPolicy(),
	};

	const server = http.createServer(async (req, res) => {
		const url = req.url ?? "";
		if (url.includes("#")) {
			logger.warn("git proxy rejected request target with fragment delimiter");
			sendLocalPlainTextAndClose(req, res, 400, "Bad request: invalid git URL format");
			return;
		}

		// Health check
		if (url === "/health" && req.method === "GET") {
			sendLocalJsonAndClose(req, res, 200, { ok: true, service: "git-proxy" });
			return;
		}

		// Identity endpoint - returns bot identity for git config
		if (url === "/identity" && req.method === "GET") {
			let identity: Awaited<ReturnType<typeof getGitHubAppIdentity>>;
			try {
				identity = await getGitHubAppIdentity();
			} catch (err) {
				logger.error({ error: String(err) }, "git proxy failed to get GitHub App identity");
				sendLocalJsonAndClose(req, res, 503, { error: "GitHub App not configured" });
				return;
			}
			if (!identity) {
				sendLocalJsonAndClose(req, res, 503, { error: "GitHub App not configured" });
				return;
			}
			sendLocalJsonAndClose(req, res, 200, identity);
			return;
		}

		// Validate session token
		const sessionHeader = req.headers["x-telclaude-session"] as string | undefined;
		if (!sessionHeader) {
			logger.warn({ url }, "git proxy request missing session token");
			sendLocalPlainTextAndClose(req, res, 401, "Unauthorized: missing session token");
			return;
		}

		const session = validateProxySessionToken(
			sessionHeader.trim(),
			req.socket.remoteAddress,
			finalConfig,
		);
		if (!session) {
			logger.warn({ url }, "git proxy request with invalid session token");
			sendLocalPlainTextAndClose(req, res, 401, "Unauthorized: invalid session token");
			return;
		}

		const lfsActionId = parseLfsActionProxyPath(url);
		if (lfsActionId) {
			const method = (req.method ?? "GET").toUpperCase();
			if (method !== "GET" && method !== "HEAD" && method !== "POST" && method !== "PUT") {
				sendLocalPlainTextAndClose(req, res, 405, "Method not allowed");
				return;
			}
			if (!lfsActionRateLimiter.check(session.sessionId, finalConfig.lfsActionRateLimitPerMinute)) {
				logger.warn({ sessionId: session.sessionId }, "git proxy lfs action rate limit exceeded");
				sendLocalPlainTextAndClose(req, res, 429, "Too many requests");
				return;
			}
			await proxyLfsActionRequest(req, res, lfsActionId, session);
			return;
		}

		// Rate limiting
		if (!rateLimiter.check(session.sessionId, finalConfig.rateLimitPerMinute)) {
			logger.warn({ sessionId: session.sessionId }, "git proxy rate limit exceeded");
			sendLocalPlainTextAndClose(req, res, 429, "Too many requests");
			return;
		}

		// Parse git URL
		const parsed = parseGitUrl(url);
		if (!parsed) {
			logger.warn({ url }, "git proxy invalid URL format");
			sendLocalPlainTextAndClose(req, res, 400, "Bad request: invalid git URL format");
			return;
		}

		// Validate host is allowed
		if (!finalConfig.allowedHosts.map((host) => host.toLowerCase()).includes(parsed.host)) {
			logger.warn({ host: parsed.host }, "git proxy request to non-allowed host");
			rejectForbiddenAndClose(req, res, 403, `host ${parsed.host} not allowed`);
			return;
		}

		// Validate method
		if (req.method !== "GET" && req.method !== "POST" && req.method !== "HEAD") {
			sendLocalPlainTextAndClose(req, res, 405, "Method not allowed");
			return;
		}

		// Proxy the request
		await proxyRequest(req, res, parsed, session, resolveProxyOrigin(finalConfig, server));
	});
	activeGitProxyServerCount += 1;
	server.once("close", () => {
		activeGitProxyServerCount = Math.max(0, activeGitProxyServerCount - 1);
		if (activeGitProxyServerCount === 0) {
			lfsActionStore.clear();
		}
	});

	server.listen(finalConfig.port, finalConfig.host, () => {
		logger.info({ host: finalConfig.host, port: finalConfig.port }, "git proxy server listening");
	});

	return server;
}

export { describeLfsActionTargetForLog, getGitOperation, parseGitUrl };
