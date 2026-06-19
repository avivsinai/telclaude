import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { getDomain } from "tldts";

import {
	buildBrowserOriginScope,
	normalizeBrowserOriginScopeEntry,
} from "./browser-connect-contract.js";
import {
	type BrowserAuthorityDomain,
	type BrowserCookieStore,
	type BrowserSessionMeta,
	type BrowserSessionRecord,
	isBrowserAuthorityDomain,
} from "./browser-cookie-store.js";

export interface BrowserSessionEnrollmentInput {
	readonly credentialRef: string;
	readonly actorId: string;
	readonly profileId: string;
	readonly authorityDomain: BrowserAuthorityDomain;
	readonly url: string;
	readonly domain?: string;
	readonly originScope?: readonly string[];
	readonly storageState: unknown;
	readonly capturedBy?: string;
	readonly nowMs?: number;
}

export interface BrowserStorageStateCaptureOptions {
	readonly url: string;
	readonly userDataDir?: string;
	readonly browserChannel?: string;
	readonly headless?: boolean;
	readonly keepProfile?: boolean;
	readonly waitForOperator?: (context: { readonly url: string }) => Promise<void>;
}

export function enrollBrowserSession(
	store: BrowserCookieStore,
	input: BrowserSessionEnrollmentInput,
): BrowserSessionMeta {
	const credentialRef = requiredTrimmed(input.credentialRef, "credentialRef");
	const actorId = requiredTrimmed(input.actorId, "actorId");
	const profileId = requiredTrimmed(input.profileId, "profileId");
	const capturedBy = input.capturedBy?.trim() || actorId;
	const authorityDomain = input.authorityDomain;
	if (!isBrowserAuthorityDomain(authorityDomain)) {
		throw new Error(
			`browser session capture requires a valid authorityDomain (got ${JSON.stringify(
				authorityDomain,
			)})`,
		);
	}

	const inferredDomain = inferBrowserSessionRegistrableDomain(input.url);
	const domain = input.domain
		? normalizeBrowserSessionRegistrableDomain(input.domain)
		: inferredDomain;
	if (domain !== inferredDomain) {
		throw new Error(
			`browser session capture domain ${domain} does not match login URL registrable domain ${inferredDomain}`,
		);
	}
	const originScope = normalizeCaptureOriginScope(domain, input.originScope ?? []);

	const record: BrowserSessionRecord = {
		credentialRef,
		actorId,
		profileId,
		authorityDomain,
		domain,
		originScope,
		storageState: input.storageState,
		createdAt: normalizeCreatedAt(input.nowMs ?? Date.now()),
		capturedBy,
	};
	store.putSession(record);
	return metaFromSessionRecord(record);
}

export function inferBrowserSessionRegistrableDomain(url: string): string {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error("browser session capture url must be an absolute http(s) URL");
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new Error("browser session capture url must be an absolute http(s) URL");
	}
	const domain = getDomain(parsed.hostname, { allowPrivateDomains: true });
	if (!domain) {
		throw new Error("browser session capture url must resolve to a registrable domain");
	}
	return domain.toLowerCase();
}

export function normalizeBrowserSessionRegistrableDomain(domain: string): string {
	const trimmed = domain.trim().toLowerCase().replace(/\.$/, "");
	if (!trimmed) throw new Error("browser session capture domain is required");
	const registrable = getDomain(trimmed, { allowPrivateDomains: true });
	if (!registrable || registrable !== trimmed) {
		throw new Error("browser session capture domain must be a registrable domain");
	}
	return registrable;
}

export function normalizeCaptureOriginScope(
	domain: string,
	entries: readonly string[] = [],
): string[] {
	const normalizedDomain = normalizeBrowserSessionRegistrableDomain(domain);
	for (const entry of entries) {
		if (!entry.trim()) continue;
		if (!normalizeBrowserOriginScopeEntry(entry)) {
			throw new Error(`browser session capture origin scope entry is not registrable: ${entry}`);
		}
	}
	return buildBrowserOriginScope([normalizedDomain, ...entries]);
}

export async function loadBrowserStorageStateFromFile(filePath: string): Promise<unknown> {
	const raw = await readFile(filePath, "utf8");
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw) as unknown;
	} catch (err) {
		throw new Error(
			`browser session storage state file is not valid JSON: ${
				err instanceof Error ? err.message : String(err)
			}`,
		);
	}
	if (!isRecord(parsed)) {
		throw new Error("browser session storage state JSON must be an object");
	}
	return parsed;
}

export async function captureBrowserStorageState(
	options: BrowserStorageStateCaptureOptions,
): Promise<unknown> {
	const url = options.url.trim();
	if (!url) throw new Error("browser session capture url is required");
	inferBrowserSessionRegistrableDomain(url);
	const createdTempProfile = !options.userDataDir;
	const userDataDir = options.userDataDir ?? (await mkdtemp(join(tmpdir(), "tc-browser-capture-")));
	let context: Awaited<
		ReturnType<typeof import("playwright-core")["chromium"]["launchPersistentContext"]>
	> | null = null;
	try {
		const { chromium } = await import("playwright-core");
		context = await chromium.launchPersistentContext(userDataDir, {
			channel: options.browserChannel ?? "chrome",
			headless: options.headless ?? false,
			viewport: null,
		});
		const page = context.pages()[0] ?? (await context.newPage());
		await page.goto(url, { waitUntil: "domcontentloaded" });
		await options.waitForOperator?.({ url: page.url() });
		return await context.storageState();
	} finally {
		await context?.close().catch(() => undefined);
		if (createdTempProfile && !options.keepProfile) {
			await rm(userDataDir, { recursive: true, force: true }).catch(() => undefined);
		}
	}
}

function metaFromSessionRecord(record: BrowserSessionRecord): BrowserSessionMeta {
	return {
		credentialRef: record.credentialRef,
		actorId: record.actorId,
		profileId: record.profileId,
		authorityDomain: record.authorityDomain,
		domain: record.domain,
		originScope: record.originScope,
		createdAt: record.createdAt,
		capturedBy: record.capturedBy,
	};
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`browser session capture ${field} is required`);
	return trimmed;
}

function normalizeCreatedAt(value: number): number {
	if (!Number.isFinite(value) || value < 0) {
		throw new Error("browser session capture createdAt must be a non-negative timestamp");
	}
	return Math.trunc(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
