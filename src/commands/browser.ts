import { stderr, stdin } from "node:process";
import { createInterface } from "node:readline/promises";
import type { Command } from "commander";
import {
	BROWSER_COOKIE_STORE_KEY_ENV,
	type BrowserAuthorityDomain,
	type BrowserSessionMeta,
	isBrowserAuthorityDomain,
	resolveBrowserCookieStore,
} from "../relay/browser-cookie-store.js";
import {
	captureBrowserStorageState,
	enrollBrowserSession,
	loadBrowserStorageStateFromFile,
} from "../relay/browser-session-capture.js";
import { CONFIG_DIR } from "../utils.js";

interface BrowserEnrollOptions {
	readonly url?: string;
	readonly credentialRef?: string;
	readonly actorId?: string;
	readonly profileId?: string;
	readonly authorityDomain?: string;
	readonly domain?: string;
	readonly originScope?: string[];
	readonly capturedBy?: string;
	readonly storageState?: string;
	readonly browserChannel?: string;
	readonly userDataDir?: string;
	readonly headless?: boolean;
	readonly keepProfile?: boolean;
	readonly json?: boolean;
}

interface BrowserListOptions {
	readonly json?: boolean;
}

function collectRepeated(value: string, previous: string[] | undefined): string[] {
	return [...(previous ?? []), value];
}

function splitOriginScope(values: readonly string[] | undefined): string[] {
	return (values ?? [])
		.flatMap((value) => value.split(/[,\s]+/))
		.map((value) => value.trim())
		.filter(Boolean);
}

function requiredOption(value: string | undefined, name: string): string {
	const trimmed = value?.trim();
	if (!trimmed) throw new Error(`${name} is required`);
	return trimmed;
}

function parseAuthorityDomain(value: string | undefined): BrowserAuthorityDomain {
	const trimmed = value?.trim() || "private";
	if (!isBrowserAuthorityDomain(trimmed)) {
		throw new Error(
			`--authority-domain must be one of private, public-social, household, public (got ${JSON.stringify(
				value,
			)})`,
		);
	}
	return trimmed;
}

function browserCookieStore() {
	const store = resolveBrowserCookieStore(CONFIG_DIR);
	if (!store) {
		throw new Error(
			`${BROWSER_COOKIE_STORE_KEY_ENV} is required to enroll, list, or delete browser sessions`,
		);
	}
	return store;
}

export function formatBrowserSessionRows(sessions: readonly BrowserSessionMeta[]): string {
	if (sessions.length === 0) return "No browser sessions.";
	const lines = [
		"Credential              Actor                  Profile          Authority      Domain",
	];
	for (const session of sessions) {
		lines.push(
			[
				pad(truncate(session.credentialRef, 22), 22),
				pad(truncate(session.actorId, 22), 22),
				pad(truncate(session.profileId, 16), 16),
				pad(session.authorityDomain, 14),
				session.domain,
			].join(" "),
		);
	}
	return lines.join("\n");
}

export function browserSessionJsonPayload(sessions: readonly BrowserSessionMeta[]): {
	readonly count: number;
	readonly sessions: readonly BrowserSessionMeta[];
} {
	return { count: sessions.length, sessions };
}

export function registerBrowserCommand(program: Command): void {
	const browser = program.command("browser").description("Manage relay-owned browser sessions");
	const sessions = browser
		.command("sessions")
		.description("Manage persistent browser login sessions");

	sessions
		.command("enroll")
		.description("Capture and store a browser login session in the relay cookie store")
		.requiredOption("--url <url>", "Registrable-domain login URL to open/capture")
		.requiredOption("--credential-ref <ref>", "Operator-chosen credential reference")
		.requiredOption("--actor-id <id>", "Exact live MCP authority actorId this login belongs to")
		.requiredOption("--profile-id <id>", "Exact live MCP authority profileId this login belongs to")
		.option(
			"--authority-domain <domain>",
			"Browser authority domain: private, public-social, household, public",
			"private",
		)
		.option("--domain <domain>", "Registrable domain expected from --url")
		.option(
			"--origin-scope <entry>",
			"Additional login origin-scope host/domain; repeat or comma-separate",
			collectRepeated,
			[],
		)
		.option("--captured-by <actor>", "Actor who performed capture; defaults to --actor-id")
		.option("--storage-state <path>", "Import an existing Playwright storageState JSON file")
		.option(
			"--browser-channel <channel>",
			"Playwright browser channel for interactive capture",
			"chrome",
		)
		.option("--user-data-dir <path>", "Use a specific browser profile directory for capture")
		.option("--headless", "Run the capture browser headless")
		.option("--keep-profile", "Keep the temporary capture profile directory")
		.option("--json", "Output metadata as JSON")
		.action(async (opts: BrowserEnrollOptions) => {
			await runBrowserSessionEnroll(opts);
		});

	sessions
		.command("list")
		.description("List browser session metadata without storage state")
		.option("--json", "Output as JSON")
		.action((opts: BrowserListOptions) => {
			try {
				const rows = browserCookieStore().listSessions();
				if (opts.json) {
					console.log(JSON.stringify(browserSessionJsonPayload(rows), null, 2));
					return;
				}
				console.log(formatBrowserSessionRows(rows));
			} catch (err) {
				failCommand(err);
			}
		});

	sessions
		.command("delete <credentialRef>")
		.description("Delete one browser session by credential reference")
		.option("--json", "Output as JSON")
		.action((credentialRef: string, opts: { json?: boolean }) => {
			try {
				const deleted = browserCookieStore().deleteSession(credentialRef);
				if (opts.json) {
					console.log(JSON.stringify({ credentialRef, deleted }, null, 2));
					return;
				}
				console.log(
					deleted
						? `Deleted browser session ${credentialRef}.`
						: `No browser session found for ${credentialRef}.`,
				);
			} catch (err) {
				failCommand(err);
			}
		});
}

async function runBrowserSessionEnroll(opts: BrowserEnrollOptions): Promise<void> {
	try {
		const store = browserCookieStore();
		const url = requiredOption(opts.url, "--url");
		const storageState = opts.storageState
			? await loadBrowserStorageStateFromFile(opts.storageState)
			: await captureBrowserStorageState({
					url,
					browserChannel: opts.browserChannel,
					userDataDir: opts.userDataDir,
					headless: opts.headless,
					keepProfile: opts.keepProfile,
					waitForOperator: waitForOperatorLogin,
				});
		const meta = enrollBrowserSession(store, {
			url,
			credentialRef: requiredOption(opts.credentialRef, "--credential-ref"),
			actorId: requiredOption(opts.actorId, "--actor-id"),
			profileId: requiredOption(opts.profileId, "--profile-id"),
			authorityDomain: parseAuthorityDomain(opts.authorityDomain),
			...(opts.domain ? { domain: opts.domain } : {}),
			originScope: splitOriginScope(opts.originScope),
			storageState,
			...(opts.capturedBy ? { capturedBy: opts.capturedBy } : {}),
		});

		if (opts.json) {
			console.log(JSON.stringify({ session: meta }, null, 2));
			return;
		}
		console.log(`Browser session enrolled: ${meta.credentialRef}`);
		console.log(`Actor: ${meta.actorId}`);
		console.log(`Profile: ${meta.profileId}`);
		console.log(`Authority: ${meta.authorityDomain}`);
		console.log(`Domain: ${meta.domain}`);
		console.log(`Origin scope: ${meta.originScope.join(", ")}`);
	} catch (err) {
		failCommand(err);
	}
}

async function waitForOperatorLogin(): Promise<void> {
	const rl = createInterface({ input: stdin, output: stderr });
	try {
		await rl.question("Log in in the opened browser, then press Enter here to store the session.");
	} finally {
		rl.close();
	}
}

function failCommand(err: unknown): void {
	console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
	process.exitCode = 1;
}

function pad(value: string, width: number): string {
	if (value.length >= width) return value;
	return `${value}${" ".repeat(width - value.length)}`;
}

function truncate(value: string, max: number): string {
	if (value.length <= max) return value;
	const keep = Math.max(4, max - 3);
	return `${value.slice(0, keep)}...`;
}
