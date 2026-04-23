import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export type IntegrationHarnessMode = "replay" | "live" | "capture";

export type FixtureEnvelope<T> = {
	schemaVersion: 1;
	name: string;
	capturedAt: string;
	mode: "replay" | "capture";
	data: T;
	redactions: string[];
};

export type UntrustedPublicText = {
	trust: "untrusted_public";
	value: string;
};

export type SanitizedFixture<T> = {
	data: T;
	redactions: string[];
};

const SECRET_KEY_PATTERNS = [
	/authorization/i,
	/api[-_]?key/i,
	/access[-_]?token/i,
	/refresh[-_]?token/i,
	/^token$/i,
	/secret/i,
	/password/i,
	/passphrase/i,
	/cookie/i,
	/approval[-_]?token/i,
];

const IDENTIFIER_KEY_PATTERNS = [
	/(^|[-_])user[-_]?id$/i,
	/(^|[-_])actor[-_]?user[-_]?id$/i,
	/(^|[-_])subject[-_]?user[-_]?id$/i,
	/(^|[-_])telegram[-_]?user[-_]?id$/i,
	/(^|[-_])chat[-_]?id$/i,
	/(^|[-_])thread[-_]?id$/i,
	/^username$/i,
	/^handle$/i,
	/^author[-_]?handle$/i,
	/^author[-_]?name$/i,
	/^display[-_]?name$/i,
	/^email$/i,
];

const PRIVATE_TEXT_KEY_PATTERNS = [
	/^message$/i,
	/^message[-_]?preview$/i,
	/^private[-_]?message[-_]?text$/i,
	/^transcript$/i,
	/^prompt$/i,
	/^body$/i,
	/^content$/i,
	/^text$/i,
	/^reply$/i,
];

const KNOWN_SECRET_VALUE_PATTERNS = [
	/sk-[A-Za-z0-9_-]{20,}/,
	/gh[pousr]_[A-Za-z0-9_]{20,}/,
	/xox[baprs]-[A-Za-z0-9-]{20,}/,
	/ya29\.[A-Za-z0-9_-]{20,}/,
	/Bearer\s+[A-Za-z0-9._-]{20,}/i,
	/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
	/-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

function keyMatches(key: string | undefined, patterns: RegExp[]): boolean {
	return Boolean(key && patterns.some((pattern) => pattern.test(key)));
}

function stableRedactedId(value: unknown): string {
	const hash = crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 10);
	return `[REDACTED_ID:${hash}]`;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUntrustedPublicText(value: unknown): value is UntrustedPublicText {
	return (
		isPlainRecord(value) && value.trust === "untrusted_public" && typeof value.value === "string"
	);
}

export function untrustedPublicText(value: string): UntrustedPublicText {
	return { trust: "untrusted_public", value };
}

function sanitizeValue(value: unknown, key: string | undefined, redactions: string[]): unknown {
	if (isUntrustedPublicText(value)) {
		return value;
	}

	if (keyMatches(key, SECRET_KEY_PATTERNS)) {
		redactions.push(key ?? "<secret>");
		return "[REDACTED_SECRET]";
	}

	if (keyMatches(key, IDENTIFIER_KEY_PATTERNS)) {
		redactions.push(key ?? "<identifier>");
		return stableRedactedId(value);
	}

	if (keyMatches(key, PRIVATE_TEXT_KEY_PATTERNS) && typeof value === "string") {
		redactions.push(key ?? "<private_text>");
		return "[REDACTED_TEXT]";
	}

	if (Array.isArray(value)) {
		return value.map((entry) => sanitizeValue(entry, undefined, redactions));
	}

	if (isPlainRecord(value)) {
		const sanitized: Record<string, unknown> = {};
		for (const [childKey, childValue] of Object.entries(value)) {
			sanitized[childKey] = sanitizeValue(childValue, childKey, redactions);
		}
		return sanitized;
	}

	return value;
}

export function sanitizeFixtureData<T>(data: T): SanitizedFixture<T> {
	const redactions: string[] = [];
	const sanitized = sanitizeValue(data, undefined, redactions) as T;
	return {
		data: sanitized,
		redactions: Array.from(new Set(redactions)).sort(),
	};
}

export function assertNoKnownSecretPatterns(serializedFixture: string): void {
	for (const pattern of KNOWN_SECRET_VALUE_PATTERNS) {
		if (pattern.test(serializedFixture)) {
			throw new Error(`Fixture contains an unredacted secret-like value: ${pattern}`);
		}
	}
}

export function buildFixtureEnvelope<T>(
	name: string,
	data: T,
	options: { capturedAt?: string; mode?: "replay" | "capture" } = {},
): FixtureEnvelope<T> {
	return {
		schemaVersion: 1,
		name,
		capturedAt: options.capturedAt ?? new Date().toISOString(),
		mode: options.mode ?? "replay",
		data,
		redactions: [],
	};
}

export async function readFixtureFile<T>(fixturePath: string): Promise<FixtureEnvelope<T>> {
	const raw = await fs.readFile(fixturePath, "utf8");
	assertNoKnownSecretPatterns(raw);
	return JSON.parse(raw) as FixtureEnvelope<T>;
}

export async function writeFixtureFile<T>(
	fixturePath: string,
	envelope: FixtureEnvelope<T>,
): Promise<FixtureEnvelope<T>> {
	const sanitized = sanitizeFixtureData(envelope.data);
	const safeEnvelope: FixtureEnvelope<T> = {
		...envelope,
		data: sanitized.data,
		redactions: Array.from(new Set([...envelope.redactions, ...sanitized.redactions])).sort(),
	};
	const serialized = `${JSON.stringify(safeEnvelope, null, 2)}\n`;
	assertNoKnownSecretPatterns(serialized);

	await fs.mkdir(path.dirname(fixturePath), { recursive: true });
	const tmpPath = `${fixturePath}.tmp.${process.pid}.${Date.now()}`;
	await fs.writeFile(tmpPath, serialized, "utf8");
	await fs.rename(tmpPath, fixturePath);
	return safeEnvelope;
}

export function resolveHarnessMode(options: {
	live?: boolean;
	captureFixtures?: boolean;
}): IntegrationHarnessMode {
	if (options.captureFixtures) {
		return "capture";
	}
	return options.live ? "live" : "replay";
}

export function integrationFixturePath(fixtureDir: string, fixtureName: string): string {
	const safeName = fixtureName.endsWith(".json") ? fixtureName : `${fixtureName}.json`;
	return path.join(fixtureDir, safeName);
}
