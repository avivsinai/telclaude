import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
	BLOCKED_METADATA_DOMAINS,
	BLOCKED_PRIVATE_NETWORKS,
	DEFAULT_WRITE_PATHS,
	DENY_WRITE_PATHS,
	PRIVATE_TMP_PATH,
	SENSITIVE_READ_PATHS,
} from "./config.js";
import { DEFAULT_ALLOWED_DOMAIN_NAMES } from "./domains.js";

type SettingsFile = {
	sandbox?: {
		enabled?: boolean;
		network?: {
			allowLocalBinding?: boolean;
			allowAllUnixSockets?: boolean;
		};
	};
	permissions?: {
		allow?: string[];
		deny?: string[];
	};
} & Record<string, unknown>;

const SETTINGS_DIR = path.join(os.homedir(), ".claude");
const SETTINGS_PATH = path.join(SETTINGS_DIR, "settings.local.json");

const IS_PROD = process.env.TELCLAUDE_ENV === "prod" || process.env.NODE_ENV === "production";

function uniq(values: string[]): string[] {
	return Array.from(new Set(values));
}

function expandHome(p: string): string {
	if (p.startsWith("~")) {
		return path.join(os.homedir(), p.slice(2));
	}
	return p;
}

function withGlobVariants(p: string): string[] {
	const base = expandHome(p);
	const parts = [base];
	if (!base.endsWith("/**")) {
		parts.push(path.join(base, "**"));
	}
	return parts;
}

function readExistingSettings(): SettingsFile {
	try {
		const raw = fs.readFileSync(SETTINGS_PATH, "utf8");
		return JSON.parse(raw) as SettingsFile;
	} catch {
		return {};
	}
}

function ensureSettingsDir(): void {
	if (!fs.existsSync(SETTINGS_DIR)) {
		fs.mkdirSync(SETTINGS_DIR, { recursive: true, mode: 0o700 });
	}
}

function buildPermissions(): { allow: string[]; deny: string[] } {
	const allowWrite = [
		"Write(.)",
		...DEFAULT_WRITE_PATHS.flatMap((p) => withGlobVariants(p).map((v) => `Write(${v})`)),
		...withGlobVariants(PRIVATE_TMP_PATH).map((p) => `Write(${p})`),
	];

	const denyRead = SENSITIVE_READ_PATHS.flatMap((p) =>
		withGlobVariants(p).map((v) => `Read(${v})`),
	);
	const denyWrite = DENY_WRITE_PATHS.flatMap((p) => withGlobVariants(p).map((v) => `Write(${v})`));

	const allowNetwork = DEFAULT_ALLOWED_DOMAIN_NAMES.map((d) => `Network(domain:${d})`);
	const denyNetwork = [...BLOCKED_METADATA_DOMAINS, ...BLOCKED_PRIVATE_NETWORKS].map((d) => {
		// The SDK matches by domain string; include IPs as-is.
		return `Network(domain:${d})`;
	});

	return {
		allow: uniq([...allowWrite, ...allowNetwork]),
		deny: uniq([...denyRead, ...denyWrite, ...denyNetwork]),
	};
}

export function syncSdkSandboxSettings(): void {
	ensureSettingsDir();

	const existing = readExistingSettings();
	const permissions = buildPermissions();

	const next: SettingsFile = {
		...existing,
		sandbox: {
			...existing.sandbox,
			enabled: true,
			network: {
				...existing.sandbox?.network,
				allowLocalBinding: !IS_PROD,
				allowAllUnixSockets: !IS_PROD,
			},
		},
		permissions: {
			allow: uniq([...(existing.permissions?.allow ?? []), ...permissions.allow]),
			deny: uniq([...(existing.permissions?.deny ?? []), ...permissions.deny]),
		},
	};

	fs.writeFileSync(SETTINGS_PATH, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
}

export { SETTINGS_PATH as SDK_SETTINGS_PATH };
