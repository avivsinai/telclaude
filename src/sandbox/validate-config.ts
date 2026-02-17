import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export type SandboxPostureSeverity = "critical" | "warning" | "info";

export type SandboxPostureFinding = {
	severity: SandboxPostureSeverity;
	category: string;
	message: string;
};

export type SandboxPostureAuditOptions = {
	composePath?: string;
	envPath?: string;
	cwd?: string;
};

type ComposeSection = "volumes" | "environment" | "security_opt" | null;

type ComposeService = {
	name: string;
	networkMode?: string;
	privileged?: boolean;
	securityOpts: string[];
	volumes: string[];
	envKeys: string[];
};

const BLOCKED_HOST_PATHS = [
	"/",
	"/etc",
	"/private/etc",
	"/proc",
	"/sys",
	"/dev",
	"/root",
	"/boot",
	"/run",
	"/var/run",
	"/private/var/run",
	"/var/run/docker.sock",
	"/private/var/run/docker.sock",
	"/run/docker.sock",
];

const AGENT_SENSITIVE_ENV_KEYS = new Set([
	"TELEGRAM_BOT_TOKEN",
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"CLAUDE_CODE_OAUTH_TOKEN",
	"SECRETS_ENCRYPTION_KEY",
	"TOTP_ENCRYPTION_KEY",
]);

const PERMISSIVE_NETWORK_MODES = new Set(["open", "permissive"]);

function toPosixPath(input: string): string {
	return path.resolve(input).replaceAll("\\", "/");
}

function stripInlineComment(value: string): string {
	const hashIndex = value.indexOf("#");
	if (hashIndex === -1) {
		return value;
	}
	return value.slice(0, hashIndex);
}

function normalizeBoolean(input: string | undefined): boolean | undefined {
	if (!input) {
		return undefined;
	}
	const normalized = input.trim().toLowerCase();
	if (normalized === "true" || normalized === '"true"' || normalized === "'true'") {
		return true;
	}
	if (normalized === "false" || normalized === '"false"' || normalized === "'false'") {
		return false;
	}
	return undefined;
}

function unquote(value: string): string {
	const trimmed = value.trim();
	if (
		(trimmed.startsWith('"') && trimmed.endsWith('"')) ||
		(trimmed.startsWith("'") && trimmed.endsWith("'"))
	) {
		return trimmed.slice(1, -1);
	}
	return trimmed;
}

function extractEnvKey(entry: string): string | null {
	const cleaned = unquote(stripInlineComment(entry).trim());
	if (!cleaned) {
		return null;
	}
	const eqIndex = cleaned.indexOf("=");
	if (eqIndex <= 0) {
		return null;
	}
	const key = cleaned.slice(0, eqIndex).trim();
	return key || null;
}

function parseBindSource(entry: string): string | null {
	const cleaned = unquote(stripInlineComment(entry).trim());
	if (!cleaned) {
		return null;
	}
	const firstColon = cleaned.indexOf(":");
	if (firstColon <= 0) {
		return cleaned;
	}
	return cleaned.slice(0, firstColon).trim();
}

function isLikelyHostPath(source: string): boolean {
	return (
		source.startsWith("/") ||
		source.startsWith("./") ||
		source.startsWith("../") ||
		source === "." ||
		source === ".." ||
		source.startsWith("~/")
	);
}

function resolveHostPath(source: string, composeDir: string): string | null {
	if (!source || source.startsWith("${")) {
		return null;
	}
	if (!isLikelyHostPath(source)) {
		return null;
	}
	if (source.startsWith("~/")) {
		return path.resolve(os.homedir(), source.slice(2));
	}
	if (source.startsWith("/")) {
		return path.resolve(source);
	}
	return path.resolve(composeDir, source);
}

function toDisplayRelative(target: string, baseDir: string): string {
	const relative = path.relative(baseDir, target);
	if (!relative || relative === ".") {
		return ".";
	}
	if (relative.startsWith("..")) {
		return target;
	}
	return `./${relative.replaceAll("\\", "/")}`;
}

function getBlockedPathMatch(resolvedPath: string): string | null {
	const normalized = toPosixPath(resolvedPath);
	for (const blocked of BLOCKED_HOST_PATHS) {
		if (normalized === blocked || normalized.startsWith(`${blocked}/`)) {
			return blocked;
		}
	}
	return null;
}

function parseEnvFile(envPath: string): Record<string, string> {
	if (!fs.existsSync(envPath)) {
		return {};
	}
	const output: Record<string, string> = {};
	const content = fs.readFileSync(envPath, "utf8");
	for (const rawLine of content.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#")) {
			continue;
		}
		const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
		if (!match) {
			continue;
		}
		const key = match[1];
		const value = unquote(stripInlineComment(match[2]).trim());
		output[key] = value;
	}
	return output;
}

/**
 * Best-effort compose parser used by static sandbox posture checks.
 *
 * Indentation assumption:
 * - services are indented with 2 spaces
 * - service keys with 4 spaces
 * - list/map entries with 6 spaces
 * Tabs are normalized to two spaces before matching.
 *
 * Non-standard indentation can cause services/keys to be skipped silently.
 * This is acceptable here because the audit is heuristic and not a full YAML parse.
 */
function parseComposeServices(content: string): ComposeService[] {
	const services: ComposeService[] = [];
	let inServicesBlock = false;
	let currentService: ComposeService | null = null;
	let currentSection: ComposeSection = null;

	for (const rawLine of content.split(/\r?\n/)) {
		const line = rawLine.replace(/\t/g, "  ");
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) {
			continue;
		}
		const indent = line.length - line.trimStart().length;

		if (!inServicesBlock) {
			if (trimmed === "services:") {
				inServicesBlock = true;
			}
			continue;
		}

		// Left top-level services block.
		if (indent === 0 && trimmed !== "services:") {
			break;
		}

		const serviceMatch = line.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
		if (serviceMatch) {
			currentService = {
				name: serviceMatch[1],
				securityOpts: [],
				volumes: [],
				envKeys: [],
			};
			services.push(currentService);
			currentSection = null;
			continue;
		}

		if (!currentService) {
			continue;
		}

		const keyMatch = line.match(/^ {4}([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/);
		if (keyMatch) {
			const key = keyMatch[1];
			const value = stripInlineComment(keyMatch[2]).trim();
			if (key === "network_mode") {
				currentService.networkMode = unquote(value);
			} else if (key === "privileged") {
				currentService.privileged = normalizeBoolean(value);
			}
			if (key === "volumes" || key === "environment" || key === "security_opt") {
				currentSection = key;
			} else {
				currentSection = null;
			}
			continue;
		}

		if (indent < 6 || !currentSection) {
			continue;
		}

		const listMatch = line.match(/^ {6}-\s*(.+)$/);
		if (listMatch) {
			const value = listMatch[1].trim();
			if (currentSection === "volumes") {
				currentService.volumes.push(value);
			} else if (currentSection === "security_opt") {
				currentService.securityOpts.push(value);
			} else if (currentSection === "environment") {
				const envKey = extractEnvKey(value);
				if (envKey) {
					currentService.envKeys.push(envKey);
				}
			}
			continue;
		}

		if (currentSection === "environment") {
			const envMapMatch = line.match(/^ {6}([A-Za-z_][A-Za-z0-9_]*)\s*:/);
			if (envMapMatch) {
				currentService.envKeys.push(envMapMatch[1]);
			}
		}
	}

	return services;
}

function hasUnconfinedSecurityOpt(value: string, kind: "seccomp" | "apparmor"): boolean {
	const normalized = unquote(stripInlineComment(value).trim()).toLowerCase();
	return normalized === `${kind}:unconfined`;
}

function isDockerSocketPath(value: string): boolean {
	const normalized = toPosixPath(value);
	return normalized === "/var/run/docker.sock" || normalized === "/run/docker.sock";
}

function addServiceSettingFindings(
	findings: SandboxPostureFinding[],
	service: ComposeService,
): void {
	if (service.networkMode?.trim().toLowerCase() === "host") {
		findings.push({
			severity: "critical",
			category: "compose.network",
			message: `Service "${service.name}" uses network_mode=host (breaks network isolation).`,
		});
	}

	if (service.privileged === true) {
		findings.push({
			severity: "critical",
			category: "compose.privileged",
			message: `Service "${service.name}" runs privileged=true.`,
		});
	}

	for (const option of service.securityOpts) {
		if (hasUnconfinedSecurityOpt(option, "seccomp")) {
			findings.push({
				severity: "critical",
				category: "compose.security_opt",
				message: `Service "${service.name}" sets seccomp:unconfined.`,
			});
		}
		if (hasUnconfinedSecurityOpt(option, "apparmor")) {
			findings.push({
				severity: "critical",
				category: "compose.security_opt",
				message: `Service "${service.name}" sets apparmor:unconfined.`,
			});
		}
	}
}

function addBindMountFindings(
	findings: SandboxPostureFinding[],
	service: ComposeService,
	composeDir: string,
): void {
	for (const volumeEntry of service.volumes) {
		const source = parseBindSource(volumeEntry);
		if (!source) {
			continue;
		}

		if (source.toLowerCase().includes("docker.sock")) {
			findings.push({
				severity: "critical",
				category: "compose.bind_mount",
				message: `Service "${service.name}" bind-mounts Docker socket via "${volumeEntry}".`,
			});
			continue;
		}

		const resolvedPath = resolveHostPath(source, composeDir);
		if (!resolvedPath) {
			continue;
		}

		const blocked = getBlockedPathMatch(resolvedPath);
		if (blocked) {
			findings.push({
				severity: "critical",
				category: "compose.bind_mount",
				message:
					`Service "${service.name}" mount source "${source}" resolves to blocked path "${blocked}". ` +
					`Resolved path: ${resolvedPath}`,
			});
			continue;
		}

		if (isDockerSocketPath(resolvedPath)) {
			findings.push({
				severity: "critical",
				category: "compose.bind_mount",
				message: `Service "${service.name}" mount source "${source}" resolves to Docker socket.`,
			});
			continue;
		}

		try {
			const stat = fs.lstatSync(resolvedPath);
			if (!stat.isSymbolicLink()) {
				continue;
			}
			const realPath = fs.realpathSync.native(resolvedPath);
			const realBlocked = getBlockedPathMatch(realPath);
			if (realBlocked) {
				findings.push({
					severity: "critical",
					category: "compose.bind_mount",
					message:
						`Service "${service.name}" mount source "${source}" is a symlink that resolves to blocked path ` +
						`"${realBlocked}" (${realPath}).`,
				});
			}
		} catch {
			// Ignore missing paths and realpath errors in static checks.
		}
	}
}

function addEnvironmentFindings(
	findings: SandboxPostureFinding[],
	services: ComposeService[],
	envMap: Record<string, string>,
	composeDir: string,
): void {
	for (const service of services) {
		const isAgentService = service.name.includes("agent");
		if (!isAgentService) {
			continue;
		}

		for (const key of service.envKeys) {
			if (!AGENT_SENSITIVE_ENV_KEYS.has(key)) {
				continue;
			}
			findings.push({
				severity: "warning",
				category: "compose.environment",
				message: `Agent service "${service.name}" exposes sensitive env key "${key}".`,
			});
		}
	}

	const networkMode = (envMap.TELCLAUDE_NETWORK_MODE ?? "").trim().toLowerCase();
	if (PERMISSIVE_NETWORK_MODES.has(networkMode)) {
		findings.push({
			severity: "warning",
			category: "environment.network",
			message:
				`docker/.env sets TELCLAUDE_NETWORK_MODE=${networkMode}, which broadens egress policy. ` +
				"Use only with explicit operator justification.",
		});
	}

	const workspacePath = (envMap.WORKSPACE_PATH ?? "").trim();
	if (workspacePath) {
		const normalized = toPosixPath(workspacePath);
		const blocked = getBlockedPathMatch(normalized);
		if (blocked && blocked !== "/") {
			findings.push({
				severity: "warning",
				category: "environment.workspace",
				message:
					`WORKSPACE_PATH in docker/.env points at sensitive path "${blocked}" (${workspacePath}). ` +
					`Expected a project workspace under ${toDisplayRelative(composeDir, composeDir)}.`,
			});
		}
	}
}

export function auditSandboxPosture(
	options: SandboxPostureAuditOptions = {},
): SandboxPostureFinding[] {
	const cwd = options.cwd ?? process.cwd();
	const composePath = options.composePath ?? path.join(cwd, "docker", "docker-compose.yml");
	const envPath = options.envPath ?? path.join(cwd, "docker", ".env");
	const composeDir = path.dirname(composePath);
	const findings: SandboxPostureFinding[] = [];

	if (!fs.existsSync(composePath)) {
		return [
			{
				severity: "warning",
				category: "compose.file",
				message: `Compose file not found: ${composePath}`,
			},
		];
	}

	const composeContent = fs.readFileSync(composePath, "utf8");
	const services = parseComposeServices(composeContent);
	for (const service of services) {
		addServiceSettingFindings(findings, service);
		addBindMountFindings(findings, service, composeDir);
	}

	const envMap = parseEnvFile(envPath);
	addEnvironmentFindings(findings, services, envMap, composeDir);

	return findings;
}
