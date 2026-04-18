type TelegramCommandCategory =
	| "Discover"
	| "System"
	| "Identity"
	| "Session"
	| "Approvals"
	| "Security"
	| "Social"
	| "Skills"
	| "Background";

/**
 * Hierarchical command IDs: "domain:subcommand" for routed commands,
 * flat names for fast-path shortcuts.
 */
export type TelegramCommandId =
	// Domain roots (bare "/domain" invocations)
	| "help"
	| "help:commands"
	| "me"
	| "me:link"
	| "me:unlink"
	| "auth"
	| "auth:setup"
	| "auth:verify"
	| "auth:logout"
	| "auth:disable"
	| "auth:skip"
	| "auth:force-reauth"
	| "system"
	| "system:sessions"
	| "system:cron"
	| "social"
	| "social:queue"
	| "social:promote"
	| "social:run"
	| "social:log"
	| "social:ask"
	| "skills"
	| "skills:list"
	| "skills:new"
	| "skills:import"
	| "skills:scan"
	| "skills:doctor"
	| "skills:drafts"
	| "skills:promote"
	| "skills:reload"
	| "background"
	| "background:list"
	| "background:show"
	| "background:cancel"
	// Fast-path shortcuts (no domain prefix)
	| "approve"
	| "deny"
	| "new"
	| "otp";

type TelegramControlCommandDefinition = {
	id: TelegramCommandId;
	name: string;
	aliases?: string[];
	category: TelegramCommandCategory;
	description: string;
	usage: string;
	examples?: string[];
	keywords?: string[];
	readOnly?: boolean;
	authExempt?: boolean;
	rateLimited?: boolean;
	menuDescription?: string;
	hideFromCatalog?: boolean;
	/** Domain root command name (e.g. "me", "auth", "system") — set for hierarchical commands. */
	domain?: string;
	/** Subcommand name within domain — set for non-default subcommands. */
	subcommand?: string;
	/** Whether this is the default subcommand when only the domain root is typed. */
	domainDefault?: boolean;
	/** Whether the domain default handler accepts freeform args (e.g. /help [topic]). */
	acceptsFreeformArgs?: boolean;
};

export type TelegramCommandMatch = {
	command: TelegramControlCommandDefinition;
	commandToken: string;
	aliasUsed?: string;
	raw: string;
	rawArgs: string;
	args: string[];
};

type TelegramHelpTopic = {
	id: string;
	title: string;
	summary: string;
	keywords: string[];
	commands: TelegramCommandId[];
};

export type TelegramHelpMatch =
	| {
			kind: "command";
			command: TelegramControlCommandDefinition;
	  }
	| {
			kind: "topic";
			topic: TelegramHelpTopic;
	  };

// ---------------------------------------------------------------------------
// Command definitions — hierarchical
// ---------------------------------------------------------------------------

const TELEGRAM_CONTROL_COMMANDS: TelegramControlCommandDefinition[] = [
	// ── /help ──────────────────────────────────────────────────────────
	{
		id: "help",
		name: "help",
		domain: "help",
		domainDefault: true,
		acceptsFreeformArgs: true,
		category: "Discover",
		description: "Explain commands, topics, or operator workflows.",
		usage: "/help [command or topic]",
		examples: ["/help approvals", "/help reset session", "/help cron"],
		keywords: ["help", "docs", "what can i do", "how do i", "explain"],
		readOnly: true,
		menuDescription: "Explain commands and topics",
	},
	{
		id: "help:commands",
		name: "help",
		domain: "help",
		subcommand: "commands",
		category: "Discover",
		description: "List the Telegram command catalog.",
		usage: "/help commands",
		examples: ["/help commands"],
		keywords: ["commands", "command list", "menu", "available commands"],
		readOnly: true,
		hideFromCatalog: true,
	},
	// ── /me ────────────────────────────────────────────────────────────
	{
		id: "me",
		name: "me",
		domain: "me",
		domainDefault: true,
		category: "Identity",
		description: "Show which local user this chat is linked to.",
		usage: "/me [link <code>|unlink]",
		examples: ["/me", "/me link ABCD-1234", "/me unlink"],
		keywords: ["me", "whoami", "who am i", "identity", "linked user", "which user"],
		readOnly: true,
		menuDescription: "Identity management",
	},
	{
		id: "me:link",
		name: "me",
		domain: "me",
		subcommand: "link",
		category: "Identity",
		description: "Link this private chat to a local user with a one-time code.",
		usage: "/me link <code>",
		examples: ["/me link ABCD-1234"],
		keywords: ["link", "pair", "identity link", "bind chat", "claim user"],
		rateLimited: true,
		hideFromCatalog: true,
	},
	{
		id: "me:unlink",
		name: "me",
		domain: "me",
		subcommand: "unlink",
		category: "Identity",
		description: "Remove the identity link for this chat.",
		usage: "/me unlink",
		examples: ["/me unlink"],
		keywords: ["unlink", "remove link", "disconnect identity"],
		hideFromCatalog: true,
	},
	// ── /auth ──────────────────────────────────────────────────────────
	{
		id: "auth",
		name: "auth",
		domain: "auth",
		domainDefault: true,
		category: "Security",
		description: "Two-factor authentication management.",
		usage: "/auth [setup|verify <code>|logout|disable|skip|force-reauth [chatId]]",
		examples: ["/auth setup", "/auth verify 123456", "/auth logout"],
		keywords: ["auth", "2fa", "totp", "two factor", "authentication"],
		readOnly: true,
		authExempt: true,
		menuDescription: "Two-factor authentication",
		hideFromCatalog: true,
	},
	{
		id: "auth:setup",
		name: "auth",
		domain: "auth",
		subcommand: "setup",
		category: "Security",
		description: "Start the local TOTP setup flow.",
		usage: "/auth setup",
		examples: ["/auth setup"],
		keywords: ["2fa", "setup totp", "enable two factor", "totp setup"],
		authExempt: true,
	},
	{
		id: "auth:verify",
		name: "auth",
		domain: "auth",
		subcommand: "verify",
		category: "Security",
		description: "Verify the current TOTP code and start a 2FA-backed session.",
		usage: "/auth verify <6-digit-code>",
		examples: ["/auth verify 123456"],
		keywords: ["verify 2fa", "totp code", "authenticate"],
		authExempt: true,
	},
	{
		id: "auth:logout",
		name: "auth",
		domain: "auth",
		subcommand: "logout",
		category: "Security",
		description: "Invalidate the current TOTP-backed session.",
		usage: "/auth logout",
		examples: ["/auth logout"],
		keywords: ["2fa logout", "logout", "end auth session", "reauth"],
	},
	{
		id: "auth:disable",
		name: "auth",
		domain: "auth",
		subcommand: "disable",
		category: "Security",
		description: "Disable TOTP for this chat.",
		usage: "/auth disable",
		examples: ["/auth disable"],
		keywords: ["disable 2fa", "turn off totp"],
	},
	{
		id: "auth:skip",
		name: "auth",
		domain: "auth",
		subcommand: "skip",
		category: "Security",
		description: "Acknowledge that TOTP setup is being skipped for now.",
		usage: "/auth skip",
		examples: ["/auth skip"],
		keywords: ["skip totp", "skip 2fa"],
	},
	{
		id: "auth:force-reauth",
		name: "auth",
		domain: "auth",
		subcommand: "force-reauth",
		category: "Security",
		description: "Invalidate your own 2FA session, or an admin can target another chat.",
		usage: "/auth force-reauth [chatId]",
		examples: ["/auth force-reauth", "/auth force-reauth 123456789"],
		keywords: ["force reauth", "invalidate totp", "end session"],
	},
	// ── /system ────────────────────────────────────────────────────────
	{
		id: "system",
		name: "system",
		domain: "system",
		domainDefault: true,
		category: "System",
		description: "Show runtime, security, service, and configuration status.",
		usage: "/system [sessions|cron]",
		examples: ["/system", "/system sessions", "/system cron"],
		keywords: [
			"system",
			"status",
			"health",
			"runtime",
			"security",
			"audit",
			"config",
			"environment",
		],
		readOnly: true,
		rateLimited: true,
		menuDescription: "System introspection",
	},
	{
		id: "system:sessions",
		name: "system",
		domain: "system",
		subcommand: "sessions",
		category: "System",
		description: "Show recent session state for active chats.",
		usage: "/system sessions",
		examples: ["/system sessions"],
		keywords: ["sessions", "session state", "active sessions", "context"],
		readOnly: true,
		rateLimited: true,
		hideFromCatalog: true,
	},
	{
		id: "system:cron",
		name: "system",
		domain: "system",
		subcommand: "cron",
		category: "System",
		description: "Show cron scheduler state and recent jobs.",
		usage: "/system cron",
		examples: ["/system cron"],
		keywords: ["cron", "schedule", "scheduled jobs", "heartbeat schedule", "next run"],
		readOnly: true,
		rateLimited: true,
		hideFromCatalog: true,
	},
	// ── /social ────────────────────────────────────────────────────────
	{
		id: "social",
		name: "social",
		domain: "social",
		domainDefault: true,
		category: "Social",
		description: "Social persona management.",
		usage: "/social [queue|promote <id>|run [svc]|log [svc] [hours]|ask [svc] <q>]",
		examples: ["/social queue", "/social promote post_123", "/social run xtwitter"],
		keywords: ["social", "public persona", "heartbeat", "posts"],
		readOnly: true,
		menuDescription: "Social persona management",
		hideFromCatalog: true,
	},
	{
		id: "social:queue",
		name: "social",
		domain: "social",
		subcommand: "queue",
		category: "Social",
		description: "List pending promotable post ideas.",
		usage: "/social queue",
		examples: ["/social queue"],
		keywords: ["pending posts", "quarantine", "draft posts", "social queue"],
		rateLimited: true,
	},
	{
		id: "social:promote",
		name: "social",
		domain: "social",
		subcommand: "promote",
		category: "Social",
		description: "Promote a pending post idea so it can be published.",
		usage: "/social promote <entry-id>",
		examples: ["/social promote post_123"],
		keywords: ["promote", "approve post", "publish idea"],
		rateLimited: true,
		hideFromCatalog: true,
	},
	{
		id: "social:run",
		name: "social",
		domain: "social",
		subcommand: "run",
		category: "Social",
		description: "Run a social heartbeat now for one service or all enabled services.",
		usage: "/social run [serviceId]",
		examples: ["/social run", "/social run xtwitter"],
		keywords: ["heartbeat", "social run", "post now", "trigger scheduler"],
		rateLimited: true,
		hideFromCatalog: true,
	},
	{
		id: "social:log",
		name: "social",
		domain: "social",
		subcommand: "log",
		category: "Social",
		description: "Summarize recent public persona activity.",
		usage: "/social log [serviceId] [hours]",
		examples: ["/social log", "/social log xtwitter 12"],
		keywords: ["public log", "activity log", "social history"],
		readOnly: true,
		rateLimited: true,
		hideFromCatalog: true,
	},
	{
		id: "social:ask",
		name: "social",
		domain: "social",
		subcommand: "ask",
		category: "Social",
		description:
			"Ask the social persona a question without routing the reply through the private persona.",
		usage: "/social ask [serviceId] <question>",
		examples: ["/social ask what did you post today?", "/social ask xtwitter draft a reply"],
		keywords: ["ask public", "public persona", "social query"],
		rateLimited: true,
		hideFromCatalog: true,
	},
	// ── /skills ────────────────────────────────────────────────────────
	{
		id: "skills",
		name: "skills",
		domain: "skills",
		domainDefault: true,
		category: "Skills",
		description: "Skill management.",
		usage: "/skills [list|new|import|scan|doctor|drafts|promote|reload]",
		examples: [
			"/skills list",
			"/skills new my-helper",
			"/skills doctor",
			"/skills promote my-skill",
		],
		keywords: ["skills", "draft skills", "skill management"],
		readOnly: true,
		menuDescription: "Skill management",
	},
	{
		id: "skills:list",
		name: "skills",
		domain: "skills",
		subcommand: "list",
		category: "Skills",
		description: "List active and draft skills with status.",
		usage: "/skills list",
		examples: ["/skills list"],
		keywords: ["list skills", "skills status", "active skills"],
		readOnly: true,
		rateLimited: true,
	},
	{
		id: "skills:new",
		name: "skills",
		domain: "skills",
		subcommand: "new",
		category: "Skills",
		description: "Scaffold a new draft skill (guided wizard).",
		usage: "/skills new [name]",
		examples: ["/skills new my-helper"],
		keywords: ["scaffold skill", "new skill", "create skill"],
		rateLimited: true,
	},
	{
		id: "skills:import",
		name: "skills",
		domain: "skills",
		subcommand: "import",
		category: "Skills",
		description: "Import OpenClaw-format skills into the draft quarantine (CLI).",
		usage: "/skills import <source-path>",
		examples: ["/skills import /tmp/openclaw-skills"],
		keywords: ["import skills", "openclaw", "import openclaw"],
		rateLimited: true,
	},
	{
		id: "skills:scan",
		name: "skills",
		domain: "skills",
		subcommand: "scan",
		category: "Skills",
		description: "Run the skill scanner over every active and draft skill.",
		usage: "/skills scan",
		examples: ["/skills scan"],
		keywords: ["scan skills", "skill scanner"],
		rateLimited: true,
	},
	{
		id: "skills:doctor",
		name: "skills",
		domain: "skills",
		subcommand: "doctor",
		category: "Skills",
		description: "Validate every skill's frontmatter, scanner, and duplicates.",
		usage: "/skills doctor",
		examples: ["/skills doctor"],
		keywords: ["doctor", "skills doctor", "validate skills", "skill health"],
		rateLimited: true,
	},
	{
		id: "skills:drafts",
		name: "skills",
		domain: "skills",
		subcommand: "drafts",
		category: "Skills",
		description: "List draft skills awaiting promotion.",
		usage: "/skills drafts",
		examples: ["/skills drafts"],
		keywords: ["draft skills", "list drafts", "skills queue"],
		rateLimited: true,
	},
	{
		id: "skills:promote",
		name: "skills",
		domain: "skills",
		subcommand: "promote",
		category: "Skills",
		description: "Promote a draft skill into the live skill set.",
		usage: "/skills promote <name>",
		examples: ["/skills promote my-skill"],
		keywords: ["promote skill", "publish skill"],
		rateLimited: true,
	},
	{
		id: "skills:reload",
		name: "skills",
		domain: "skills",
		subcommand: "reload",
		category: "Skills",
		description: "Force the next session to start with the latest skills.",
		usage: "/skills reload",
		examples: ["/skills reload"],
		keywords: ["reload skills", "refresh skills"],
		rateLimited: true,
	},
	// ── /background domain ────────────────────────────────────────────
	{
		id: "background",
		name: "background",
		domain: "background",
		domainDefault: true,
		category: "Background",
		description: "Inspect or cancel long-running background jobs.",
		usage: "/background [list|show <id>|cancel <id>]",
		examples: ["/background", "/background show a1b2c3d4", "/background cancel a1b2c3d4"],
		keywords: ["background", "jobs", "background job", "long running task"],
		readOnly: true,
		menuDescription: "Background jobs",
	},
	{
		id: "background:list",
		name: "background",
		domain: "background",
		subcommand: "list",
		category: "Background",
		description: "List active and recent background jobs (last 7 days).",
		usage: "/background list",
		examples: ["/background list"],
		keywords: ["list background", "background list", "jobs list"],
		readOnly: true,
		rateLimited: true,
	},
	{
		id: "background:show",
		name: "background",
		domain: "background",
		subcommand: "show",
		category: "Background",
		description: "Show a single background job status card by short id.",
		usage: "/background show <id>",
		examples: ["/background show a1b2c3d4"],
		keywords: ["show background", "background status"],
		readOnly: true,
		rateLimited: true,
	},
	{
		id: "background:cancel",
		name: "background",
		domain: "background",
		subcommand: "cancel",
		category: "Background",
		description: "Cancel a queued or running background job.",
		usage: "/background cancel <id>",
		examples: ["/background cancel a1b2c3d4"],
		keywords: ["cancel background", "abort job", "kill job"],
		rateLimited: true,
	},
	// ── Fast-path shortcuts ────────────────────────────────────────────
	{
		id: "approve",
		name: "approve",
		category: "Approvals",
		description: "Approve a pending request, plan, provider action, or admin claim.",
		usage: "/approve <code>",
		examples: ["/approve 123456"],
		keywords: ["approve", "approval", "allow pending request", "confirm"],
		rateLimited: true,
	},
	{
		id: "deny",
		name: "deny",
		category: "Approvals",
		description: "Deny a pending request. Without a code, denies the newest pending approval.",
		usage: "/deny [code]",
		examples: ["/deny", "/deny 123456"],
		keywords: ["deny", "reject", "cancel approval", "block pending request"],
		rateLimited: true,
	},
	{
		id: "otp",
		name: "otp",
		category: "Security",
		description: "Submit a provider OTP challenge code.",
		usage: "/otp <service> <code> OR /otp <service> <challengeId> <code>",
		examples: ["/otp github 123456"],
		keywords: ["otp", "one time password", "provider auth", "challenge"],
		rateLimited: true,
	},
	{
		id: "new",
		name: "new",
		aliases: ["reset"],
		category: "Session",
		description: "Reset the current conversation session and start fresh.",
		usage: "/new",
		examples: ["/new", "/reset"],
		keywords: ["new conversation", "reset session", "start fresh", "clear context"],
		readOnly: true,
		menuDescription: "Start a fresh session",
	},
];

// ---------------------------------------------------------------------------
// Help topics — updated to use hierarchical command IDs
// ---------------------------------------------------------------------------

const TELEGRAM_HELP_TOPICS: TelegramHelpTopic[] = [
	{
		id: "approvals",
		title: "Approvals",
		summary:
			"Approvals protect sensitive actions. Approve with /approve <code>, deny with /deny <code>, and /deny without a code rejects the newest pending request.",
		keywords: ["approval", "approvals", "approve", "deny", "plan preview", "pending request"],
		commands: ["approve", "deny"],
	},
	{
		id: "identity",
		title: "Identity",
		summary:
			"Identity linking binds a Telegram chat to a local user. Use /me to inspect, /me link <code> to link, and /me unlink to remove.",
		keywords: ["identity", "link", "unlink", "who am i", "whoami", "pairing", "me"],
		commands: ["me", "me:link", "me:unlink"],
	},
	{
		id: "2fa",
		title: "Two-Factor Auth",
		summary:
			"2FA is set up locally. /auth setup explains the local flow, /auth verify activates it, /auth logout ends the current session, and /auth disable removes it.",
		keywords: ["2fa", "totp", "two factor", "reauth", "force reauth", "auth"],
		commands: [
			"auth:setup",
			"auth:verify",
			"auth:logout",
			"auth:disable",
			"auth:force-reauth",
			"auth:skip",
		],
	},
	{
		id: "system",
		title: "System Introspection",
		summary:
			"Use /system for runtime and security state, /system sessions for recent chat sessions, /system cron for scheduled jobs.",
		keywords: ["system", "status", "sessions", "cron", "health", "diagnostics"],
		commands: ["system", "system:sessions", "system:cron"],
	},
	{
		id: "social",
		title: "Social Persona",
		summary:
			"Social commands are admin-gated. Use /social queue and /social promote for queued ideas, /social run to heartbeat now, /social log for metadata history, and /social ask to query the social persona.",
		keywords: ["social", "public persona", "heartbeat", "posts", "pending", "promote"],
		commands: ["social:queue", "social:promote", "social:run", "social:log", "social:ask"],
	},
	{
		id: "skills",
		title: "Skills",
		summary:
			"Skills are promoted intentionally. /skills list shows everything, /skills new scaffolds a draft, /skills doctor validates, /skills drafts shows candidates, /skills promote activates one, /skills reload resets the next session so the refreshed set is loaded.",
		keywords: [
			"skills",
			"skill scaffold",
			"new skill",
			"skill doctor",
			"draft skills",
			"promote skill",
			"reload skills",
		],
		commands: [
			"skills:list",
			"skills:new",
			"skills:scan",
			"skills:doctor",
			"skills:drafts",
			"skills:promote",
			"skills:reload",
		],
	},
	{
		id: "background",
		title: "Background Jobs",
		summary:
			"Background jobs run long tasks asynchronously and notify on completion. /background lists recent jobs; /background show <id> opens a status card; /background cancel <id> aborts a queued or running job.",
		keywords: ["background", "jobs", "long running", "async"],
		commands: ["background", "background:list", "background:show", "background:cancel"],
	},
	{
		id: "reset-session",
		title: "Reset Session",
		summary:
			"Use /new to clear the current chat session and start fresh. /reset is an alias for the same action.",
		keywords: ["reset session", "new session", "start fresh", "clear context"],
		commands: ["new"],
	},
];

// ---------------------------------------------------------------------------
// Lookup indexes
// ---------------------------------------------------------------------------

const COMMAND_BY_ID = new Map(
	TELEGRAM_CONTROL_COMMANDS.map((command) => [command.id, command] as const),
);

/**
 * Domain root names → commands that belong to each domain.
 * Used for hierarchical resolution: "/system sessions" → system:sessions.
 */
const DOMAIN_COMMANDS = new Map<string, TelegramControlCommandDefinition[]>();
const DOMAIN_DEFAULTS = new Map<string, TelegramControlCommandDefinition>();
for (const command of TELEGRAM_CONTROL_COMMANDS) {
	if (!command.domain) continue;
	const list = DOMAIN_COMMANDS.get(command.domain) ?? [];
	list.push(command);
	DOMAIN_COMMANDS.set(command.domain, list);
	if (command.domainDefault) {
		DOMAIN_DEFAULTS.set(command.domain, command);
	}
}

/**
 * Direct trigger map for flat commands (approve, deny, new/reset, otp)
 * and domain roots when used without subcommands.
 */
const DIRECT_TRIGGER_MAP = new Map<string, TelegramControlCommandDefinition>();
for (const command of TELEGRAM_CONTROL_COMMANDS) {
	// Only register flat (non-domain) commands and domain defaults
	if (!command.domain) {
		DIRECT_TRIGGER_MAP.set(command.name, command);
		for (const alias of command.aliases ?? []) {
			DIRECT_TRIGGER_MAP.set(alias, command);
		}
	}
}

const CATALOG_CATEGORY_ORDER: TelegramCommandCategory[] = [
	"Discover",
	"System",
	"Identity",
	"Session",
	"Approvals",
	"Security",
	"Social",
	"Skills",
	"Background",
];

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function normalizeLookup(value: string): string {
	return value
		.toLowerCase()
		.replace(/^\//, "")
		.replace(/[_-]+/g, " ")
		.replace(/[^a-z0-9\s]+/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

function tokenize(value: string): string[] {
	const normalized = normalizeLookup(value);
	return normalized ? normalized.split(" ") : [];
}

function scoreLookup(query: string, terms: string[]): number {
	if (!query) {
		return 0;
	}
	const queryTokens = tokenize(query);
	let best = 0;
	for (const term of terms) {
		const normalizedTerm = normalizeLookup(term);
		if (!normalizedTerm) {
			continue;
		}
		if (normalizedTerm === query) {
			best = Math.max(best, 100);
			continue;
		}
		if (normalizedTerm.includes(query) || query.includes(normalizedTerm)) {
			best = Math.max(best, 60);
			continue;
		}
		const termTokens = new Set(tokenize(normalizedTerm));
		const overlap = queryTokens.filter((token) => termTokens.has(token)).length;
		best = Math.max(best, overlap * 10);
	}
	return best;
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function formatCommandTrigger(command: TelegramControlCommandDefinition): string {
	if (command.domain && command.subcommand) {
		return `/${command.domain} ${command.subcommand}`;
	}
	const aliases = (command.aliases ?? []).map((alias) => `/${alias}`);
	if (aliases.length === 0) {
		return `/${command.name}`;
	}
	return `/${command.name} (aliases: ${aliases.join(", ")})`;
}

function formatCommandLine(command: TelegramControlCommandDefinition): string {
	return `${formatCommandTrigger(command)} - ${command.description}`;
}

function formatCommandDetail(command: TelegramControlCommandDefinition): string {
	const lines = [
		formatCommandTrigger(command),
		"",
		command.description,
		"",
		`Usage: ${command.usage}`,
	];
	if (command.examples?.length) {
		lines.push("", "Examples:");
		for (const example of command.examples) {
			lines.push(`- ${example}`);
		}
	}
	return lines.join("\n");
}

function formatTopicDetail(topic: TelegramHelpTopic): string {
	const lines = [topic.title, "", topic.summary];
	if (topic.commands.length > 0) {
		lines.push("", "Related commands:");
		for (const commandId of topic.commands) {
			const command = getTelegramControlCommand(commandId);
			lines.push(`- ${formatCommandLine(command)}`);
		}
	}
	return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function listTelegramControlCommands(): TelegramControlCommandDefinition[] {
	return [...TELEGRAM_CONTROL_COMMANDS];
}

export function getTelegramControlCommand(
	commandId: TelegramCommandId,
): TelegramControlCommandDefinition {
	const command = COMMAND_BY_ID.get(commandId);
	if (!command) {
		throw new Error(`Unknown Telegram command: ${commandId}`);
	}
	return command;
}

/**
 * Match an incoming message body against the command registry.
 *
 * Supports two forms:
 * 1. Hierarchical: "/system sessions" → system:sessions
 * 2. Shortcuts: "/approve 123" → approve
 */
export function matchTelegramControlCommand(
	body: string,
	options?: { botUsername?: string },
): TelegramCommandMatch | null {
	const trimmed = body.trim();
	if (!trimmed.startsWith("/")) {
		return null;
	}

	const spaceIndex = trimmed.indexOf(" ");
	const rawToken = (spaceIndex === -1 ? trimmed : trimmed.slice(0, spaceIndex)).slice(1);
	const rawArgs = spaceIndex === -1 ? "" : trimmed.slice(spaceIndex + 1).trim();

	let commandToken = rawToken.toLowerCase();
	const atIndex = commandToken.indexOf("@");
	if (atIndex !== -1) {
		const explicitTarget = commandToken.slice(atIndex + 1);
		if (!options?.botUsername) {
			return null;
		}
		if (explicitTarget !== options.botUsername.toLowerCase()) {
			return null;
		}
		commandToken = commandToken.slice(0, atIndex);
	}

	// 1. Try hierarchical domain routing: "/system sessions" → system:sessions
	const domainCommands = DOMAIN_COMMANDS.get(commandToken);
	if (domainCommands) {
		const argParts = rawArgs ? rawArgs.split(/\s+/).filter(Boolean) : [];
		const firstArg = argParts[0]?.toLowerCase();

		if (firstArg) {
			// Try to match subcommand
			const subcommandMatch = domainCommands.find((cmd) => cmd.subcommand === firstArg);
			if (subcommandMatch) {
				const subRawArgs = rawArgs.slice(firstArg.length).trim();
				return {
					command: subcommandMatch,
					commandToken,
					raw: trimmed,
					rawArgs: subRawArgs,
					args: subRawArgs ? subRawArgs.split(/\s+/).filter(Boolean) : [],
				};
			}

			// No subcommand matched but args present — if domain has an "ask" subcommand,
			// route unrecognized tokens to it (e.g. "/social what did you post?" → social:ask).
			const askSubcommand = domainCommands.find((cmd) => cmd.subcommand === "ask");
			if (askSubcommand) {
				return {
					command: askSubcommand,
					commandToken,
					raw: trimmed,
					rawArgs,
					args: rawArgs ? rawArgs.split(/\s+/).filter(Boolean) : [],
				};
			}

			// If the domain default accepts freeform args (e.g. /help [topic]),
			// route to it with the full rawArgs. Otherwise, unknown subcommand.
			const domainDefaultForArgs = DOMAIN_DEFAULTS.get(commandToken);
			if (domainDefaultForArgs?.acceptsFreeformArgs) {
				return {
					command: domainDefaultForArgs,
					commandToken,
					raw: trimmed,
					rawArgs,
					args: rawArgs ? rawArgs.split(/\s+/).filter(Boolean) : [],
				};
			}

			// Unknown subcommand with no ask/freeform fallback — return null so
			// dispatch can show usage instead of silently resolving to the default.
			return null;
		}

		// No args — use domain default (bare "/system")
		const domainDefault = DOMAIN_DEFAULTS.get(commandToken);
		if (domainDefault) {
			return {
				command: domainDefault,
				commandToken,
				raw: trimmed,
				rawArgs: "",
				args: [],
			};
		}
	}

	// 2. Try direct flat commands (approve, deny, new/reset, otp)
	const direct = DIRECT_TRIGGER_MAP.get(commandToken);
	if (direct) {
		return {
			command: direct,
			commandToken,
			aliasUsed: commandToken !== direct.name ? commandToken : undefined,
			raw: trimmed,
			rawArgs,
			args: rawArgs ? rawArgs.split(/\s+/).filter(Boolean) : [],
		};
	}

	return null;
}

export function hasTelegramControlCommand(
	body: string,
	options?: { botUsername?: string },
): boolean {
	return matchTelegramControlCommand(body, options) !== null;
}

/**
 * Check if a message starts with a known domain command token.
 * Used to detect unknown subcommands (e.g. "/system crno") where
 * matchTelegramControlCommand returns null but the user clearly
 * intended a control command.
 */
export function isKnownDomainCommand(body: string): boolean {
	const trimmed = body.trim();
	if (!trimmed.startsWith("/")) return false;
	const token = trimmed.slice(1).split(/[\s@]/)[0]?.toLowerCase();
	if (!token) return false;
	return DOMAIN_COMMANDS.has(token);
}

export function isTelegramAuthExemptCommand(
	body: string,
	options?: { botUsername?: string },
): boolean {
	const match = matchTelegramControlCommand(body, options);
	return match?.command.authExempt === true;
}

// ---------------------------------------------------------------------------
// Help formatting
// ---------------------------------------------------------------------------

export function formatTelegramHelpOverview(): string {
	const lines = [
		"Chat normally — anything not starting with / goes to your AI agent.",
		"",
		"Control plane:",
		"  /system — Status, sessions, cron",
		"  /me — Identity, link/unlink",
		"  /auth — 2FA setup and management",
		"  /social — Social persona, queue, posting",
		"  /skills — Skill drafts and management",
		"  /background — Long-running background jobs",
		"  /new — Reset conversation",
		"",
		"/help <topic> — Learn about approvals, 2fa, sessions, etc.",
		"/help commands — Full command catalog",
	];

	return lines.join("\n");
}

export function formatTelegramCommandCatalog(): string {
	const visibleCommands = TELEGRAM_CONTROL_COMMANDS.filter(
		(command) => command.hideFromCatalog !== true,
	);
	const sections = CATALOG_CATEGORY_ORDER.map((category) => {
		const commands = visibleCommands.filter((command) => command.category === category);
		if (commands.length === 0) {
			return null;
		}
		return [category, ...commands.map((command) => `- ${formatCommandLine(command)}`)].join("\n");
	}).filter(Boolean) as string[];

	return [
		"Telclaude command catalog",
		"",
		...sections,
		"",
		"Use /help <command or topic> for details.",
	].join("\n");
}

export function resolveTelegramHelpQuery(query: string): TelegramHelpMatch | null {
	const normalized = normalizeLookup(query);
	if (!normalized) {
		return null;
	}

	// Check for exact command trigger — support both "system sessions" and "sessions"
	// Try colon-joined form first (e.g. "system sessions" → "system:sessions")
	const colonJoined = normalized.replace(/\s+/, ":");
	const exactById = COMMAND_BY_ID.get(colonJoined as TelegramCommandId);
	if (exactById) {
		return { kind: "command", command: exactById };
	}

	// Try domain default
	const domainDefault = DOMAIN_DEFAULTS.get(normalized);
	if (domainDefault) {
		return { kind: "command", command: domainDefault };
	}

	const exactTopic = TELEGRAM_HELP_TOPICS.find((topic) =>
		topic.keywords.some((keyword) => normalizeLookup(keyword) === normalized),
	);
	if (exactTopic) {
		return { kind: "topic", topic: exactTopic };
	}

	const bestCommand = TELEGRAM_CONTROL_COMMANDS.map((command) => ({
		command,
		score: scoreLookup(normalized, [
			command.name,
			...(command.aliases ?? []),
			command.description,
			command.usage,
			...(command.keywords ?? []),
		]),
	})).sort((a, b) => b.score - a.score)[0];

	const bestTopic = TELEGRAM_HELP_TOPICS.map((topic) => ({
		topic,
		score: scoreLookup(normalized, [topic.title, topic.summary, ...topic.keywords]),
	})).sort((a, b) => b.score - a.score)[0];

	if (bestCommand && bestCommand.score >= Math.max(bestTopic?.score ?? 0, 20)) {
		return { kind: "command", command: bestCommand.command };
	}

	if (bestTopic && bestTopic.score >= 20) {
		return { kind: "topic", topic: bestTopic.topic };
	}

	return null;
}

export function formatTelegramHelp(query?: string): string {
	const trimmedQuery = query?.trim();
	if (!trimmedQuery) {
		return formatTelegramHelpOverview();
	}

	const match = resolveTelegramHelpQuery(trimmedQuery);
	if (!match) {
		return [
			`No help match for "${trimmedQuery}".`,
			"",
			"Try:",
			"- /help approvals",
			"- /help 2fa",
			"- /help system",
			"- /help reset session",
			"",
			"Use /help commands to browse the full catalog.",
		].join("\n");
	}

	return match.kind === "command"
		? formatCommandDetail(match.command)
		: formatTopicDetail(match.topic);
}

/**
 * Build the Telegram bot menu commands, scoped by chat type.
 * Returns entries for setMyCommands per scope.
 */
export function getTelegramMenuCommands(
	scope?: "private" | "group",
): Array<{ command: string; description: string }> {
	const effectiveScope = scope ?? "private";

	if (effectiveScope === "group") {
		// Groups only see /help and /new
		return [
			{ command: "help", description: "Explain commands and topics" },
			{ command: "new", description: "Start a fresh session" },
		];
	}

	// Private chat: domain roots + shortcuts
	return [
		{ command: "help", description: "Explain commands and topics" },
		{ command: "me", description: "Identity management" },
		{ command: "auth", description: "Two-factor authentication" },
		{ command: "system", description: "System introspection" },
		{ command: "social", description: "Social persona management" },
		{ command: "skills", description: "Skill management" },
		{ command: "background", description: "Background jobs" },
		{ command: "approve", description: "Approve a pending request" },
		{ command: "new", description: "Start a fresh session" },
	];
}
