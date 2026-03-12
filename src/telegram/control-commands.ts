type TelegramCommandCategory =
	| "Discover"
	| "System"
	| "Identity"
	| "Session"
	| "Approvals"
	| "Security"
	| "Social"
	| "Skills";

export type TelegramCommandId =
	| "help"
	| "commands"
	| "system"
	| "link"
	| "unlink"
	| "whoami"
	| "approve"
	| "deny"
	| "otp"
	| "setup-2fa"
	| "verify-2fa"
	| "disable-2fa"
	| "2fa-logout"
	| "force-reauth"
	| "skip-totp"
	| "status"
	| "sessions"
	| "cron"
	| "heartbeat"
	| "pending"
	| "promote"
	| "public-log"
	| "ask-public"
	| "list-drafts"
	| "promote-skill"
	| "reload-skills"
	| "new";

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

export type TelegramSystemIntent =
	| {
			kind: "command";
			commandId: "status" | "sessions" | "cron" | "whoami";
	  }
	| {
			kind: "help";
			query: string;
	  }
	| {
			kind: "unknown";
	  };

const TELEGRAM_CONTROL_COMMANDS: TelegramControlCommandDefinition[] = [
	{
		id: "help",
		name: "help",
		category: "Discover",
		description: "Explain commands, topics, or operator workflows.",
		usage: "/help [command or topic]",
		examples: ["/help approvals", "/help reset session", "/help cron"],
		keywords: ["help", "docs", "what can i do", "how do i", "explain"],
		readOnly: true,
		menuDescription: "Explain commands and topics",
	},
	{
		id: "commands",
		name: "commands",
		category: "Discover",
		description: "List the Telegram command catalog.",
		usage: "/commands",
		examples: ["/commands"],
		keywords: ["commands", "command list", "menu", "available commands"],
		readOnly: true,
		menuDescription: "List available commands",
	},
	{
		id: "system",
		name: "system",
		category: "System",
		description: "Answer a natural-language question about status, sessions, cron, or identity.",
		usage: "/system <question>",
		examples: [
			"/system what's the current status?",
			"/system any cron jobs running?",
			"/system who am i linked as?",
		],
		keywords: ["system", "status question", "natural language", "what is running"],
		readOnly: true,
		rateLimited: true,
		menuDescription: "Ask about system state",
	},
	{
		id: "status",
		name: "status",
		category: "System",
		description: "Show runtime, security, service, and configuration status.",
		usage: "/status",
		examples: ["/status"],
		keywords: ["status", "health", "runtime", "security", "audit", "config", "environment"],
		readOnly: true,
		rateLimited: true,
		menuDescription: "Show runtime status",
	},
	{
		id: "sessions",
		name: "sessions",
		category: "System",
		description: "Show recent session state for active chats.",
		usage: "/sessions",
		examples: ["/sessions"],
		keywords: ["sessions", "session state", "active sessions", "context"],
		readOnly: true,
		rateLimited: true,
		menuDescription: "Inspect chat sessions",
	},
	{
		id: "cron",
		name: "cron",
		category: "System",
		description: "Show cron scheduler state and recent jobs.",
		usage: "/cron",
		examples: ["/cron", "/system when is the next heartbeat"],
		keywords: ["cron", "schedule", "scheduled jobs", "heartbeat schedule", "next run"],
		readOnly: true,
		rateLimited: true,
		menuDescription: "Inspect cron jobs",
	},
	{
		id: "link",
		name: "link",
		category: "Identity",
		description: "Link this private chat to a local user with a one-time code.",
		usage: "/link <code>",
		examples: ["/link ABCD-1234"],
		keywords: ["link", "pair", "identity link", "bind chat", "claim user"],
		rateLimited: true,
	},
	{
		id: "unlink",
		name: "unlink",
		category: "Identity",
		description: "Remove the identity link for this chat.",
		usage: "/unlink",
		examples: ["/unlink"],
		keywords: ["unlink", "remove link", "disconnect identity"],
	},
	{
		id: "whoami",
		name: "whoami",
		category: "Identity",
		description: "Show which local user this chat is linked to.",
		usage: "/whoami",
		examples: ["/whoami"],
		keywords: ["whoami", "who am i", "identity", "linked user", "which user"],
		readOnly: true,
		menuDescription: "Show linked identity",
	},
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
		id: "setup-2fa",
		name: "setup-2fa",
		category: "Security",
		description: "Start the local TOTP setup flow.",
		usage: "/setup-2fa",
		examples: ["/setup-2fa"],
		keywords: ["2fa", "setup totp", "enable two factor", "totp setup"],
		authExempt: true,
	},
	{
		id: "verify-2fa",
		name: "verify-2fa",
		category: "Security",
		description: "Verify the current TOTP code and start a 2FA-backed session.",
		usage: "/verify-2fa <6-digit-code>",
		examples: ["/verify-2fa 123456"],
		keywords: ["verify 2fa", "totp code", "authenticate"],
		authExempt: true,
	},
	{
		id: "disable-2fa",
		name: "disable-2fa",
		category: "Security",
		description: "Disable TOTP for this chat.",
		usage: "/disable-2fa",
		examples: ["/disable-2fa"],
		keywords: ["disable 2fa", "turn off totp"],
	},
	{
		id: "2fa-logout",
		name: "2fa-logout",
		category: "Security",
		description: "Invalidate the current TOTP-backed session.",
		usage: "/2fa-logout",
		examples: ["/2fa-logout"],
		keywords: ["2fa logout", "logout", "end auth session", "reauth"],
	},
	{
		id: "force-reauth",
		name: "force-reauth",
		category: "Security",
		description: "Invalidate your own 2FA session, or an admin can target another chat.",
		usage: "/force-reauth [chatId]",
		examples: ["/force-reauth", "/force-reauth 123456789"],
		keywords: ["force reauth", "invalidate totp", "end session"],
	},
	{
		id: "skip-totp",
		name: "skip-totp",
		category: "Security",
		description: "Acknowledge that TOTP setup is being skipped for now.",
		usage: "/skip-totp",
		examples: ["/skip-totp"],
		keywords: ["skip totp", "skip 2fa"],
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
	{
		id: "heartbeat",
		name: "heartbeat",
		category: "Social",
		description: "Run a social heartbeat now for one service or all enabled services.",
		usage: "/heartbeat [serviceId]",
		examples: ["/heartbeat", "/heartbeat xtwitter"],
		keywords: ["heartbeat", "social run", "post now", "trigger scheduler"],
		rateLimited: true,
	},
	{
		id: "pending",
		name: "pending",
		category: "Social",
		description: "List pending promotable post ideas.",
		usage: "/pending",
		examples: ["/pending"],
		keywords: ["pending posts", "quarantine", "draft posts"],
		rateLimited: true,
	},
	{
		id: "promote",
		name: "promote",
		category: "Social",
		description: "Promote a pending post idea so it can be published.",
		usage: "/promote <entry-id>",
		examples: ["/promote post_123"],
		keywords: ["promote", "approve post", "publish idea"],
		rateLimited: true,
	},
	{
		id: "public-log",
		name: "public-log",
		category: "Social",
		description: "Summarize recent public persona activity.",
		usage: "/public-log [serviceId] [hours]",
		examples: ["/public-log", "/public-log xtwitter 12"],
		keywords: ["public log", "activity log", "social history"],
		readOnly: true,
		rateLimited: true,
	},
	{
		id: "ask-public",
		name: "ask-public",
		category: "Social",
		description:
			"Ask the social persona a question without routing the reply through the private persona.",
		usage: "/ask-public [serviceId] <question>",
		examples: ["/ask-public what did you post today?", "/ask-public xtwitter draft a reply"],
		keywords: ["ask public", "public persona", "social query"],
		rateLimited: true,
	},
	{
		id: "list-drafts",
		name: "list-drafts",
		category: "Skills",
		description: "List draft skills awaiting promotion.",
		usage: "/list-drafts",
		examples: ["/list-drafts"],
		keywords: ["draft skills", "list drafts", "skills queue"],
		rateLimited: true,
	},
	{
		id: "promote-skill",
		name: "promote-skill",
		category: "Skills",
		description: "Promote a draft skill into the live skill set.",
		usage: "/promote-skill <name>",
		examples: ["/promote-skill my-skill"],
		keywords: ["promote skill", "publish skill"],
		rateLimited: true,
	},
	{
		id: "reload-skills",
		name: "reload-skills",
		category: "Skills",
		description: "Force the next session to start with the latest skills.",
		usage: "/reload-skills",
		examples: ["/reload-skills"],
		keywords: ["reload skills", "refresh skills"],
		rateLimited: true,
	},
];

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
			"Identity linking binds a Telegram chat to a local user. Link in a private chat, inspect it with /whoami, and remove it with /unlink.",
		keywords: ["identity", "link", "unlink", "who am i", "whoami", "pairing"],
		commands: ["link", "whoami", "unlink"],
	},
	{
		id: "2fa",
		title: "Two-Factor Auth",
		summary:
			"2FA is set up locally. /setup-2fa explains the local flow, /verify-2fa activates it, /2fa-logout ends the current session, and /disable-2fa removes it.",
		keywords: ["2fa", "totp", "two factor", "reauth", "force reauth", "auth"],
		commands: ["setup-2fa", "verify-2fa", "2fa-logout", "disable-2fa", "force-reauth", "skip-totp"],
	},
	{
		id: "system",
		title: "System Introspection",
		summary:
			"Use /status for runtime and security state, /sessions for recent chat sessions, /cron for scheduled jobs, or /system <question> when you want the bot to route a natural-language system question for you.",
		keywords: ["system", "status", "sessions", "cron", "health", "diagnostics"],
		commands: ["status", "sessions", "cron", "system"],
	},
	{
		id: "social",
		title: "Social Persona",
		summary:
			"Social commands are still explicit and admin-gated. Use /pending and /promote for queued ideas, /heartbeat to run posting now, /public-log for metadata history, and /ask-public to query the social persona directly.",
		keywords: ["social", "public persona", "heartbeat", "posts", "pending", "promote"],
		commands: ["pending", "promote", "heartbeat", "public-log", "ask-public"],
	},
	{
		id: "skills",
		title: "Skills",
		summary:
			"Skills are promoted intentionally. /list-drafts shows candidates, /promote-skill activates one, and /reload-skills resets the next session so the refreshed set is loaded.",
		keywords: ["skills", "draft skills", "promote skill", "reload skills"],
		commands: ["list-drafts", "promote-skill", "reload-skills"],
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

const COMMAND_BY_ID = new Map(
	TELEGRAM_CONTROL_COMMANDS.map((command) => [command.id, command] as const),
);

const COMMAND_BY_TRIGGER = new Map<string, TelegramControlCommandDefinition>();
for (const command of TELEGRAM_CONTROL_COMMANDS) {
	COMMAND_BY_TRIGGER.set(command.name, command);
	for (const alias of command.aliases ?? []) {
		COMMAND_BY_TRIGGER.set(alias, command);
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
];

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

function formatCommandTrigger(command: TelegramControlCommandDefinition): string {
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

	const command = COMMAND_BY_TRIGGER.get(commandToken);
	if (!command) {
		return null;
	}

	return {
		command,
		commandToken,
		aliasUsed: commandToken !== command.name ? commandToken : undefined,
		raw: trimmed,
		rawArgs,
		args: rawArgs ? rawArgs.split(/\s+/).filter(Boolean) : [],
	};
}

export function hasTelegramControlCommand(
	body: string,
	options?: { botUsername?: string },
): boolean {
	return matchTelegramControlCommand(body, options) !== null;
}

export function isTelegramAuthExemptCommand(body: string): boolean {
	const match = matchTelegramControlCommand(body);
	return match?.command.authExempt === true;
}

export function formatTelegramHelpOverview(): string {
	const lines = [
		"Telclaude help",
		"",
		"Start with:",
		"- /help approvals",
		"- /help reset session",
		"- /help 2fa",
		"- /system what's the current status?",
		"",
		"Common commands:",
		`- ${formatCommandLine(getTelegramControlCommand("help"))}`,
		`- ${formatCommandLine(getTelegramControlCommand("status"))}`,
		`- ${formatCommandLine(getTelegramControlCommand("whoami"))}`,
		`- ${formatCommandLine(getTelegramControlCommand("new"))}`,
		"",
		"Use /commands for the full catalog.",
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

	const exactCommand = COMMAND_BY_TRIGGER.get(normalized);
	if (exactCommand) {
		return { kind: "command", command: exactCommand };
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
			"- /help status",
			"- /help reset session",
			"",
			"Use /commands to browse the full catalog.",
		].join("\n");
	}

	return match.kind === "command"
		? formatCommandDetail(match.command)
		: formatTopicDetail(match.topic);
}

export function getTelegramMenuCommands(): Array<{ command: string; description: string }> {
	return TELEGRAM_CONTROL_COMMANDS.filter((command) => Boolean(command.menuDescription)).map(
		(command) => ({
			command: command.name,
			description: command.menuDescription ?? command.description,
		}),
	);
}

export function resolveTelegramSystemIntent(query: string): TelegramSystemIntent {
	const normalized = normalizeLookup(query);
	if (!normalized) {
		return { kind: "unknown" };
	}

	const whoamiScore = scoreLookup(normalized, [
		"whoami",
		"who am i",
		"identity",
		"linked user",
		"linked chat",
		"who is this chat",
	]);
	const statusScore = scoreLookup(normalized, [
		"status",
		"health",
		"runtime",
		"security",
		"audit",
		"config",
		"environment",
		"version",
		"running",
	]);
	const sessionsScore = scoreLookup(normalized, [
		"sessions",
		"session state",
		"active sessions",
		"conversation context",
		"session age",
	]);
	const cronScore = scoreLookup(normalized, [
		"cron",
		"schedule",
		"scheduled jobs",
		"heartbeat schedule",
		"next heartbeat",
		"next run",
		"jobs",
	]);

	const bestCommand = [
		{ commandId: "whoami" as const, score: whoamiScore },
		{ commandId: "status" as const, score: statusScore },
		{ commandId: "sessions" as const, score: sessionsScore },
		{ commandId: "cron" as const, score: cronScore },
	].sort((a, b) => b.score - a.score)[0];

	if (bestCommand && bestCommand.score >= 20) {
		return { kind: "command", commandId: bestCommand.commandId };
	}

	return { kind: "help", query };
}
