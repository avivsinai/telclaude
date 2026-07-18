import type { Command } from "commander";
import {
	HOUSEHOLD_ROLLOUT_RUNGS,
	type HouseholdRolloutRung,
	loadConfig,
	type TelclaudeConfig,
} from "../config/config.js";
import { resolveHouseholdMediaActivation } from "../config/profiles.js";
import {
	collectHouseholdMetricRollups,
	type HouseholdMetricRollup,
} from "../household-metrics/store.js";
import { fetchWithTimeout } from "../infra/timeout.js";
import { checkProviderHealth, type HealthCheckResult } from "../providers/provider-health.js";
import {
	TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV,
	WHATSAPP_SIDECAR_ALLOWED_HOST,
} from "../relay/whatsapp-edge-channel-connector.js";
import { WHATSAPP_BRIDGE_HEALTH_PATH } from "../whatsapp-bridge/contract.js";
import {
	buildReport,
	type CheckResult,
	checkHermesWhatsAppReadiness,
	fail,
	pass,
	skip,
	warn,
	worstStatus,
} from "./doctor-helpers.js";

const HOUSEHOLD_BRIDGE_HEALTH_TIMEOUT_MS = 2_500;
const HOUSEHOLD_MEDIA_CONFIRMATION_KEY_ENV = "TELCLAUDE_HOUSEHOLD_MEDIA_CONFIRMATION_KEY";
const PROVIDER_DETAIL =
	"Health is connector-scoped; per-subject session validity is verified during enrollment.";

export type HouseholdBridgeHealth =
	| {
			reachable: true;
			connected: boolean;
			state: "starting" | "waiting_for_pairing" | "connected" | "disconnected" | "logged_out";
	  }
	| {
			reachable: false;
			state: "unconfigured" | "invalid_config" | "invalid_response" | "unreachable";
	  };

type FetchWithTimeout = typeof fetchWithTimeout;
type LiveHouseholdBridgeHealth = Extract<HouseholdBridgeHealth, { reachable: true }>;
type BridgeRuntimeState = LiveHouseholdBridgeHealth["state"];
type HouseholdBinding = NonNullable<
	TelclaudeConfig["profiles"][number]["whatsappHouseholdBindings"]
>[number];

const BRIDGE_RUNTIME_STATES = new Set<BridgeRuntimeState>([
	"starting",
	"waiting_for_pairing",
	"connected",
	"disconnected",
	"logged_out",
]);

function isBridgeRuntimeState(value: unknown): value is BridgeRuntimeState {
	return typeof value === "string" && BRIDGE_RUNTIME_STATES.has(value as BridgeRuntimeState);
}

export async function probeHouseholdBridgeHealth(
	env: Partial<Record<string, string | undefined>> = process.env,
	fetch: FetchWithTimeout = fetchWithTimeout,
): Promise<HouseholdBridgeHealth> {
	const configuredUrl = env[TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV]?.trim();
	if (!configuredUrl) return { reachable: false, state: "unconfigured" };

	let url: URL;
	try {
		url = new URL(configuredUrl);
	} catch {
		return { reachable: false, state: "invalid_config" };
	}
	if (url.protocol !== "http:" || url.hostname !== WHATSAPP_SIDECAR_ALLOWED_HOST) {
		return { reachable: false, state: "invalid_config" };
	}

	try {
		const response = await fetch(
			new URL(WHATSAPP_BRIDGE_HEALTH_PATH, url).toString(),
			{ method: "GET", headers: { accept: "application/json" } },
			HOUSEHOLD_BRIDGE_HEALTH_TIMEOUT_MS,
		);
		if (!response.ok) return { reachable: false, state: "unreachable" };
		const payload: unknown = await response.json();
		if (typeof payload !== "object" || payload === null) {
			return { reachable: false, state: "invalid_response" };
		}
		const { connected, state } = payload as Record<string, unknown>;
		if (typeof connected !== "boolean" || !isBridgeRuntimeState(state)) {
			return { reachable: false, state: "invalid_response" };
		}
		return { reachable: true, connected, state };
	} catch {
		return { reachable: false, state: "unreachable" };
	}
}

type HouseholdPreflightGate =
	| "bindings"
	| "consent"
	| "bridge"
	| "provider"
	| "media"
	| "data-control"
	| "reminders";

export interface HouseholdPreflightResult {
	report: ReturnType<typeof buildReport>;
	rung: HouseholdRolloutRung;
	nextRung: HouseholdRolloutRung | null;
	unmetForNext: HouseholdPreflightGate[];
}

export interface HouseholdPreflightOptions {
	env?: Partial<Record<string, string | undefined>>;
	checkProviderHealth?: typeof checkProviderHealth;
	probeBridgeHealth?: typeof probeHouseholdBridgeHealth;
}

type ProviderObservation = {
	green: boolean;
	status: "pass" | "warn" | "fail";
	summary: string;
};

export async function runHouseholdPreflight(
	config: TelclaudeConfig,
	options: HouseholdPreflightOptions = {},
): Promise<HouseholdPreflightResult> {
	const env = options.env ?? process.env;
	const bindings = (config.profiles ?? []).flatMap(
		(profile) => profile.whatsappHouseholdBindings ?? [],
	);
	const currentRung = config.householdRollout.rung;
	const nextRung = nextHouseholdRung(currentRung);
	const currentRequirements = requirementsForRung(currentRung);
	const requiredBindings = requiredBindingCount(currentRung);
	const providerConsentCount = bindings.filter(isGrantedProviderConsent).length;
	const reminderConsentCount = bindings.filter(isGrantedReminderConsent).length;
	const consentedCount = bindings.filter(
		(binding) => isGrantedProviderConsent(binding) && isGrantedReminderConsent(binding),
	).length;
	const mediaActivation = resolveHouseholdMediaActivation(
		config,
		env[HOUSEHOLD_MEDIA_CONFIRMATION_KEY_ENV]?.trim(),
	);
	const dataControlGreen = config.householdMedia.dataControlAck?.acknowledged === true;

	const provider = config.providers?.find((candidate) => candidate.id === "clalit");
	const providerHealth = provider
		? await (options.checkProviderHealth ?? checkProviderHealth)("clalit", provider.baseUrl)
		: null;
	const providerObservation = classifyProviderHealth(providerHealth);

	const bridgeReadiness = checkHermesWhatsAppReadiness(
		new Set(config.hermes?.privateRuntime?.outboundChannels ?? []),
		env,
	);
	const bridgeHealth = await (options.probeBridgeHealth ?? probeHouseholdBridgeHealth)(env);
	const bridgeConfigGreen = bridgeReadiness.every((result) => result.status === "pass");
	const bridgeGreen =
		bridgeConfigGreen &&
		bridgeHealth.reachable &&
		bridgeHealth.connected &&
		bridgeHealth.state === "connected";
	const reminderGreen = config.householdReminders.enabled;

	const gateState: Record<HouseholdPreflightGate, boolean> = {
		bindings: bindings.length >= requiredBindings,
		consent: consentedCount >= requiredBindings,
		bridge: bridgeGreen,
		provider: providerObservation.green,
		media: mediaActivation.enabled,
		"data-control": dataControlGreen,
		reminders: reminderGreen,
	};
	const currentUnmet = [...currentRequirements].filter((gate) => !gateState[gate]);

	const checks: CheckResult[] = [
		bindingCheck(bindings, requiredBindings),
		consentCheck(
			bindings.length,
			providerConsentCount,
			reminderConsentCount,
			consentedCount,
			requiredBindings,
		),
		mediaCheck(mediaActivation, currentRequirements.has("media")),
		providerCheck(providerObservation, currentRequirements.has("provider")),
		bridgeCheck(bridgeReadiness, bridgeHealth, bridgeGreen, currentRequirements.has("bridge")),
		dataControlCheck(dataControlGreen, currentRequirements.has("data-control")),
		switchCheck(config, currentRequirements),
		rolloutCheck(currentRung, currentRequirements, currentUnmet),
	];

	return {
		report: buildReport(checks),
		rung: currentRung,
		nextRung,
		unmetForNext: nextRung
			? unmetForRung(nextRung, gateState, bindings.length, consentedCount)
			: [],
	};
}

function isGrantedProviderConsent(binding: HouseholdBinding): boolean {
	return (
		binding.providerConsent?.state === "granted" && binding.providerConsent.revokedAt === undefined
	);
}

function isGrantedReminderConsent(binding: HouseholdBinding): boolean {
	return (
		binding.reminderConsent?.state === "granted" && binding.reminderConsent.revokedAt === undefined
	);
}

function bindingCheck(
	bindings: ReadonlyArray<{
		readonly addresseeGender: "f" | "m";
	}>,
	requiredCount: number,
): CheckResult {
	const female = bindings.filter((binding) => binding.addresseeGender === "f").length;
	const male = bindings.length - female;
	const summary = `${bindings.length} household binding(s) configured`;
	const detail = `required=${requiredCount}; gender-f=${female}; gender-m=${male}`;
	return bindings.length >= requiredCount
		? pass("household.bindings", "bindings", summary, detail)
		: fail("household.bindings", "bindings", summary, detail, "complete household enrollment");
}

function consentCheck(
	bindingCount: number,
	providerCount: number,
	reminderCount: number,
	consentedCount: number,
	requiredCount: number,
): CheckResult {
	const summary = `Consent receipts: provider=${providerCount}/${bindingCount}, reminder=${reminderCount}/${bindingCount}`;
	const detail = `independently consented=${consentedCount}; required=${requiredCount}`;
	return consentedCount >= requiredCount
		? pass("household.consent", "consent", summary, detail)
		: fail(
				"household.consent",
				"consent",
				summary,
				detail,
				"complete and record each consent ceremony",
			);
}

function mediaCheck(
	activation: ReturnType<typeof resolveHouseholdMediaActivation>,
	required: boolean,
): CheckResult {
	if (activation.enabled) {
		return pass(
			"household.media",
			"media",
			"Household media activation gates are green",
			`eligible bindings=${activation.eligibleBindingIds.size}`,
		);
	}
	const summary = `Household media inactive: ${activation.reason}`;
	return required
		? fail("household.media", "media", summary, undefined, "close the reported media gate")
		: skip("household.media", "media", summary, "Media is not required at the current rung.");
}

function classifyProviderHealth(health: HealthCheckResult | null): ProviderObservation {
	if (!health)
		return { green: false, status: "fail", summary: "Clalit provider is not configured" };
	if (!health.reachable || !health.response) {
		return { green: false, status: "fail", summary: "Clalit provider is unreachable" };
	}
	const connector = health.response.connectors?.clalit;
	if (connector?.status === "auth_expired") {
		return { green: false, status: "fail", summary: "Clalit connector authentication expired" };
	}
	if (connector?.status === "error" || health.response.status === "unhealthy") {
		return { green: false, status: "fail", summary: "Clalit connector reports an error" };
	}
	if (connector?.status === "drift_detected") {
		return { green: false, status: "warn", summary: "Clalit connector drift detected" };
	}
	if (health.response.status === "degraded") {
		return { green: false, status: "warn", summary: "Clalit provider is degraded" };
	}
	if (!connector) {
		return { green: false, status: "warn", summary: "Clalit connector status is unavailable" };
	}
	return { green: true, status: "pass", summary: "Clalit connector is healthy" };
}

function providerCheck(observation: ProviderObservation, required: boolean): CheckResult {
	if (observation.status === "pass") {
		return pass("household.provider", "providers", observation.summary, PROVIDER_DETAIL);
	}
	if (observation.status === "warn" || !required) {
		return warn("household.provider", "providers", observation.summary, PROVIDER_DETAIL);
	}
	return fail(
		"household.provider",
		"providers",
		observation.summary,
		PROVIDER_DETAIL,
		"re-enroll the household principal with Clalit",
	);
}

function bridgeCheck(
	readiness: readonly CheckResult[],
	health: HouseholdBridgeHealth,
	green: boolean,
	required: boolean,
): CheckResult {
	const incomplete = readiness.filter((result) => result.status !== "pass").length;
	let summary: string;
	if (incomplete > 0) {
		summary = "WhatsApp bridge configuration is incomplete";
	} else if (!health.reachable) {
		summary = `WhatsApp bridge ${health.state}`;
	} else {
		summary = `WhatsApp bridge state: ${health.state}`;
	}
	const detail = `configuration checks incomplete=${incomplete}; live pairing proven=${green}`;
	if (green) return pass("household.bridge", "bridge", summary, detail);
	return required
		? fail("household.bridge", "bridge", summary, detail, "pair the bridge and send a test message")
		: warn("household.bridge", "bridge", summary, detail);
}

function dataControlCheck(green: boolean, required: boolean): CheckResult {
	if (green) {
		return pass(
			"household.data-control",
			"data-control",
			"OpenAI data-control posture is acknowledged",
		);
	}
	return required
		? fail(
				"household.data-control",
				"data-control",
				"OpenAI data-control posture is not acknowledged",
				undefined,
				"record householdMedia.dataControlAck",
			)
		: skip(
				"household.data-control",
				"data-control",
				"OpenAI data-control posture is not yet required",
			);
}

function switchCheck(
	config: TelclaudeConfig,
	requirements: ReadonlySet<HouseholdPreflightGate>,
): CheckResult {
	const mediaRequired = requirements.has("media");
	const remindersRequired = requirements.has("reminders");
	const missingRequired =
		(mediaRequired && !config.householdMedia.enabled) ||
		(remindersRequired && !config.householdReminders.enabled);
	const armedEarly =
		(!mediaRequired && config.householdMedia.enabled) ||
		(!remindersRequired && config.householdReminders.enabled);
	const summary = [
		`reminders=${onOff(config.householdReminders.enabled)}`,
		`media=${onOff(config.householdMedia.enabled)}`,
		`emergency=${onOff(config.householdEmergency.enabled)}`,
		`metrics=${onOff(config.householdMetrics.enabled)}`,
	].join("; ");
	if (missingRequired) {
		return fail("household.switches", "rollout", summary, "A current-rung lane is not armed.");
	}
	if (armedEarly) {
		return warn("household.switches", "rollout", summary, "A later-rung lane is armed early.");
	}
	return pass("household.switches", "rollout", summary);
}

function rolloutCheck(
	rung: HouseholdRolloutRung,
	requirements: ReadonlySet<HouseholdPreflightGate>,
	unmet: readonly HouseholdPreflightGate[],
): CheckResult {
	const summary = `Current rollout rung: ${rung}`;
	const detail = `required=${[...requirements].join(",")}; unmet=${unmet.join(",") || "none"}`;
	return unmet.length === 0
		? pass("household.rollout", "rollout", summary, detail)
		: fail("household.rollout", "rollout", summary, detail, "close current-rung gates");
}

function requirementsForRung(rung: HouseholdRolloutRung): Set<HouseholdPreflightGate> {
	const index = HOUSEHOLD_ROLLOUT_RUNGS.indexOf(rung);
	const requirements = new Set<HouseholdPreflightGate>(["bindings", "consent"]);
	if (index >= HOUSEHOLD_ROLLOUT_RUNGS.indexOf("parentA_text")) requirements.add("bridge");
	if (index >= HOUSEHOLD_ROLLOUT_RUNGS.indexOf("parentA_clalit")) requirements.add("provider");
	if (index >= HOUSEHOLD_ROLLOUT_RUNGS.indexOf("parentA_media")) {
		requirements.add("media");
		requirements.add("data-control");
	}
	if (index >= HOUSEHOLD_ROLLOUT_RUNGS.indexOf("parentA_reminders")) {
		requirements.add("reminders");
	}
	return requirements;
}

function nextHouseholdRung(rung: HouseholdRolloutRung): HouseholdRolloutRung | null {
	return HOUSEHOLD_ROLLOUT_RUNGS[HOUSEHOLD_ROLLOUT_RUNGS.indexOf(rung) + 1] ?? null;
}

function requiredBindingCount(rung: HouseholdRolloutRung): number {
	return rung.startsWith("parentB_") || rung === "complete" ? 2 : 1;
}

function unmetForRung(
	rung: HouseholdRolloutRung,
	gateState: Readonly<Record<HouseholdPreflightGate, boolean>>,
	bindingCount: number,
	consentedCount: number,
): HouseholdPreflightGate[] {
	const requiredCount = requiredBindingCount(rung);
	return [...requirementsForRung(rung)].filter((gate) => {
		if (gate === "bindings") return bindingCount < requiredCount;
		if (gate === "consent") return consentedCount < requiredCount;
		return !gateState[gate];
	});
}

function onOff(value: boolean): "on" | "off" {
	return value ? "on" : "off";
}

export function formatHouseholdPreflightText(result: HouseholdPreflightResult): string {
	const checksByCategory = new Map<string, CheckResult[]>();
	for (const check of result.report.checks) {
		const checks = checksByCategory.get(check.category) ?? [];
		checks.push(check);
		checksByCategory.set(check.category, checks);
	}

	const lines: string[] = [];
	for (const [category, checks] of checksByCategory) {
		lines.push(category);
		for (const check of checks) {
			lines.push(`  ${check.status.toUpperCase()} ${check.summary}`);
			if (check.detail) lines.push(`    ${check.detail}`);
			if (check.remediation) lines.push(`    try: ${check.remediation}`);
		}
		lines.push("");
	}

	const status = worstStatus(result.report.checks).toUpperCase();
	const { pass: passed, warn: warned, fail: failed, skip: skipped } = result.report.summary;
	lines.push(`Summary: ${status} — pass=${passed} warn=${warned} fail=${failed} skip=${skipped}`);
	lines.push(
		result.nextRung
			? `Ladder: currently at ${result.rung}; to advance to ${result.nextRung} you need: ${result.unmetForNext.join(", ") || "none"}`
			: `Ladder: currently at ${result.rung}; rollout ladder complete`,
	);
	return lines.join("\n");
}

export function householdPreflightExitCode(result: HouseholdPreflightResult): 0 | 1 {
	return worstStatus(result.report.checks) === "fail" ? 1 : 0;
}

export interface HouseholdCommandDependencies {
	loadConfig?: () => TelclaudeConfig;
	runPreflight?: (config: TelclaudeConfig) => Promise<HouseholdPreflightResult>;
	writeOutput?: (value: string) => void;
	setExitCode?: (value: number) => void;
}

export function registerHouseholdCommand(
	parent: Command,
	dependencies: HouseholdCommandDependencies = {},
): void {
	registerHouseholdStatsCommand(parent);
	const readConfig = dependencies.loadConfig ?? loadConfig;
	const runPreflight = dependencies.runPreflight ?? runHouseholdPreflight;
	const writeOutput = dependencies.writeOutput ?? ((value: string) => process.stdout.write(value));
	const setExitCode = dependencies.setExitCode ?? ((value: number) => (process.exitCode = value));

	parent
		.command("preflight")
		.description("Check read-only household activation readiness")
		.option("--json", "Output JSON")
		.action(async (options: { json?: boolean }) => {
			try {
				const result = await runPreflight(readConfig());
				writeOutput(
					`${options.json ? JSON.stringify(result) : formatHouseholdPreflightText(result)}\n`,
				);
				setExitCode(householdPreflightExitCode(result));
			} catch {
				const error = {
					status: "input_error",
					detail: "household preflight could not load required inputs",
				};
				writeOutput(`${options.json ? JSON.stringify(error) : `Input error: ${error.detail}`}\n`);
				setExitCode(2);
			}
		});
}

export type HouseholdStatsRow = HouseholdMetricRollup;

export function collectHouseholdStatsRows(): HouseholdStatsRow[] {
	return collectHouseholdMetricRollups();
}

export function formatHouseholdStatsRows(rows: readonly HouseholdStatsRow[]): string {
	if (rows.length === 0) return "No household metrics recorded.";
	const bindingWidth = Math.max("BINDING".length, ...rows.map((row) => row.bindingKey.length));
	const metricWidth = Math.max("METRIC".length, ...rows.map((row) => row.metricKind.length));
	return [
		`${"BINDING".padEnd(bindingWidth)}  ${"METRIC".padEnd(metricWidth)}  COUNT`,
		...rows.map(
			(row) =>
				`${row.bindingKey.padEnd(bindingWidth)}  ${row.metricKind.padEnd(metricWidth)}  ${row.count}`,
		),
	].join("\n");
}

export function registerHouseholdStatsCommand(parent: Command): void {
	parent
		.command("stats")
		.description("Show content-free household product counters")
		.option("--json", "Output JSON")
		.action((options: { json?: boolean }) => {
			const rows = collectHouseholdStatsRows();
			console.log(options.json ? JSON.stringify(rows, null, 2) : formatHouseholdStatsRows(rows));
		});
}
