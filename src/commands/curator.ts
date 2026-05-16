import fs from "node:fs";
import type { Command } from "commander";
import { runCuratorScan } from "../curator/actions.js";
import {
	type CuratorProducerEnvelope,
	type SignedCuratorProducerKind,
	signCuratorProducerEnvelope,
	upsertSignedCuratorItem,
} from "../curator/auth.js";
import { decideCuratorItem, getCuratorItem, listCuratorItems } from "../curator/store.js";
import type {
	CuratorItem,
	CuratorItemInput,
	CuratorItemKind,
	CuratorItemStatus,
	CuratorProducerKind,
	CuratorSeverity,
} from "../curator/types.js";
import { getVaultClient, type VaultClient } from "../vault-daemon/client.js";

const CURATOR_KINDS: CuratorItemKind[] = [
	"cron_hardening",
	"background_attention",
	"memory_queue",
	"skill_review",
];
const CURATOR_SEVERITIES: CuratorSeverity[] = ["info", "low", "medium", "high"];
const SIGNED_CURATOR_PRODUCERS: SignedCuratorProducerKind[] = ["claude-code", "codex"];

function handleCommandError(err: unknown): void {
	console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
	process.exitCode = 1;
}

function asRecord(value: unknown, field: string): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error(`${field} must be a JSON object`);
	}
	return value as Record<string, unknown>;
}

function unwrapJsonObject(value: unknown, key: "item" | "envelope"): unknown {
	const record = value && typeof value === "object" && !Array.isArray(value) ? value : null;
	if (record && key in record) {
		return (record as Record<string, unknown>)[key];
	}
	return value;
}

function requiredString(value: unknown, field: string): string {
	if (typeof value !== "string") {
		throw new Error(`${field} must be a string`);
	}
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`${field} must not be empty`);
	}
	return trimmed;
}

function optionalString(value: unknown, field: string): string | undefined {
	if (value === undefined || value === null) return undefined;
	return requiredString(value, field);
}

function optionalNumber(value: unknown, field: string): number | undefined {
	if (value === undefined || value === null) return undefined;
	if (typeof value !== "number" || !Number.isFinite(value)) {
		throw new Error(`${field} must be a finite number`);
	}
	return value;
}

function enumValue<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
	const stringValue = requiredString(value, field);
	if (!allowed.includes(stringValue as T)) {
		throw new Error(`${field} must be one of ${allowed.join(", ")}`);
	}
	return stringValue as T;
}

function readJsonFile(filePath: string): unknown {
	try {
		return JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
	} catch (err) {
		throw new Error(
			`failed to read JSON from ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
}

function parseTtlMs(raw: string | undefined): number | undefined {
	if (!raw) return undefined;
	const value = Number(raw);
	if (!Number.isFinite(value) || value <= 0) {
		throw new Error("--ttl-ms must be a positive number");
	}
	return Math.trunc(value);
}

export function parseCuratorItemInput(value: unknown): CuratorItemInput {
	const record = asRecord(unwrapJsonObject(value, "item"), "item");
	return {
		fingerprint: requiredString(record.fingerprint, "item.fingerprint"),
		kind: enumValue(record.kind, "item.kind", CURATOR_KINDS),
		severity: enumValue(record.severity, "item.severity", CURATOR_SEVERITIES),
		source: requiredString(record.source, "item.source"),
		title: requiredString(record.title, "item.title"),
		summary: requiredString(record.summary, "item.summary"),
		...(optionalString(record.rationale, "item.rationale")
			? { rationale: optionalString(record.rationale, "item.rationale") }
			: {}),
		entityRef: requiredString(record.entityRef, "item.entityRef"),
		proposedAction: asRecord(record.proposedAction, "item.proposedAction"),
		evidence: asRecord(record.evidence, "item.evidence"),
		...(record.producerKind !== undefined
			? {
					producerKind: enumValue(record.producerKind, "item.producerKind", [
						"system",
						...SIGNED_CURATOR_PRODUCERS,
					] as CuratorProducerKind[]),
				}
			: {}),
		...(optionalString(record.producerId, "item.producerId")
			? { producerId: optionalString(record.producerId, "item.producerId") }
			: {}),
		...(optionalNumber(record.expiresAtMs, "item.expiresAtMs") !== undefined
			? { expiresAtMs: optionalNumber(record.expiresAtMs, "item.expiresAtMs") }
			: {}),
	};
}

export function parseCuratorProducerEnvelope(value: unknown): CuratorProducerEnvelope {
	const record = asRecord(unwrapJsonObject(value, "envelope"), "envelope");
	return {
		producerKind: enumValue(record.producerKind, "envelope.producerKind", SIGNED_CURATOR_PRODUCERS),
		producerId: requiredString(record.producerId, "envelope.producerId"),
		claimsHash: requiredString(record.claimsHash, "envelope.claimsHash"),
		expiresAtMs:
			optionalNumber(record.expiresAtMs, "envelope.expiresAtMs") ??
			(() => {
				throw new Error("envelope.expiresAtMs must be a finite number");
			})(),
		signature: requiredString(record.signature, "envelope.signature"),
	};
}

export async function signCuratorProducerItem(
	input: CuratorItemInput,
	options: {
		vault?: Pick<VaultClient, "signPayload">;
		producerKind: SignedCuratorProducerKind;
		producerId: string;
		ttlMs?: number;
		nowMs?: number;
	},
): Promise<CuratorProducerEnvelope> {
	return signCuratorProducerEnvelope(input, {
		vaultClient: options.vault ?? getVaultClient(),
		producerKind: options.producerKind,
		producerId: options.producerId,
		...(options.ttlMs ? { ttlMs: options.ttlMs } : {}),
		...(options.nowMs ? { nowMs: options.nowMs } : {}),
	});
}

export async function submitSignedCuratorProducerItem(
	input: CuratorItemInput,
	envelope: CuratorProducerEnvelope,
	options: {
		vault?: Pick<VaultClient, "verifyPayload">;
		nowMs?: number;
	} = {},
): Promise<CuratorItem> {
	return upsertSignedCuratorItem(input, envelope, {
		vaultClient: options.vault ?? getVaultClient(),
		...(options.nowMs ? { nowMs: options.nowMs } : {}),
	});
}

function formatItem(item: CuratorItem): string {
	return [
		`${item.shortId} ${item.severity.toUpperCase()} ${item.kind} ${item.status}`,
		`  ${item.title}`,
		`  ${item.summary}`,
		`  entity: ${item.entityRef}`,
	].join("\n");
}

export function registerCuratorCommand(program: Command): void {
	const curator = program
		.command("curator")
		.description("Review local Curator suggestions for safer, more useful automation");

	curator
		.command("scan")
		.description("Scan local telclaude state for reviewable suggestions")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean }) => {
			const result = runCuratorScan({ producerKind: "system" });
			if (opts.json) {
				console.log(JSON.stringify(result, null, 2));
				return;
			}
			console.log(
				`Curator scan created/updated ${result.createdOrUpdated} item(s); ${result.openItems} open.`,
			);
		});

	curator
		.command("sign-producer")
		.description("Sign a Curator item JSON file for a Claude Code or Codex producer")
		.requiredOption("--item <path>", "Curator item JSON file, optionally wrapped as { item }")
		.requiredOption("--producer-kind <kind>", "claude-code or codex")
		.requiredOption("--producer-id <id>", "Stable producer id for audit attribution")
		.option("--ttl-ms <ms>", "Envelope lifetime in milliseconds")
		.action(
			async (opts: { item: string; producerKind: string; producerId: string; ttlMs?: string }) => {
				try {
					const input = parseCuratorItemInput(readJsonFile(opts.item));
					const envelope = await signCuratorProducerItem(input, {
						producerKind: enumValue(opts.producerKind, "--producer-kind", SIGNED_CURATOR_PRODUCERS),
						producerId: opts.producerId,
						ttlMs: parseTtlMs(opts.ttlMs),
					});
					console.log(JSON.stringify({ envelope }, null, 2));
				} catch (err) {
					handleCommandError(err);
				}
			},
		);

	curator
		.command("submit-signed")
		.description("Verify and submit a signed Claude Code or Codex Curator item")
		.requiredOption("--item <path>", "Curator item JSON file, optionally wrapped as { item }")
		.requiredOption(
			"--envelope <path>",
			"Curator producer envelope JSON file, optionally wrapped as { envelope }",
		)
		.option("--json", "Output as JSON")
		.action(async (opts: { item: string; envelope: string; json?: boolean }) => {
			try {
				const input = parseCuratorItemInput(readJsonFile(opts.item));
				const envelope = parseCuratorProducerEnvelope(readJsonFile(opts.envelope));
				const item = await submitSignedCuratorProducerItem(input, envelope);
				if (opts.json) {
					console.log(JSON.stringify({ item }, null, 2));
					return;
				}
				console.log(
					`Submitted ${item.shortId} from ${item.producerKind}:${item.producerId ?? "unknown"}.`,
				);
			} catch (err) {
				handleCommandError(err);
			}
		});

	curator
		.command("list")
		.description("List Curator suggestions")
		.option("--status <status>", "open, accepted, rejected, expired, or all", "open")
		.option("--json", "Output as JSON")
		.action((opts: { status?: string; json?: boolean }) => {
			const status = opts.status === "all" ? "all" : (opts.status ?? "open");
			if (!["open", "accepted", "rejected", "expired", "all"].includes(status)) {
				console.error("Error: --status must be open, accepted, rejected, expired, or all");
				process.exitCode = 1;
				return;
			}
			const items = listCuratorItems({ status: status as CuratorItemStatus | "all" });
			if (opts.json) {
				console.log(JSON.stringify({ items }, null, 2));
				return;
			}
			if (items.length === 0) {
				console.log("No curator items.");
				return;
			}
			console.log(items.map(formatItem).join("\n\n"));
		});

	curator
		.command("show")
		.description("Show one Curator suggestion")
		.argument("<id>", "Curator id or short id")
		.option("--json", "Output as JSON")
		.action((id: string, opts: { json?: boolean }) => {
			const item = getCuratorItem(id);
			if (!item) {
				console.error(`Error: unknown curator item '${id}'`);
				process.exitCode = 1;
				return;
			}
			if (opts.json) {
				console.log(JSON.stringify({ item }, null, 2));
				return;
			}
			console.log(formatItem(item));
		});

	curator
		.command("accept")
		.description("Accept a Curator suggestion without performing the privileged action")
		.argument("<id>", "Curator id or short id")
		.option("--actor <id>", "Actor id for audit", "cli:operator")
		.action((id: string, opts: { actor?: string }) => {
			const item = decideCuratorItem({
				id,
				status: "accepted",
				actor: opts.actor ?? "cli:operator",
			});
			if (!item) {
				console.error(`Error: unknown curator item '${id}'`);
				process.exitCode = 1;
				return;
			}
			console.log(`Accepted ${item.shortId}. Next action remains manual: ${item.entityRef}`);
		});

	curator
		.command("reject")
		.description("Reject a Curator suggestion")
		.argument("<id>", "Curator id or short id")
		.option("--actor <id>", "Actor id for audit", "cli:operator")
		.option("--reason <text>", "Optional decision reason")
		.action((id: string, opts: { actor?: string; reason?: string }) => {
			const item = decideCuratorItem({
				id,
				status: "rejected",
				actor: opts.actor ?? "cli:operator",
				...(opts.reason ? { reason: opts.reason } : {}),
			});
			if (!item) {
				console.error(`Error: unknown curator item '${id}'`);
				process.exitCode = 1;
				return;
			}
			console.log(`Rejected ${item.shortId}.`);
		});
}
