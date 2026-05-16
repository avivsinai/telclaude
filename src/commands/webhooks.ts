import fs from "node:fs";
import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { deleteSecret, storeSecret } from "../secrets/index.js";
import { assertWebhookSecret } from "../webhooks/auth.js";
import {
	createWebhook,
	getWebhook,
	listWebhooks,
	removeWebhook,
	setWebhookEnabled,
	touchWebhookUpdated,
	webhookSecretId,
} from "../webhooks/store.js";

function collectRepeated(value: string, previous: string[] | undefined): string[] {
	return [...(previous ?? []), value];
}

function readSecretFromStdin(): string {
	const secret = fs.readFileSync(0, "utf8").trim();
	assertWebhookSecret(secret);
	return secret;
}

function parsePositiveInteger(raw: string | undefined, label: string): number | undefined {
	if (raw === undefined) return undefined;
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isInteger(parsed) || parsed <= 0) {
		throw new Error(`${label} must be a positive integer`);
	}
	return parsed;
}

function printWebhooks(json: boolean | undefined): void {
	const webhooks = listWebhooks();
	if (json) {
		console.log(JSON.stringify({ webhooks }, null, 2));
		return;
	}
	if (webhooks.length === 0) {
		console.log("No webhooks.");
		return;
	}
	console.log("Slug                 Enabled Target Cron Job       Rate/h Hits Last Hit");
	for (const webhook of webhooks) {
		const slug = webhook.slug.padEnd(20).slice(0, 20);
		const enabled = (webhook.enabled ? "yes" : "no").padEnd(7);
		const target = webhook.targetCronJobId.padEnd(21).slice(0, 21);
		const rate = String(webhook.rateLimitPerHour).padEnd(6);
		const hits = String(webhook.hitCount).padEnd(4);
		const lastHit = webhook.lastHitAtMs ? new Date(webhook.lastHitAtMs).toISOString() : "-";
		console.log(`${slug} ${enabled} ${target} ${rate} ${hits} ${lastHit}`);
	}
}

export function registerWebhooksCommand(parent: Command): void {
	const webhooks = parent
		.command("webhooks")
		.description("Manage signed local webhook receivers for preconfigured cron jobs");

	webhooks
		.command("list")
		.description("List webhook definitions")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean }) => {
			printWebhooks(opts.json);
		});

	webhooks
		.command("add")
		.description("Create a disabled-by-default webhook definition")
		.requiredOption("--slug <slug>", "Webhook slug used in /v1/webhooks/:slug")
		.requiredOption("--target-cron-job <id>", "Existing enabled cron job id")
		.requiredOption("--secret-stdin", "Read HMAC secret from stdin")
		.option("--allowed-cidrs <cidr>", "Allowed source CIDR; repeatable", collectRepeated)
		.option("--rate-limit-per-hour <n>", "Per-webhook hourly limit")
		.option("--enabled", "Create enabled")
		.option("--json", "Output as JSON")
		.action(
			async (opts: {
				slug: string;
				targetCronJob: string;
				secretStdin: boolean;
				allowedCidrs?: string[];
				rateLimitPerHour?: string;
				enabled?: boolean;
				json?: boolean;
			}) => {
				try {
					if (!opts.secretStdin) {
						throw new Error("--secret-stdin is required");
					}
					if (getWebhook(opts.slug)) {
						throw new Error(`webhook '${opts.slug}' already exists`);
					}
					const secret = readSecretFromStdin();
					const cfg = loadConfig();
					const rateLimit =
						parsePositiveInteger(opts.rateLimitPerHour, "--rate-limit-per-hour") ??
						cfg.webhooks.defaultRateLimitPerHour;
					const secretId = webhookSecretId(opts.slug);
					await storeSecret(secretId, secret);
					try {
						const webhook = createWebhook({
							slug: opts.slug,
							targetCronJobId: opts.targetCronJob,
							vaultSecretId: secretId,
							allowedCidrs: opts.allowedCidrs,
							rateLimitPerHour: rateLimit,
							enabled: opts.enabled === true,
						});
						if (opts.json) {
							console.log(JSON.stringify({ webhook }, null, 2));
							return;
						}
						console.log(
							`Added webhook ${webhook.slug} (${webhook.enabled ? "enabled" : "disabled"})`,
						);
						console.log(`  URL path: /v1/webhooks/${webhook.slug}`);
						console.log(`  Target cron job: ${webhook.targetCronJobId}`);
						console.log(`  Secret id: ${webhook.vaultSecretId}`);
					} catch (err) {
						await deleteSecret(secretId);
						throw err;
					}
				} catch (err) {
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exitCode = 1;
				}
			},
		);

	webhooks
		.command("enable")
		.description("Enable a webhook")
		.argument("<slug>", "Webhook slug")
		.action((slug: string) => {
			try {
				const webhook = setWebhookEnabled(slug, true);
				if (!webhook) throw new Error(`unknown webhook '${slug}'`);
				console.log(`Enabled webhook ${webhook.slug}`);
			} catch (err) {
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});

	webhooks
		.command("disable")
		.description("Disable a webhook")
		.argument("<slug>", "Webhook slug")
		.action((slug: string) => {
			try {
				const webhook = setWebhookEnabled(slug, false);
				if (!webhook) throw new Error(`unknown webhook '${slug}'`);
				console.log(`Disabled webhook ${webhook.slug}`);
			} catch (err) {
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});

	webhooks
		.command("rotate-secret")
		.description("Replace a webhook HMAC secret")
		.argument("<slug>", "Webhook slug")
		.requiredOption("--secret-stdin", "Read HMAC secret from stdin")
		.action(async (slug: string, opts: { secretStdin: boolean }) => {
			try {
				if (!opts.secretStdin) {
					throw new Error("--secret-stdin is required");
				}
				const webhook = getWebhook(slug);
				if (!webhook) throw new Error(`unknown webhook '${slug}'`);
				const secret = readSecretFromStdin();
				await storeSecret(webhook.vaultSecretId, secret);
				touchWebhookUpdated(webhook.slug);
				console.log(`Rotated secret for webhook ${webhook.slug}`);
			} catch (err) {
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});

	webhooks
		.command("remove")
		.description("Remove a webhook and delete its stored secret")
		.argument("<slug>", "Webhook slug")
		.action(async (slug: string) => {
			try {
				const removed = removeWebhook(slug);
				if (!removed) throw new Error(`unknown webhook '${slug}'`);
				await deleteSecret(removed.vaultSecretId);
				console.log(`Removed webhook ${removed.slug}`);
			} catch (err) {
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});
}
