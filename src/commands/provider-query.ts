/**
 * CLI command for querying external providers via relay proxy.
 *
 * This command allows the agent to make POST requests to providers
 * through the relay's /v1/provider/proxy endpoint. The relay handles
 * HMAC authentication, response sanitization (strips inline base64),
 * and attachment storage.
 *
 * Usage:
 *   telclaude provider-query --provider israel-services --service clalit --action appointments
 *   telclaude provider-query --provider israel-services --service poalim --action scrape --params '{"startDate":"2024-01-01"}'
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { relayProviderProxy } from "../relay/capabilities-client.js";

const logger = getChildLogger({ module: "cmd-provider-query" });

export type ProviderQueryOptions = {
	provider?: string;
	service?: string;
	action?: string;
	params?: string;
	userId?: string;
	subjectUserId?: string;
	idempotencyKey?: string;
};

export function registerProviderQueryCommand(program: Command): void {
	program
		.command("provider-query")
		.description("Query an external provider via the relay proxy")
		.option("--provider <id>", "Provider ID (from telclaude.json)")
		.option("--service <id>", "Service ID (e.g., clalit, poalim)")
		.option("--action <name>", "Action name (e.g., appointments, scrape)")
		.option("--params <json>", "Optional JSON parameters")
		.option("--user-id <id>", "Actor user ID for the request (optional)")
		.option("--subject-user-id <id>", "Subject user ID for delegated requests")
		.option("--idempotency-key <key>", "Idempotency key for write operations")
		.action(async (opts: ProviderQueryOptions) => {
			try {
				const useRelay = Boolean(process.env.TELCLAUDE_CAPABILITIES_URL);
				if (!useRelay) {
					console.error("Error: TELCLAUDE_CAPABILITIES_URL is not configured.");
					console.error("This command requires the relay capabilities server.");
					process.exit(1);
				}

				const providerId = opts.provider?.trim();
				const service = opts.service?.trim();
				const action = opts.action?.trim();

				if (!providerId) {
					console.error("Error: --provider is required.");
					console.error(
						"Usage: telclaude provider-query --provider <id> --service <id> --action <name>",
					);
					process.exit(1);
				}

				if (!service || !action) {
					console.error("Error: --service and --action are required.");
					console.error(
						"Usage: telclaude provider-query --provider <id> --service <id> --action <name>",
					);
					process.exit(1);
				}

				// Parse params if provided
				let params: Record<string, unknown> = {};
				if (opts.params) {
					try {
						params = JSON.parse(opts.params) as Record<string, unknown>;
					} catch (parseErr) {
						console.error(`Error: Invalid JSON in --params: ${String(parseErr)}`);
						process.exit(1);
					}
				}

				// Build the provider request body
				const requestBody: Record<string, unknown> = {
					params,
				};

				// Add optional fields if provided
				const subjectUserId = opts.subjectUserId?.trim();
				const idempotencyKey = opts.idempotencyKey?.trim();
				if (subjectUserId) {
					requestBody.subjectUserId = subjectUserId;
				}
				if (idempotencyKey) {
					requestBody.idempotencyKey = idempotencyKey;
				}

				const userId = opts.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID;

				logger.info(
					{ providerId, service, action, hasParams: Object.keys(params).length > 0 },
					"querying provider",
				);

				const result = await relayProviderProxy({
					providerId,
					path: `/v1/${service}/${action}`,
					method: "POST",
					body: JSON.stringify(requestBody),
					userId,
				});

				if (result.status !== "ok" && result.error) {
					console.error(`Error: ${result.error}`);
					process.exit(1);
				}

				// Output the full response as JSON for the agent to parse
				console.log(JSON.stringify(result.data ?? result, null, 2));
			} catch (err) {
				logger.error({ error: String(err) }, "provider-query command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
