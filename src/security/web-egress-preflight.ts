/**
 * Shared outbound web-egress preflight.
 *
 * Any relay surface that lets contained compute reach the public web (the
 * served-MCP `tc_web_fetch`/`tc_web_search` tools and the browser broker) can be
 * turned into an exfiltration channel: a private turn can read private memory,
 * so a secret-shaped or private-data value placed in an outbound URL or query
 * would leave the relay boundary. This module is the single fail-closed guard
 * those surfaces run BEFORE any network or provider call.
 *
 * It is intentionally not a DLP classifier — it is pattern-based secret
 * detection (the streaming output filter) plus a small high-confidence
 * private-data denylist. The errors carry only the field name and a reason
 * category, never the offending value.
 */

import { filterOutput } from "./output-filter.js";

export class WebEgressSecretError extends Error {
	readonly code = "mcp_outbound_secret_blocked";

	constructor(field: string) {
		super(`outbound ${field} blocked: secret-shaped material must not leave via web egress`);
		this.name = "WebEgressSecretError";
	}
}

export class WebEgressPrivateDataError extends Error {
	readonly code = "mcp_outbound_private_data_blocked";

	constructor(field: string, reason: string) {
		super(`outbound ${field} blocked: private data must not leave via web egress (${reason})`);
		this.name = "WebEgressPrivateDataError";
	}
}

/**
 * Fail closed if `value` carries secret-shaped or obvious private-data material.
 * Throws `WebEgressSecretError` / `WebEgressPrivateDataError`; both expose a
 * stable `.code` consumed by the MCP error mapping.
 */
export function assertSafeWebEgress(value: string, field: string): void {
	if (filterOutput(value).blocked) {
		throw new WebEgressSecretError(field);
	}
	const privateDataReason = privateDataEgressReason(value);
	if (privateDataReason) {
		throw new WebEgressPrivateDataError(field, privateDataReason);
	}
}

export function privateDataEgressReason(value: string): string | undefined {
	const decoded = decodeURIComponentSafe(value);
	const normalized = decoded.replace(/\s+/g, " ").trim().toLowerCase();
	if (!normalized) return undefined;
	if (/\b\d{3}-\d{2}-\d{4}\b/.test(normalized)) return "ssn-like identifier";
	if (
		/\b(?:my|our|family|wife|husband|child|kid|son|daughter)\s+(?:home\s+)?address\s+(?:is|:)\s+\S/.test(
			normalized,
		)
	) {
		return "address disclosure phrase";
	}
	if (
		/\b(?:my|our|family|wife|husband|child|kid|son|daughter)\s+(?:email|e-mail|phone|mobile|cell)\s+(?:is|:)\s+\S/.test(
			normalized,
		)
	) {
		return "contact disclosure phrase";
	}
	if (
		/\b(?:my|our|family)\s+(?:passport|national id|identity number|bank account|iban|credit card)\s+(?:is|:)\s+\S/.test(
			normalized,
		)
	) {
		return "identity or financial disclosure phrase";
	}
	return undefined;
}

function decodeURIComponentSafe(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}
