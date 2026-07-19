import { redactSecrets } from "./output-filter.js";

export type OpaqueStringFieldValidators = Readonly<Record<string, (value: string) => boolean>>;

export type StructuredRedactionOptions = {
	/**
	 * Relay-owned fields that are safe to preserve only when their strict value
	 * grammar also validates. Unlisted fields and failed validators default to
	 * content redaction.
	 */
	readonly opaqueFields?: OpaqueStringFieldValidators;
	readonly maxStringLength?: number;
	readonly maxArrayLength?: number;
};

const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX_SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA256_REF_PATTERN = /^sha256:[0-9a-f]{64}$/;

export function isUuidV4(value: string): boolean {
	return UUID_V4_PATTERN.test(value);
}

export function isPrefixedUuidV4(value: string, prefix: string): boolean {
	return value.startsWith(prefix) && isUuidV4(value.slice(prefix.length));
}

export function isSha256Value(value: string): boolean {
	return HEX_SHA256_PATTERN.test(value) || SHA256_REF_PATTERN.test(value);
}

// These validators prove format only. Callers must additionally prove the
// value came from the named relay-owned producer before listing its field.
export function isRelayActionRef(value: string): boolean {
	return isPrefixedUuidV4(value, "effect-");
}

export function isRelayApprovalRequestId(value: string): boolean {
	return isPrefixedUuidV4(value, "mcp-approval-");
}

export function isRelayAttachmentRef(value: string): boolean {
	return /^att_[0-9a-f]{8}\.[1-9][0-9]*\.[0-9a-f]{16}$/.test(value);
}

export function isRelayContainerId(value: string): boolean {
	return /^[0-9a-f]{64}$/.test(value);
}

export function isRelayCronJobId(value: string): boolean {
	return /^cron-[0-9a-f]{8}-[0-9a-f]{3}$/.test(value);
}

export function isRelayCuratorItemId(value: string): boolean {
	return isPrefixedUuidV4(value, "curator-");
}

export function isRelayEdgePreparedRef(value: string): boolean {
	return /^edge-out:[0-9a-f]{32}$/.test(value);
}

export function isRelayReminderId(value: string): boolean {
	return isPrefixedUuidV4(value, "reminder-");
}

export function redactStructuredSecrets(
	value: unknown,
	options: StructuredRedactionOptions = {},
): unknown {
	return redactStructuredValue(value, options, undefined);
}

function redactStructuredValue(
	value: unknown,
	options: StructuredRedactionOptions,
	field: string | undefined,
): unknown {
	if (typeof value === "string") {
		const validator = field === undefined ? undefined : options.opaqueFields?.[field];
		if (validator?.(value) === true) return value;
		const redacted = redactSecrets(value);
		return options.maxStringLength === undefined
			? redacted
			: redacted.slice(0, options.maxStringLength);
	}
	if (Array.isArray(value)) {
		const items =
			options.maxArrayLength === undefined ? value : value.slice(0, options.maxArrayLength);
		return items.map((item) => redactStructuredValue(item, options, undefined));
	}
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value as Record<string, unknown>).map(([key, child]) => [
			key,
			redactStructuredValue(child, options, key),
		]),
	);
}
