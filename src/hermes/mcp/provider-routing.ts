export type TelclaudeProviderRouteInput = {
	readonly providerId?: string;
	readonly service: string;
	readonly action: string;
	readonly params: Record<string, unknown>;
};

export type TelclaudeProviderOperation = {
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
	readonly params: Record<string, unknown>;
};

const GOOGLE_PROVIDER_ID = "google";
const GOOGLE_SERVICE_IDS = new Set(["gmail", "calendar", "drive", "contacts"]);
const PROVIDER_ACTION_PATTERN = /^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_.:-]+)$/;

export function resolveTelclaudeProviderOperation(
	input: TelclaudeProviderRouteInput,
): TelclaudeProviderOperation {
	const providerId = trimOrUndefined(input.providerId);
	const service = requiredTrimmed(input.service, "service");
	const action = requiredTrimmed(input.action, "action");
	const split = splitProviderAction(action);
	const explicitOrServiceProviderId = providerId ?? providerIdForService(service, split?.service);

	if (
		explicitOrServiceProviderId === GOOGLE_PROVIDER_ID &&
		split &&
		GOOGLE_SERVICE_IDS.has(split.service)
	) {
		return {
			providerId: GOOGLE_PROVIDER_ID,
			service: split.service,
			action: split.action,
			params: input.params,
		};
	}

	return {
		providerId: explicitOrServiceProviderId,
		service,
		action,
		params: input.params,
	};
}

export function providerAccountRefFor(operation: TelclaudeProviderOperation): string {
	if (operation.providerId === operation.service) {
		return `${operation.providerId}:primary`;
	}
	return `${operation.providerId}:${operation.service}:primary`;
}

export function providerApprovalRenderFor(operation: TelclaudeProviderOperation): string {
	return `${operation.providerId}.${operation.service}.${operation.action}`;
}

function providerIdForService(service: string, actionService: string | undefined): string {
	if (
		service === GOOGLE_PROVIDER_ID ||
		GOOGLE_SERVICE_IDS.has(service) ||
		(actionService !== undefined && GOOGLE_SERVICE_IDS.has(actionService))
	) {
		return GOOGLE_PROVIDER_ID;
	}
	return service;
}

function splitProviderAction(action: string): { service: string; action: string } | null {
	const match = action.match(PROVIDER_ACTION_PATTERN);
	if (!match) return null;
	return { service: match[1], action: match[2] };
}

function trimOrUndefined(value: string | undefined): string | undefined {
	if (value === undefined) return undefined;
	const trimmed = value.trim();
	return trimmed || undefined;
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`provider ${field} is required`);
	return trimmed;
}
