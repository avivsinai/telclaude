import { MODEL_CATALOG } from "./model-catalog.js";
import { getChatModelPreference, type ModelPreference } from "./model-preferences.js";

export type ModelFallbackState = "default" | "override" | "fallback";

export type ModelRoute = {
	/** Runtime model override. Undefined means use the Claude SDK default. */
	effectiveModel?: string;
	effectiveProviderId: string;
	fallbackState: ModelFallbackState;
	detail: string;
	requestedProviderId?: string;
	requestedModelId?: string;
};

const SDK_DEFAULT_DETAIL = "SDK default";

export function isExecutableProviderId(providerId: string): boolean {
	return MODEL_CATALOG.some(
		(provider) => provider.id === providerId && provider.execution.executable,
	);
}

export function getModelExecutionBlockReason(providerId: string): string | undefined {
	const provider = MODEL_CATALOG.find((candidate) => candidate.id === providerId);
	if (!provider) return `Unknown provider: ${providerId}`;
	if (provider.execution.executable) return undefined;
	return provider.execution.reason;
}

export function isExecutableModelId(modelId: string): boolean {
	return MODEL_CATALOG.some(
		(provider) =>
			provider.execution.executable && provider.models.some((model) => model.id === modelId),
	);
}

export function assertExecutableModelId(modelId: string): string {
	if (!isExecutableModelId(modelId)) {
		throw new Error(`Model is not executable by this runtime: ${modelId}`);
	}
	return modelId;
}

function findProviderForModel(modelId: string): string | undefined {
	return MODEL_CATALOG.find((provider) => provider.models.some((model) => model.id === modelId))
		?.id;
}

function resolvePreferenceRoute(pref: ModelPreference): ModelRoute {
	const requestedProviderId = pref.providerId;
	const requestedModelId = pref.modelId;

	if (!isExecutableProviderId(requestedProviderId)) {
		return {
			effectiveProviderId: "anthropic",
			fallbackState: "fallback",
			detail: `${SDK_DEFAULT_DETAIL} (ignored ${requestedProviderId}:${requestedModelId})`,
			requestedProviderId,
			requestedModelId,
		};
	}

	const actualModelProviderId = findProviderForModel(requestedModelId);
	if (actualModelProviderId !== requestedProviderId || !isExecutableModelId(requestedModelId)) {
		return {
			effectiveProviderId: "anthropic",
			fallbackState: "fallback",
			detail: `${SDK_DEFAULT_DETAIL} (unknown model: ${requestedModelId})`,
			requestedProviderId,
			requestedModelId,
		};
	}

	return {
		effectiveModel: requestedModelId,
		effectiveProviderId: requestedProviderId,
		fallbackState: "override",
		detail: `${requestedProviderId}:${requestedModelId}`,
		requestedProviderId,
		requestedModelId,
	};
}

export function resolveModelRoute(chatId: number): ModelRoute {
	const pref = getChatModelPreference(chatId);
	if (!pref) {
		return {
			effectiveProviderId: "anthropic",
			fallbackState: "default",
			detail: SDK_DEFAULT_DETAIL,
		};
	}
	return resolvePreferenceRoute(pref);
}

export function formatModelRoute(route: ModelRoute): string {
	switch (route.fallbackState) {
		case "default":
			return route.detail;
		case "override":
			return `override: ${route.detail}`;
		case "fallback":
			return `fallback: ${route.detail}`;
	}
}
