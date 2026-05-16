import { MODEL_CATALOG } from "./model-catalog.js";
import { getChatModelPreference, type ModelPreference } from "./model-preferences.js";
import type { EffectiveOperatorProfile } from "./profiles.js";

export type ModelFallbackState = "default" | "override" | "profile" | "fallback";

export type ModelRoute = {
	/** Runtime model override. Undefined means use the Claude SDK default. */
	effectiveModel?: string;
	effectiveProviderId: string;
	fallbackState: ModelFallbackState;
	detail: string;
	requestedProviderId?: string;
	requestedModelId?: string;
	profileId?: string;
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

type ModelSelection = Pick<ModelPreference, "providerId" | "modelId">;

function resolveSelectionRoute(
	selection: ModelSelection,
	source: "preference" | "profile",
): ModelRoute {
	const requestedProviderId = selection.providerId;
	const requestedModelId = selection.modelId;

	if (!isExecutableProviderId(requestedProviderId)) {
		return {
			effectiveProviderId: "anthropic",
			fallbackState: "fallback",
			detail: `${SDK_DEFAULT_DETAIL} (ignored ${source} ${requestedProviderId}:${requestedModelId})`,
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
		fallbackState: source === "profile" ? "profile" : "override",
		detail: `${requestedProviderId}:${requestedModelId}`,
		requestedProviderId,
		requestedModelId,
	};
}

function resolveProfileDefaultRoute(profile?: EffectiveOperatorProfile): ModelRoute | null {
	if (!profile?.defaultModel) return null;
	const route = resolveSelectionRoute(profile.defaultModel, "profile");
	return { ...route, profileId: profile.id };
}

export function resolveModelRoute(
	chatId: number,
	options: { profile?: EffectiveOperatorProfile } = {},
): ModelRoute {
	const pref = getChatModelPreference(chatId);
	const profileRoute = resolveProfileDefaultRoute(options.profile);
	if (pref) {
		const prefRoute = resolveSelectionRoute(pref, "preference");
		if (prefRoute.fallbackState !== "fallback") return prefRoute;
		if (profileRoute && profileRoute.fallbackState !== "fallback") {
			return {
				...profileRoute,
				fallbackState: "fallback",
				detail: `${prefRoute.detail}; using profile default ${profileRoute.detail}`,
				requestedProviderId: pref.providerId,
				requestedModelId: pref.modelId,
			};
		}
		if (profileRoute?.fallbackState === "fallback") {
			return {
				...prefRoute,
				detail: `${prefRoute.detail}; profile default unavailable: ${profileRoute.detail}`,
			};
		}
		return prefRoute;
	}
	if (profileRoute) {
		if (profileRoute.fallbackState === "fallback") {
			return {
				...profileRoute,
				detail: `${profileRoute.detail}; using ${SDK_DEFAULT_DETAIL}`,
			};
		}
		return profileRoute;
	}
	return {
		effectiveProviderId: "anthropic",
		fallbackState: "default",
		detail: SDK_DEFAULT_DETAIL,
	};
}

export function formatModelRoute(route: ModelRoute): string {
	switch (route.fallbackState) {
		case "default":
			return route.detail;
		case "override":
			return `override: ${route.detail}`;
		case "profile":
			return `profile: ${route.detail}`;
		case "fallback":
			return `fallback: ${route.detail}`;
	}
}
