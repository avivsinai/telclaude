export type HermesPrivateRuntimeControlMode = "hermes";
export type HermesPrivateRuntimeControlSource = "hermes-only";

export type HermesPrivateRuntimeEffectiveState = {
	readonly ok: true;
	readonly effectiveMode: "hermes";
	readonly effectiveValue: "1";
	readonly controlMode: "hermes";
	readonly controlSource: "hermes-only";
};

export function readHermesPrivateRuntimeEffectiveState(): HermesPrivateRuntimeEffectiveState {
	return {
		ok: true,
		effectiveMode: "hermes",
		effectiveValue: "1",
		controlMode: "hermes",
		controlSource: "hermes-only",
	};
}
