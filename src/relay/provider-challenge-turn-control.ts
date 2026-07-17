const DEFAULT_BLOCK_TTL_MS = 5 * 60 * 1_000;

export type ProviderChallengeTurnControl = {
	register(turnConversationRef: string, controller: AbortController): () => void;
	block(turnConversationRef: string, expiresAtMs?: number): void;
	isBlocked(turnConversationRef: string, nowMs?: number): boolean;
	cleanup(nowMs?: number): number;
	clear(): void;
};

/**
 * Couples the two independent post-arm controls without carrying challenge
 * data: abort the in-flight Hermes stream and reject later MCP calls for the
 * same relay turn. Only opaque turn refs and expiries are retained.
 */
export function createProviderChallengeTurnControl(input?: {
	readonly nowMs?: () => number;
}): ProviderChallengeTurnControl {
	const nowMs = input?.nowMs ?? Date.now;
	const controllers = new Map<string, Set<AbortController>>();
	const blockedUntil = new Map<string, number>();

	return {
		register(turnConversationRef, controller) {
			const turnRef = normalizeTurnRef(turnConversationRef);
			if (isBlocked(turnRef, nowMs(), blockedUntil)) {
				controller.abort(new Error("Hermes turn closed by relay control"));
				return () => {};
			}
			const registered = controllers.get(turnRef) ?? new Set<AbortController>();
			registered.add(controller);
			controllers.set(turnRef, registered);
			return () => {
				const current = controllers.get(turnRef);
				current?.delete(controller);
				if (current?.size === 0) controllers.delete(turnRef);
			};
		},

		block(turnConversationRef, expiresAtMs = nowMs() + DEFAULT_BLOCK_TTL_MS) {
			const turnRef = normalizeTurnRef(turnConversationRef);
			const normalizedExpiry = normalizeExpiry(expiresAtMs, nowMs());
			blockedUntil.set(turnRef, Math.max(blockedUntil.get(turnRef) ?? 0, normalizedExpiry));
			for (const controller of controllers.get(turnRef) ?? []) {
				if (!controller.signal.aborted) {
					controller.abort(new Error("Hermes turn closed by relay control"));
				}
			}
		},

		isBlocked(turnConversationRef, atMs = nowMs()) {
			return isBlocked(normalizeTurnRef(turnConversationRef), atMs, blockedUntil);
		},

		cleanup(atMs = nowMs()) {
			let removed = 0;
			for (const [turnRef, expiry] of blockedUntil) {
				if (expiry <= atMs) {
					blockedUntil.delete(turnRef);
					removed += 1;
				}
			}
			return removed;
		},

		clear() {
			controllers.clear();
			blockedUntil.clear();
		},
	};
}

export const providerChallengeTurnControl = createProviderChallengeTurnControl();

function isBlocked(
	turnRef: string,
	nowMs: number,
	blockedUntil: ReadonlyMap<string, number>,
): boolean {
	const expiry = blockedUntil.get(turnRef);
	return expiry !== undefined && expiry > nowMs;
}

function normalizeTurnRef(value: string): string {
	const trimmed = value.trim();
	if (!/^turn_[0-9a-f]{32}$/.test(trimmed)) {
		throw new Error("turnConversationRef must be a relay turn ref");
	}
	return trimmed;
}

function normalizeExpiry(value: number, nowMs: number): number {
	if (!Number.isFinite(value) || !Number.isInteger(value) || value <= nowMs) {
		throw new Error("turn block expiry must be a future integer timestamp");
	}
	return value;
}
