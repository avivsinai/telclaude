import crypto from "node:crypto";

export type HermesSessionRecord = {
	sessionKey: string;
	profileId: string;
	telclaudeSessionId: string;
	hermesSessionId?: string;
	createdAt: number;
	updatedAt: number;
};

export class HermesSessionMap {
	private readonly records = new Map<string, HermesSessionRecord>();

	constructor(
		private readonly createTelclaudeSessionId: () => string = () => crypto.randomUUID(),
	) {}

	get(sessionKey: string, profileId: string): HermesSessionRecord | null {
		return this.records.get(makeMapKey(sessionKey, profileId)) ?? null;
	}

	getOrCreate(input: {
		sessionKey: string;
		profileId: string;
		now: number;
		telclaudeSessionId?: string;
	}): { record: HermesSessionRecord; created: boolean } {
		const key = makeMapKey(input.sessionKey, input.profileId);
		const existing = this.records.get(key);
		if (existing) {
			existing.updatedAt = input.now;
			return { record: existing, created: false };
		}

		const record: HermesSessionRecord = {
			sessionKey: input.sessionKey,
			profileId: input.profileId,
			telclaudeSessionId: input.telclaudeSessionId ?? this.createTelclaudeSessionId(),
			createdAt: input.now,
			updatedAt: input.now,
		};
		this.records.set(key, record);
		return { record, created: true };
	}

	updateHermesSessionId(
		sessionKey: string,
		profileId: string,
		hermesSessionId: string,
		now: number,
	): void {
		const { record } = this.getOrCreate({ sessionKey, profileId, now });
		record.hermesSessionId = hermesSessionId;
		record.updatedAt = now;
	}

	clearSessionKey(sessionKey: string): number {
		let cleared = 0;
		for (const [key, record] of this.records) {
			if (record.sessionKey === sessionKey) {
				this.records.delete(key);
				cleared += 1;
			}
		}
		return cleared;
	}
}

export const hermesSessionMap = new HermesSessionMap();

export function clearHermesSessionMapping(sessionKey: string): number {
	return hermesSessionMap.clearSessionKey(sessionKey);
}

function makeMapKey(sessionKey: string, profileId: string): string {
	return `${profileId}\0${sessionKey}`;
}
