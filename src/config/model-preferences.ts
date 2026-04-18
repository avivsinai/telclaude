/**
 * Per-chat model preference storage (W2 model picker).
 *
 * The model picker writes into this table when an operator taps a model.
 * Runtime session execution may read it later to inform SDK model overrides;
 * this module only defines the storage surface — wiring into the query path
 * is intentionally left to a later workstream so W2 stays scoped.
 */

import { z } from "zod";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";

const logger = getChildLogger({ module: "model-preferences" });

const ModelPreferenceSchema = z.object({
	chatId: z.number().int(),
	providerId: z.string().min(1).max(64),
	modelId: z.string().min(1).max(128),
	updatedAt: z.number().int(),
});

export type ModelPreference = z.infer<typeof ModelPreferenceSchema>;

type ModelPreferenceRow = {
	chat_id: number;
	provider_id: string;
	model_id: string;
	updated_at: number;
};

function rowToPreference(row: ModelPreferenceRow): ModelPreference {
	return {
		chatId: row.chat_id,
		providerId: row.provider_id,
		modelId: row.model_id,
		updatedAt: row.updated_at,
	};
}

export function getChatModelPreference(chatId: number): ModelPreference | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM model_preferences WHERE chat_id = ?").get(chatId) as
		| ModelPreferenceRow
		| undefined;
	return row ? rowToPreference(row) : null;
}

export function setChatModelPreference(input: {
	chatId: number;
	providerId: string;
	modelId: string;
}): ModelPreference {
	const now = Date.now();
	const parsed = ModelPreferenceSchema.parse({
		chatId: input.chatId,
		providerId: input.providerId,
		modelId: input.modelId,
		updatedAt: now,
	});

	const db = getDb();
	db.prepare(
		`INSERT INTO model_preferences (chat_id, provider_id, model_id, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(chat_id) DO UPDATE SET
			 provider_id = excluded.provider_id,
			 model_id = excluded.model_id,
			 updated_at = excluded.updated_at`,
	).run(parsed.chatId, parsed.providerId, parsed.modelId, parsed.updatedAt);

	logger.info(
		{ chatId: parsed.chatId, providerId: parsed.providerId, modelId: parsed.modelId },
		"chat model preference updated",
	);

	return parsed;
}

export function clearChatModelPreference(chatId: number): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM model_preferences WHERE chat_id = ?").run(chatId);
	return result.changes > 0;
}
