import { collectCronHardeningItems, collectUnusedSkillItems } from "./collectors.js";
import { listCuratorItems, upsertCuratorItem } from "./store.js";
import type { CuratorScanResult } from "./types.js";

export function runCuratorScan(options?: {
	producerKind?: "system" | "claude-code" | "codex";
	producerId?: string;
	cwd?: string;
	nowMs?: number;
	unusedSkillStaleAfterMs?: number;
}): CuratorScanResult {
	const items = [
		...collectCronHardeningItems(),
		...collectUnusedSkillItems({
			cwd: options?.cwd,
			nowMs: options?.nowMs,
			staleAfterMs: options?.unusedSkillStaleAfterMs,
		}),
	];
	for (const item of items) {
		upsertCuratorItem(
			{
				...item,
				producerKind: options?.producerKind ?? item.producerKind,
				...(options?.producerId ? { producerId: options.producerId } : {}),
			},
			options?.nowMs,
		);
	}
	const openItems = listCuratorItems({ status: "open" });
	const byKind: Record<string, number> = {};
	for (const item of openItems) {
		byKind[item.kind] = (byKind[item.kind] ?? 0) + 1;
	}
	return {
		createdOrUpdated: items.length,
		openItems: openItems.length,
		byKind,
	};
}
