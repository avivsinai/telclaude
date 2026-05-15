import { collectCronHardeningItems } from "./collectors.js";
import { listCuratorItems, upsertCuratorItem } from "./store.js";
import type { CuratorScanResult } from "./types.js";

export function runCuratorScan(options?: {
	producerKind?: "system" | "claude-code" | "codex";
	producerId?: string;
}): CuratorScanResult {
	const items = collectCronHardeningItems();
	for (const item of items) {
		upsertCuratorItem({
			...item,
			producerKind: options?.producerKind ?? item.producerKind,
			...(options?.producerId ? { producerId: options.producerId } : {}),
		});
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
