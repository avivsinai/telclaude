import { getChildLogger } from "../logging.js";
import {
	denyApproval,
	type PendingToolApprovalResolution,
	registerPendingToolApprovalWait,
	unregisterPendingToolApprovalWait,
} from "./approvals.js";

const logger = getChildLogger({ module: "approval-wait" });

type WaitForToolApprovalOptions = {
	nonce: string;
	chatId: number;
	timeoutMs: number;
	signal?: AbortSignal;
};

export function waitForToolApproval(
	options: WaitForToolApprovalOptions,
): Promise<PendingToolApprovalResolution> {
	return new Promise((resolve) => {
		let settled = false;
		let timeoutId: ReturnType<typeof setTimeout> | null = null;

		const settle = (result: PendingToolApprovalResolution) => {
			if (settled) {
				return;
			}
			settled = true;
			if (timeoutId) {
				clearTimeout(timeoutId);
			}
			unregisterPendingToolApprovalWait(options.nonce);
			options.signal?.removeEventListener("abort", onAbort);
			resolve(result);
		};

		const expireApproval = (source: "timeout" | "abort", reason: string) => {
			const result = denyApproval(options.nonce, options.chatId);
			if (!result.success && !result.error.includes("No pending approval")) {
				logger.warn(
					{ nonce: options.nonce, chatId: options.chatId, error: result.error, source },
					"failed to expire pending tool approval",
				);
			}
			settle({ status: "denied", source, reason });
		};

		const onAbort = () =>
			expireApproval("abort", "Query canceled while waiting for tool approval.");

		if (options.signal?.aborted) {
			onAbort();
			return;
		}

		registerPendingToolApprovalWait(options.nonce, settle);

		timeoutId = setTimeout(
			() => {
				expireApproval("timeout", "Tool approval timed out.");
			},
			Math.max(1, options.timeoutMs),
		);

		options.signal?.addEventListener("abort", onAbort, { once: true });
	});
}
