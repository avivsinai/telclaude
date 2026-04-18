import type { InternalAuthScope } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import type { ApprovalScope, RiskTier } from "../security/approvals.js";
import { stripTrailingSlash } from "../utils.js";
import { buildRpcAuthHeaders } from "./token-client.js";

const logger = getChildLogger({ module: "agent-approval-client" });

const RPC_TIMEOUT_MS = 15_000;

type ApprovalScopeCardRequest = {
	chatId: number;
	actorId: number;
	threadId?: number;
	title: string;
	body: string;
	nonce: string;
	toolKey: string;
	riskTier: RiskTier;
	scopesEnabled: ApprovalScope[];
	explanation?: string;
};

type ApprovalScopeCardResponse = {
	ok: boolean;
	cardId: string;
	messageId: number;
};

function getCapabilitiesUrl(): string {
	const url = process.env.TELCLAUDE_CAPABILITIES_URL;
	if (!url) {
		throw new Error("TELCLAUDE_CAPABILITIES_URL is not configured");
	}
	return stripTrailingSlash(url);
}

export async function requestApprovalScopeCard(
	request: ApprovalScopeCardRequest,
	scope: InternalAuthScope = "telegram",
): Promise<ApprovalScopeCardResponse> {
	const path = "/v1/telegram.approval-scope";
	const payload = JSON.stringify(request);
	const response = await fetch(`${getCapabilitiesUrl()}${path}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...buildRpcAuthHeaders("POST", path, payload, scope),
		},
		body: payload,
		signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
	});

	if (!response.ok) {
		const text = await response.text();
		logger.warn(
			{ status: response.status, statusText: response.statusText, body: text },
			"approval scope RPC failed",
		);
		throw new Error(`Approval card request failed: ${response.status} ${response.statusText}`);
	}

	return (await response.json()) as ApprovalScopeCardResponse;
}
