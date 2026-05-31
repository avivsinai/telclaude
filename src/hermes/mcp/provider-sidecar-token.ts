import { type ApprovalTokenSigner, generateApprovalToken } from "../../relay/approval-token.js";
import type {
	TelclaudeMcpProviderSidecarApprovalTokenIssuer,
	TelclaudeMcpProviderSidecarApprovalTokenRequest,
} from "./ledger-execute.js";

export type GoogleProviderSidecarApprovalTokenSigner = ApprovalTokenSigner;

export type CreateGoogleProviderSidecarApprovalTokenIssuerOptions = {
	readonly vaultClient: GoogleProviderSidecarApprovalTokenSigner;
	readonly subjectUserId?: string | null;
};

const GOOGLE_PROVIDER_ID = "google";
const GOOGLE_SERVICE_IDS = new Set(["gmail", "calendar", "drive", "contacts"]);

export function createGoogleProviderSidecarApprovalTokenIssuer(
	options: CreateGoogleProviderSidecarApprovalTokenIssuerOptions,
): TelclaudeMcpProviderSidecarApprovalTokenIssuer {
	return (request) => generateGoogleProviderSidecarApprovalToken(request, options);
}

export async function generateGoogleProviderSidecarApprovalToken(
	request: TelclaudeMcpProviderSidecarApprovalTokenRequest,
	options: CreateGoogleProviderSidecarApprovalTokenIssuerOptions,
): Promise<string> {
	const providerId = requiredTrimmed(request.providerId, "providerId");
	if (providerId !== GOOGLE_PROVIDER_ID) {
		throw new Error(`unsupported provider sidecar token issuer: ${providerId}`);
	}
	const service = requiredTrimmed(request.service, "service");
	if (!GOOGLE_SERVICE_IDS.has(service)) {
		throw new Error(`unsupported Google sidecar service: ${service}`);
	}
	return generateApprovalToken(
		{
			actorUserId: requiredTrimmed(request.actorUserId, "actorUserId"),
			service,
			action: requiredTrimmed(request.action, "action"),
			params: request.params,
			subjectUserId: normalizeSubjectUserId(options.subjectUserId),
			approvalNonce: requiredTrimmed(request.approvalNonce, "approvalNonce"),
		},
		options.vaultClient,
	);
}

function normalizeSubjectUserId(value: string | null | undefined): string | null {
	if (value === null || value === undefined) return null;
	const trimmed = value.trim();
	return trimmed.length > 0 ? trimmed : null;
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`provider sidecar token ${field} is required`);
	return trimmed;
}
