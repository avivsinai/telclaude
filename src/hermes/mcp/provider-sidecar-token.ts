import { type ApprovalTokenSigner, generateApprovalToken } from "../../relay/approval-token.js";
import type {
	TelclaudeMcpProviderSidecarApprovalTokenIssuer,
	TelclaudeMcpProviderSidecarApprovalTokenRequest,
} from "./ledger-execute.js";

export type ProviderSidecarApprovalTokenSigner = ApprovalTokenSigner;

export type GoogleProviderSidecarApprovalTokenSigner = ProviderSidecarApprovalTokenSigner;

export type CreateGoogleProviderSidecarApprovalTokenIssuerOptions = {
	readonly vaultClient: ProviderSidecarApprovalTokenSigner;
	readonly subjectUserId?: string | null;
};

const GOOGLE_PROVIDER_ID = "google";
const GOOGLE_SERVICE_IDS = new Set(["gmail", "calendar", "drive", "contacts"]);
const CLALIT_PROVIDER_ID = "clalit";
const CLALIT_WRITE_ACTION = "prescription_renewal";
const ISRAEL_SERVICES_AUDIENCE = "israel-services";

export function createProviderSidecarApprovalTokenIssuer(
	options: CreateGoogleProviderSidecarApprovalTokenIssuerOptions,
): TelclaudeMcpProviderSidecarApprovalTokenIssuer {
	return (request) => generateProviderSidecarApprovalToken(request, options);
}

export function createGoogleProviderSidecarApprovalTokenIssuer(
	options: CreateGoogleProviderSidecarApprovalTokenIssuerOptions,
): TelclaudeMcpProviderSidecarApprovalTokenIssuer {
	return (request) => generateGoogleProviderSidecarApprovalToken(request, options);
}

export async function generateProviderSidecarApprovalToken(
	request: TelclaudeMcpProviderSidecarApprovalTokenRequest,
	options: CreateGoogleProviderSidecarApprovalTokenIssuerOptions,
): Promise<string> {
	const providerId = requiredTrimmed(request.providerId, "providerId");
	if (providerId === GOOGLE_PROVIDER_ID) {
		return generateGoogleProviderSidecarApprovalToken(request, options);
	}
	if (providerId === CLALIT_PROVIDER_ID) {
		return generateClalitProviderSidecarApprovalToken(request, options);
	}
	throw new Error(`unsupported provider sidecar token issuer: ${providerId}`);
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
			subjectUserId: normalizeSubjectUserId(request.subjectUserId ?? options.subjectUserId),
			approvalNonce: requiredTrimmed(request.approvalNonce, "approvalNonce"),
		},
		options.vaultClient,
	);
}

async function generateClalitProviderSidecarApprovalToken(
	request: TelclaudeMcpProviderSidecarApprovalTokenRequest,
	options: CreateGoogleProviderSidecarApprovalTokenIssuerOptions,
): Promise<string> {
	const service = requiredTrimmed(request.service, "service");
	if (service !== CLALIT_PROVIDER_ID) {
		throw new Error(`unsupported Clalit sidecar service: ${service}`);
	}
	const action = requiredTrimmed(request.action, "action");
	if (action !== CLALIT_WRITE_ACTION) {
		throw new Error(`unsupported Clalit sidecar action: ${action}`);
	}
	const subjectUserId = normalizeSubjectUserId(request.subjectUserId);
	if (!subjectUserId) {
		throw new Error("provider sidecar token subjectUserId is required for Clalit");
	}
	return generateApprovalToken(
		{
			providerId: CLALIT_PROVIDER_ID,
			audience: ISRAEL_SERVICES_AUDIENCE,
			actorUserId: requiredTrimmed(request.actorUserId, "actorUserId"),
			service,
			action,
			params: request.params,
			subjectUserId,
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
