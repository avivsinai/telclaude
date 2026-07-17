import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	canonicalHash,
	JtiStore,
	verifyApprovalToken,
} from "../../src/google-services/approval.js";
import type { FetchRequest } from "../../src/google-services/types.js";
import {
	generateTelclaudeMcpSideEffectApprovalToken,
	type TelclaudeMcpSideEffectApprovalSigner,
} from "../../src/hermes/mcp/approval-token.js";
import {
	createGoogleProviderSidecarApprovalTokenIssuer,
	createProviderSidecarApprovalTokenIssuer,
	type GoogleProviderSidecarApprovalTokenSigner,
} from "../../src/hermes/mcp/provider-sidecar-token.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpProviderSideEffectRecord,
} from "../../src/hermes/mcp/side-effect-ledger.js";
import { GOOGLE_APPROVAL_SIGNING_PREFIX } from "../../src/security/approval-domains.js";

describe("Hermes provider sidecar approval-token issuer", () => {
	let tempDir: string;
	let jtiStore: JtiStore;
	let vault: PrefixSigningVault;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-provider-sidecar-token-"));
		jtiStore = new JtiStore(tempDir);
		vault = new PrefixSigningVault();
	});

	afterEach(() => {
		jtiStore.close();
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("mints a Google sidecar token from the exact ledger params and round-trips through sidecar verification", async () => {
		const record = googleProviderRecord({
			to: "operator@example.com",
			subject: "nested params",
			body: "hello",
			metadata: { z: 1, a: true },
		});
		const issuer = createGoogleProviderSidecarApprovalTokenIssuer({ vaultClient: vault });

		const token = await issuer(sidecarRequestFor(record));
		const claims = claimsFrom(token);

		expect(claims).toMatchObject({
			approvalNonce: record.approvalRequestId,
			actorUserId: record.actorId,
			providerId: "google",
			service: "gmail",
			action: "create_draft",
			subjectUserId: null,
		});
		expect(claims.paramsHash).toBe(
			canonicalHash({
				service: record.service,
				action: record.action,
				params: record.params,
				actorUserId: record.actorId,
				subjectUserId: null,
			}),
		);
		expect(vault.calls).toEqual([
			expect.objectContaining({ prefix: GOOGLE_APPROVAL_SIGNING_PREFIX }),
		]);

		const result = verifyApprovalToken(
			token,
			fetchRequestFor(record),
			record.actorId,
			(payload, signature) =>
				vault.verifySignature(payload, signature, GOOGLE_APPROVAL_SIGNING_PREFIX),
			jtiStore,
		);
		expect(result).toEqual({ ok: true });

		const replay = verifyApprovalToken(
			token,
			fetchRequestFor(record),
			record.actorId,
			(payload, signature) =>
				vault.verifySignature(payload, signature, GOOGLE_APPROVAL_SIGNING_PREFIX),
			jtiStore,
		);
		expect(replay).toMatchObject({ ok: false, code: "approval_replayed" });
	});

	it("rejects params mutation without consuming the relay-minted sidecar token", async () => {
		const record = googleProviderRecord({
			to: "operator@example.com",
			subject: "original",
			body: "hello",
		});
		const issuer = createGoogleProviderSidecarApprovalTokenIssuer({ vaultClient: vault });
		const token = await issuer(sidecarRequestFor(record));
		const verify = (payload: string, signature: string) =>
			vault.verifySignature(payload, signature, GOOGLE_APPROVAL_SIGNING_PREFIX);

		const mutated = verifyApprovalToken(
			token,
			fetchRequestFor(record, { params: { ...record.params, subject: "mutated" } }),
			record.actorId,
			verify,
			jtiStore,
		);
		expect(mutated).toMatchObject({ ok: false, code: "approval_mismatch" });

		expect(
			verifyApprovalToken(token, fetchRequestFor(record), record.actorId, verify, jtiStore),
		).toEqual({ ok: true });
	});

	it("rejects Hermes-domain side-effect tokens at the Google sidecar verifier boundary", async () => {
		const record = googleProviderRecord({
			to: "operator@example.com",
			subject: "wrong token domain",
			body: "hello",
		});
		const hermesToken = await generateTelclaudeMcpSideEffectApprovalToken(
			getTelclaudeMcpSideEffectApprovalBinding(record),
			vault,
			{ jti: "hermes-side-effect-jti" },
		);

		const result = verifyApprovalToken(
			hermesToken,
			fetchRequestFor(record),
			record.actorId,
			(payload, signature) =>
				vault.verifySignature(payload, signature, GOOGLE_APPROVAL_SIGNING_PREFIX),
			jtiStore,
		);

		expect(result).toMatchObject({
			ok: false,
			code: "approval_required",
			message: "Invalid token signature",
		});
	});

	it("fails closed instead of minting Google sidecar tokens for non-Google providers", async () => {
		const issuer = createGoogleProviderSidecarApprovalTokenIssuer({ vaultClient: vault });
		const record = googleProviderRecord({ to: "operator@example.com" });

		await expect(
			issuer({
				...sidecarRequestFor(record),
				providerId: "bank",
				service: "bank",
				action: "transfer.prepare",
			}),
		).rejects.toThrow("unsupported provider sidecar");
		expect(vault.calls).toEqual([]);
	});

	it("mints provider-correct signed evidence for an actor-bound Clalit renewal", async () => {
		const issuer = createProviderSidecarApprovalTokenIssuer({ vaultClient: vault });
		const record = clalitProviderRecord();

		const token = await issuer(sidecarRequestFor(record));

		expect(claimsFrom(token)).toMatchObject({
			aud: "israel-services",
			providerId: "clalit",
			service: "clalit",
			action: "prescription_renewal",
			subjectUserId: record.subjectUserId,
		});
	});

	it("fails closed when Clalit execution lacks an actor-bound subject", async () => {
		const issuer = createProviderSidecarApprovalTokenIssuer({ vaultClient: vault });
		const record = clalitProviderRecord();

		await expect(
			issuer({
				...sidecarRequestFor(record),
				subjectUserId: undefined,
			}),
		).rejects.toThrow("subjectUserId is required");
		expect(vault.calls).toEqual([]);
	});

	it("fails closed for Clalit writes outside the Phase 0 renewal surface", async () => {
		const issuer = createProviderSidecarApprovalTokenIssuer({ vaultClient: vault });
		const record = clalitProviderRecord();

		await expect(
			issuer({ ...sidecarRequestFor(record), action: "appointment_booking" }),
		).rejects.toThrow("unsupported Clalit sidecar action");
		expect(vault.calls).toEqual([]);
	});
});

function googleProviderRecord(
	params: Record<string, unknown>,
): TelclaudeMcpProviderSideEffectRecord {
	const ledger = createTelclaudeMcpSideEffectLedger({
		verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
		makeRef: () => "google-provider-sidecar-ref",
		nowMs: () => 100_000,
	});
	return ledger.prepare({
		kind: "provider",
		actorId: "telegram:operator",
		approverActorId: "telegram:approver",
		profileId: "ops",
		domain: "private",
		providerId: "google",
		service: "gmail",
		action: "create_draft",
		params,
		providerAccountRef: "google:gmail:primary",
		approvalRequestId: "approval-google-create-draft",
		approvalRevision: 1,
		wysiwysRender: "google.gmail.create_draft",
	});
}

function clalitProviderRecord(): TelclaudeMcpProviderSideEffectRecord {
	const ledger = createTelclaudeMcpSideEffectLedger({
		verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
		makeRef: () => "clalit-provider-sidecar-ref",
		nowMs: () => 100_000,
	});
	return ledger.prepare({
		kind: "provider",
		actorId: "household:whatsapp:parent-b",
		approverActorId: "telegram:parent-a",
		profileId: "parent-b",
		domain: "household",
		providerId: "clalit",
		service: "clalit",
		action: "prescription_renewal",
		params: { prescriptionId: "synthetic-rx" },
		subjectUserId: "household:parent-b",
		providerAccountRef: "clalit:primary",
		approvalRequestId: "approval-clalit-renewal",
		approvalRevision: 1,
		wysiwysRender: "clalit.clalit.prescription_renewal",
	});
}

function sidecarRequestFor(record: TelclaudeMcpProviderSideEffectRecord) {
	return {
		record,
		providerId: record.providerId,
		service: record.service,
		action: record.action,
		params: record.params,
		subjectUserId: record.subjectUserId,
		actorUserId: record.actorId,
		approvalNonce: record.approvalRequestId,
	};
}

function fetchRequestFor(
	record: TelclaudeMcpProviderSideEffectRecord,
	overrides: Partial<FetchRequest> = {},
): FetchRequest {
	return {
		service: record.service as FetchRequest["service"],
		action: record.action,
		params: record.params,
		...overrides,
	};
}

function claimsFrom(token: string): Record<string, unknown> {
	const [, claimsB64] = token.split(".");
	return JSON.parse(Buffer.from(claimsB64, "base64url").toString("utf8")) as Record<
		string,
		unknown
	>;
}

class PrefixSigningVault
	implements TelclaudeMcpSideEffectApprovalSigner, GoogleProviderSidecarApprovalTokenSigner
{
	readonly calls: Array<{ readonly payload: string; readonly prefix: string }> = [];

	async signPayload(payload: string, prefix: string): Promise<{ type: string; signature: string }> {
		this.calls.push({ payload, prefix });
		return { type: "sign-payload", signature: this.signatureFor(payload, prefix) };
	}

	verifySignature(payload: string, signature: string, prefix: string): boolean {
		return signature === this.signatureFor(payload, prefix);
	}

	private signatureFor(payload: string, prefix: string): string {
		return crypto.createHash("sha256").update(`${prefix}\n${payload}`).digest("base64url");
	}
}
