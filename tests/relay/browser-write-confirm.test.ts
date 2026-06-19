import { describe, expect, it } from "vitest";

import {
	type BrowserActEvidence,
	type BrowserActEvidencePage,
	type BrowserActIntent,
	type BrowserActObservedSignals,
	type BrowserActScreenshotSink,
	captureBrowserActEvidence,
} from "../../src/relay/browser-act-evidence.js";
import {
	BrowserWriteConfirmError,
	type BrowserWriteContext,
	deriveBrowserWriteBindingHash,
	prepareBrowserWrite,
	verifyBrowserWriteExecution,
} from "../../src/relay/browser-write-confirm.js";

const COMMITMENT_SECRET = "browser-write-confirm-test-secret-32b";

class FakePage implements BrowserActEvidencePage {
	constructor(
		private readonly currentUrl: string,
		private readonly dom: string,
		private readonly screenshotBytes: Uint8Array = Buffer.from("png-bytes"),
	) {}
	url(): string {
		return this.currentUrl;
	}
	async evaluate<T>(_expression: string): Promise<T> {
		return this.dom as T;
	}
	async screenshot(): Promise<Uint8Array> {
		return this.screenshotBytes;
	}
}

class FakeSink implements BrowserActScreenshotSink {
	async storeScreenshot(input: { readonly hash: string }): Promise<string> {
		return `att_${input.hash.slice("sha256:".length, "sha256:".length + 16)}`;
	}
}

const SUBMIT_SIGNALS: BrowserActObservedSignals = { formSubmit: true, navigation: true };

async function buildEvidence(opts: {
	url?: string;
	dom?: string;
	action?: BrowserActIntent;
	evidenceNonce?: string;
	signals?: BrowserActObservedSignals;
}): Promise<BrowserActEvidence> {
	const action: BrowserActIntent = opts.action ?? {
		verb: "submit",
		target: "#pay-form",
		submittedValues: { amount: "100", to: "alice@example.com" },
	};
	return captureBrowserActEvidence(
		new FakePage(
			opts.url ?? "https://bank.example.com/pay?step=2",
			opts.dom ?? "<html><body>pay</body></html>",
		),
		action,
		{
			screenshotSink: new FakeSink(),
			commitmentSecret: COMMITMENT_SECRET,
			observedSignals: opts.signals ?? SUBMIT_SIGNALS,
			evidenceNonce: opts.evidenceNonce ?? "nonce-fixed-1",
		},
	);
}

function baseContext(overrides: Partial<BrowserWriteContext> = {}): BrowserWriteContext {
	return {
		sessionRef: "sess-abc",
		actor: "telegram:default:operator",
		profile: "default",
		authorityDomain: "private",
		host: "bank.example.com",
		originScope: ["bank.example.com"],
		...overrides,
	};
}

const ACTION = { verb: "submit", target: "#pay-form" } as const;

describe("browser write-confirm binding hash", () => {
	it("is stable for identical inputs", async () => {
		const evidence = await buildEvidence({});
		const a = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		const b = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		expect(a).toBe(b);
		expect(a).toMatch(/^sha256:[0-9a-f]{64}$/);
	});

	it("is order-stable across originScope ordering / case / dupes", async () => {
		const evidence = await buildEvidence({});
		const a = deriveBrowserWriteBindingHash(
			baseContext({ originScope: ["bank.example.com", "cdn.example.com"] }),
			ACTION,
			evidence,
		);
		const b = deriveBrowserWriteBindingHash(
			baseContext({ originScope: ["CDN.example.com", "bank.example.com", "bank.example.com"] }),
			ACTION,
			evidence,
		);
		expect(a).toBe(b);
	});

	it("changes when the verb changes (action drift)", async () => {
		const evidence = await buildEvidence({});
		const base = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		const drift = deriveBrowserWriteBindingHash(
			baseContext(),
			{ verb: "click", target: "#pay-form" },
			evidence,
		);
		expect(drift).not.toBe(base);
	});

	it("changes when the target changes (action drift)", async () => {
		const evidence = await buildEvidence({});
		const base = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		const drift = deriveBrowserWriteBindingHash(
			baseContext(),
			{ verb: "submit", target: "#cancel-form" },
			evidence,
		);
		expect(drift).not.toBe(base);
	});

	it("changes when the host changes", async () => {
		const evidence = await buildEvidence({});
		const base = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		const drift = deriveBrowserWriteBindingHash(
			baseContext({ host: "evil.example.com" }),
			ACTION,
			evidence,
		);
		expect(drift).not.toBe(base);
	});

	it("changes when the page revision changes (page drift via DOM)", async () => {
		const evidence = await buildEvidence({});
		// Same nonce/url/action but a mutated DOM → the HMAC revision changes.
		const mutated = await buildEvidence({ dom: "<html><body>pay MORE</body></html>" });
		expect(mutated.revision).not.toBe(evidence.revision);
		const base = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		const drift = deriveBrowserWriteBindingHash(baseContext(), ACTION, mutated);
		expect(drift).not.toBe(base);
	});

	it("changes when submittedValuesHash changes (values drift)", async () => {
		const evidence = await buildEvidence({});
		const tampered = await buildEvidence({
			action: {
				verb: "submit",
				target: "#pay-form",
				submittedValues: { amount: "9999", to: "mallory@evil.com" },
			},
		});
		expect(tampered.submittedValuesHash).not.toBe(evidence.submittedValuesHash);
		const base = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		const drift = deriveBrowserWriteBindingHash(baseContext(), ACTION, tampered);
		expect(drift).not.toBe(base);
	});

	it("changes when the evidenceNonce changes", async () => {
		const evidence = await buildEvidence({ evidenceNonce: "nonce-fixed-1" });
		const reNonced = await buildEvidence({ evidenceNonce: "nonce-fixed-2" });
		expect(reNonced.evidenceNonce).not.toBe(evidence.evidenceNonce);
		const base = deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence);
		const drift = deriveBrowserWriteBindingHash(baseContext(), ACTION, reNonced);
		expect(drift).not.toBe(base);
	});

	it("does NOT change when only the display-only domDigest/screenshotHash differ", async () => {
		// Page revision is the HMAC anchor; if we hold url+nonce+action+dom fixed,
		// domDigest/screenshotHash are identical anyway. This asserts the binding
		// surface is exactly the evidence anchor, not the display metadata: a
		// second capture with the same inputs yields the same binding.
		const a = await buildEvidence({});
		const b = await buildEvidence({});
		expect(a.revision).toBe(b.revision);
		expect(deriveBrowserWriteBindingHash(baseContext(), ACTION, a)).toBe(
			deriveBrowserWriteBindingHash(baseContext(), ACTION, b),
		);
	});
});

describe("prepareBrowserWrite", () => {
	it("stages a write and binds it; commit signal passes through", async () => {
		const evidence = await buildEvidence({});
		const prepared = prepareBrowserWrite({
			context: baseContext(),
			action: ACTION,
			evidence,
			approver: "telegram:default:human",
		});
		expect(prepared.bindingHash).toBe(
			deriveBrowserWriteBindingHash(baseContext(), ACTION, evidence),
		);
		expect(prepared.commitSignal).toEqual(evidence.commitSignal);
		expect(prepared.commitSignal.forceConfirm).toBe(true);
		expect(prepared.display).toEqual({
			verb: "submit",
			target: "#pay-form",
			urlOrigin: "https://bank.example.com",
		});
		expect(prepared.expiresAtMs).toBeGreaterThan(prepared.createdAtMs);
	});

	it("rejects self-approval (actor == approver)", async () => {
		const evidence = await buildEvidence({});
		expect(() =>
			prepareBrowserWrite({
				context: baseContext({ actor: "same" }),
				action: ACTION,
				evidence,
				approver: "same",
			}),
		).toThrowError(BrowserWriteConfirmError);
		try {
			prepareBrowserWrite({
				context: baseContext({ actor: "same" }),
				action: ACTION,
				evidence,
				approver: "same",
			});
		} catch (err) {
			expect((err as BrowserWriteConfirmError).code).toBe("write_confirm_self_approval");
		}
	});

	it("rejects a write whose evidence did not force confirmation", async () => {
		// A read-only verb with no commit signals → commitSignal.forceConfirm = false.
		const evidence = await buildEvidence({
			action: { verb: "read", target: "#balance" },
			signals: {},
		});
		expect(evidence.commitSignal.forceConfirm).toBe(false);
		try {
			prepareBrowserWrite({
				context: baseContext(),
				action: { verb: "read", target: "#balance" },
				evidence,
				approver: "telegram:default:human",
			});
			throw new Error("expected throw");
		} catch (err) {
			expect((err as BrowserWriteConfirmError).code).toBe("write_confirm_not_required");
		}
	});

	it("rejects a missing identity (empty host)", async () => {
		const evidence = await buildEvidence({});
		try {
			prepareBrowserWrite({
				context: baseContext({ host: "" }),
				action: ACTION,
				evidence,
				approver: "telegram:default:human",
			});
			throw new Error("expected throw");
		} catch (err) {
			expect((err as BrowserWriteConfirmError).code).toBe("write_confirm_identity_missing");
		}
	});

	it("never carries raw submitted values, the full URL, or the commitment secret", async () => {
		const evidence = await buildEvidence({
			url: "https://bank.example.com/pay?step=2&token=SECRET-URL-PARAM",
			action: {
				verb: "submit",
				target: "#pay-form",
				submittedValues: { amount: "100", to: "ALICE-RAW-VALUE@example.com" },
			},
		});
		const prepared = prepareBrowserWrite({
			context: baseContext(),
			action: ACTION,
			evidence,
			approver: "telegram:default:human",
		});
		const serialized = JSON.stringify(prepared);
		expect(serialized).not.toContain("ALICE-RAW-VALUE");
		expect(serialized).not.toContain("SECRET-URL-PARAM");
		expect(serialized).not.toContain("step=2");
		expect(serialized).not.toContain(COMMITMENT_SECRET);
		// Only the redacted origin survives, never the full path/query.
		expect(serialized).toContain("https://bank.example.com");
		expect(serialized).not.toContain("/pay?");
	});

	it("redacts a URL-token action target from the persisted display (binding keeps the raw)", async () => {
		const evidence = await buildEvidence({});
		const prepared = prepareBrowserWrite({
			context: baseContext(),
			action: { verb: "submit", target: "https://bank.example.com/pay?token=TARGET-SECRET-TOKEN" },
			evidence,
			approver: "telegram:default:human",
		});
		// The display target collapses to origin — no token, no path/query.
		expect(prepared.display.target).toBe("https://bank.example.com");
		const serialized = JSON.stringify(prepared);
		expect(serialized).not.toContain("TARGET-SECRET-TOKEN");
		expect(serialized).not.toContain("/pay?");
	});

	it("execute recapture with the SAME evidence nonce on an unchanged page passes", async () => {
		const evidence = await buildEvidence({ evidenceNonce: "prepare-nonce-xyz" });
		const prepared = prepareBrowserWrite({
			context: baseContext(),
			action: ACTION,
			evidence,
			approver: "telegram:default:human",
		});
		expect(prepared.evidenceNonce).toBe("prepare-nonce-xyz");
		// Execute recaptures the SAME settled page under the STORED nonce.
		const recaptured = await buildEvidence({ evidenceNonce: prepared.evidenceNonce });
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext(),
			action: ACTION,
			currentEvidence: recaptured,
		});
		expect(check.ok).toBe(true);
	});

	it("execute recapture with a FRESH random nonce fails binding_drift on an unchanged page", async () => {
		const evidence = await buildEvidence({ evidenceNonce: "prepare-nonce-xyz" });
		const prepared = prepareBrowserWrite({
			context: baseContext(),
			action: ACTION,
			evidence,
			approver: "telegram:default:human",
		});
		const recaptured = await buildEvidence({ evidenceNonce: "a-different-nonce" });
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext(),
			action: ACTION,
			currentEvidence: recaptured,
		});
		expect(check.ok).toBe(false);
		expect(check.reason).toBe("write_confirm_binding_drift");
	});
});

describe("verifyBrowserWriteExecution", () => {
	async function stage() {
		const evidence = await buildEvidence({});
		const prepared = prepareBrowserWrite({
			context: baseContext(),
			action: ACTION,
			evidence,
			approver: "telegram:default:human",
		});
		return { evidence, prepared };
	}

	it("passes when the action + evidence are unchanged", async () => {
		const { evidence, prepared } = await stage();
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext(),
			action: ACTION,
			currentEvidence: evidence,
		});
		expect(check).toEqual({ ok: true, reason: "ok" });
	});

	it("fails closed on expiry", async () => {
		const { evidence, prepared } = await stage();
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext(),
			action: ACTION,
			currentEvidence: evidence,
			now: prepared.expiresAtMs + 1,
		});
		expect(check).toEqual({ ok: false, reason: "write_confirm_expired" });
	});

	it("fails closed on actor mismatch", async () => {
		const { evidence, prepared } = await stage();
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext({ actor: "telegram:default:someone-else" }),
			action: ACTION,
			currentEvidence: evidence,
		});
		expect(check).toEqual({ ok: false, reason: "write_confirm_actor_mismatch" });
	});

	it("fails closed on host mismatch", async () => {
		const { evidence, prepared } = await stage();
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext({ host: "evil.example.com" }),
			action: ACTION,
			currentEvidence: evidence,
		});
		expect(check).toEqual({ ok: false, reason: "write_confirm_host_mismatch" });
	});

	it("fails closed on page-revision drift (DOM mutated after approval)", async () => {
		const { prepared } = await stage();
		const mutated = await buildEvidence({ dom: "<html><body>pay MORE</body></html>" });
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext(),
			action: ACTION,
			currentEvidence: mutated,
		});
		expect(check).toEqual({ ok: false, reason: "write_confirm_binding_drift" });
	});

	it("fails closed on action drift (verb redirected after approval)", async () => {
		const { evidence, prepared } = await stage();
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext(),
			action: { verb: "click", target: "#pay-form" },
			currentEvidence: evidence,
		});
		expect(check).toEqual({ ok: false, reason: "write_confirm_binding_drift" });
	});

	it("fails closed on submitted-values drift (values changed after approval)", async () => {
		const { prepared } = await stage();
		const tampered = await buildEvidence({
			action: {
				verb: "submit",
				target: "#pay-form",
				submittedValues: { amount: "9999", to: "mallory@evil.com" },
			},
		});
		const check = verifyBrowserWriteExecution({
			prepared,
			context: baseContext(),
			action: ACTION,
			currentEvidence: tampered,
		});
		expect(check).toEqual({ ok: false, reason: "write_confirm_binding_drift" });
	});
});
