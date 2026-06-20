import { describe, expect, it } from "vitest";

import {
	BROWSER_ACT_EVIDENCE_SCHEMA_VERSION,
	type BrowserActEvidencePage,
	type BrowserActScreenshotSink,
	captureBrowserActEvidence,
	classifyCommitSignal,
	normalizeBrowserDom,
} from "../../src/relay/browser-act-evidence.js";
import type { BrowserActVerb } from "../../src/relay/browser-act-executor.js";

const COMMITMENT_SECRET = "browser-act-evidence-test-secret-32b";

class FakePage implements BrowserActEvidencePage {
	private urlReads = 0;

	constructor(
		private readonly currentUrl: string | readonly string[],
		private readonly dom: string,
		private readonly screenshotBytes: Uint8Array = Buffer.from("png-bytes"),
	) {}

	url(): string {
		if (!Array.isArray(this.currentUrl)) return this.currentUrl;
		const index = Math.min(this.urlReads, this.currentUrl.length - 1);
		this.urlReads += 1;
		return this.currentUrl[index] ?? "";
	}

	async evaluate<T>(_expression: string): Promise<T> {
		return this.dom as T;
	}

	async screenshot(): Promise<Uint8Array> {
		return this.screenshotBytes;
	}
}

class RecordingScreenshotSink implements BrowserActScreenshotSink {
	readonly stored: Array<{
		readonly bytes: Uint8Array;
		readonly contentType: string;
		readonly hash: string;
	}> = [];

	async storeScreenshot(input: {
		readonly bytes: Uint8Array;
		readonly contentType: "image/png";
		readonly hash: string;
	}): Promise<string> {
		this.stored.push(input);
		return `att_${input.hash.slice("sha256:".length, "sha256:".length + 16)}`;
	}
}

describe("browser act evidence", () => {
	it("normalizes volatile DOM details before hashing page evidence", async () => {
		const first = new RecordingScreenshotSink();
		const second = new RecordingScreenshotSink();

		const firstEvidence = await captureBrowserActEvidence(
			new FakePage("https://example.com/settings", '<main nonce="abc"> Hello   world </main>'),
			{ verb: "hover" },
			{
				commitmentSecret: COMMITMENT_SECRET,
				evidenceNonce: "same-nonce",
				screenshotSink: first,
			},
		);
		const secondEvidence = await captureBrowserActEvidence(
			new FakePage(
				"https://example.com/settings",
				"<!--ignored--><main nonce='def'>Hello world</main>",
			),
			{ verb: "hover" },
			{
				commitmentSecret: COMMITMENT_SECRET,
				evidenceNonce: "same-nonce",
				screenshotSink: second,
			},
		);

		expect(normalizeBrowserDom('<!--x--><main nonce="abc"> Hello   world </main>')).toBe(
			"<main>Hello world</main>",
		);
		expect(normalizeBrowserDom("<main>Hello</main><!-- trailing")).toBe("<main>Hello</main>");
		expect(firstEvidence.schemaVersion).toBe(BROWSER_ACT_EVIDENCE_SCHEMA_VERSION);
		expect(firstEvidence.evidenceNonce).toBe("same-nonce");
		expect(firstEvidence.domDigest).toBe(secondEvidence.domDigest);
		expect(firstEvidence.revision).toBe(secondEvidence.revision);
		expect(firstEvidence.urlOrigin).toBe("https://example.com");
		expect(firstEvidence.urlHash).toMatch(/^hmac-sha256:[a-f0-9]{64}$/);
		expect(firstEvidence.screenshotHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(first.stored[0]?.hash).toBe(firstEvidence.screenshotHash);
		expect(firstEvidence.screenshotRef).toMatch(/^att_[a-f0-9]{16}$/);
	});

	it("hashes submitted values without returning raw form data", async () => {
		const sink = new RecordingScreenshotSink();
		const evidence = await captureBrowserActEvidence(
			new FakePage(
				"https://example.com/pay?token=secret-url-token&amount=123",
				'<form><input name="amount"></form>',
			),
			{
				verb: "submit",
				target: "form#pay",
				submittedValues: { amount: "123", memo: "secret memo" },
			},
			{
				commitmentSecret: COMMITMENT_SECRET,
				evidenceNonce: "payment-nonce",
				screenshotSink: sink,
			},
		);

		expect(evidence.submittedValuesHash).toMatch(/^hmac-sha256:[a-f0-9]{64}$/);
		expect(JSON.stringify(evidence)).not.toContain("secret memo");
		expect(JSON.stringify(evidence)).not.toContain("secret-url-token");
		expect(JSON.stringify(evidence)).not.toContain("amount=123");
		expect(JSON.stringify(evidence)).not.toContain("form#pay");
		expect(evidence.urlOrigin).toBe("https://example.com");
		expect(evidence.commitSignal.forceConfirm).toBe(true);
		expect(evidence.commitSignal.reasons).toContain("action.verb.submit");
	});

	it("uses canonical submitted-value hashing independent of object key order", async () => {
		const first = await captureBrowserActEvidence(
			new FakePage("https://example.com/form", "<form></form>"),
			{ verb: "hover", submittedValues: { b: 2, a: 1 } },
			{
				commitmentSecret: COMMITMENT_SECRET,
				evidenceNonce: "same-values",
				screenshotSink: new RecordingScreenshotSink(),
			},
		);
		const second = await captureBrowserActEvidence(
			new FakePage("https://example.com/form", "<form></form>"),
			{ verb: "hover", submittedValues: { a: 1, b: 2 } },
			{
				commitmentSecret: COMMITMENT_SECRET,
				evidenceNonce: "same-values",
				screenshotSink: new RecordingScreenshotSink(),
			},
		);

		expect(first.submittedValuesHash).toBe(second.submittedValuesHash);
	});

	it("uses the evidence nonce to prevent cross-record submitted-value linking", async () => {
		const first = await captureBrowserActEvidence(
			new FakePage("https://example.com/form", "<form></form>"),
			{ verb: "hover", submittedValues: { otp: "123456" } },
			{
				commitmentSecret: COMMITMENT_SECRET,
				evidenceNonce: "nonce-one",
				screenshotSink: new RecordingScreenshotSink(),
			},
		);
		const second = await captureBrowserActEvidence(
			new FakePage("https://example.com/form", "<form></form>"),
			{ verb: "hover", submittedValues: { otp: "123456" } },
			{
				commitmentSecret: COMMITMENT_SECRET,
				evidenceNonce: "nonce-two",
				screenshotSink: new RecordingScreenshotSink(),
			},
		);

		expect(first.submittedValuesHash).not.toBe(second.submittedValuesHash);
		expect(first.revision).not.toBe(second.revision);
	});

	it("rejects ambiguous submitted-value inputs before awaiting page capture", async () => {
		await expect(
			captureBrowserActEvidence(
				new FakePage("https://example.com/form", "<form></form>"),
				{ verb: "hover", submittedValues: { amount: Number.NaN } as never },
				{
					commitmentSecret: COMMITMENT_SECRET,
					evidenceNonce: "invalid-values",
					screenshotSink: new RecordingScreenshotSink(),
				},
			),
		).rejects.toThrow("finite numbers");
	});

	it("fails when page URL changes during capture instead of mixing page states", async () => {
		await expect(
			captureBrowserActEvidence(
				new FakePage(
					["https://example.com/start", "https://example.com/redirected"],
					"<main>changed</main>",
				),
				{ verb: "hover" },
				{
					commitmentSecret: COMMITMENT_SECRET,
					evidenceNonce: "mixed-page",
					screenshotSink: new RecordingScreenshotSink(),
				},
			),
		).rejects.toThrow("URL change");
	});

	it("requires a relay-held commitment secret", async () => {
		await expect(
			captureBrowserActEvidence(
				new FakePage("https://example.com/form", "<form></form>"),
				{ verb: "hover" },
				{
					commitmentSecret: "short",
					screenshotSink: new RecordingScreenshotSink(),
				},
			),
		).rejects.toThrow("at least 32 bytes");
	});

	it("treats forceConfirm and observed browser commit signals as escalation-only", () => {
		// `fill` is a provably non-committing verb (in the allowlist), so this isolates
		// the escalation: only forceConfirm + observed signals drive the classification.
		expect(classifyCommitSignal({ verb: "fill", forceConfirm: false }).forceConfirm).toBe(false);

		const signal = classifyCommitSignal(
			{ verb: "fill", forceConfirm: true },
			{
				navigation: true,
				formSubmit: true,
				mutatingRequestMethods: ["GET", "post"],
			},
		);

		expect(signal.forceConfirm).toBe(true);
		expect(signal.observed).toEqual({
			navigation: true,
			formSubmit: true,
			mutatingRequest: true,
		});
		expect(signal.reasons).toEqual([
			"action.force_confirm",
			"playwright.navigation_observed",
			"playwright.form_submit_observed",
			"playwright.mutating_request_observed",
		]);
	});
});

describe("classifyCommitSignal verb classification (HIGH#2 inline-act regression)", () => {
	// Compile-time exhaustiveness guard: a Record over the BrowserActVerb union fails to
	// typecheck if a verb is added to the union without being classified here (or if a
	// non-verb key is listed). This is the build-time guard the inline-act hardening
	// relies on — the allowlist in browser-act-evidence.ts treats any unlisted verb as
	// committing (fail-closed), so drift can never silently make a verb inline-able.
	const VERB_CLASS: Record<BrowserActVerb, "committing" | "non-committing"> = {
		fill: "non-committing",
		type: "non-committing",
		selectOption: "committing",
		click: "committing",
		press: "committing",
		goto: "committing",
	};

	it("classifies every BrowserActVerb as intended; only fill/type run inline", () => {
		for (const [verb, klass] of Object.entries(VERB_CLASS)) {
			const committing = classifyCommitSignal({ verb }, {}).forceConfirm;
			expect(committing, `${verb} should be ${klass}`).toBe(klass === "committing");
		}
	});

	it("selectOption (the union value, not the absent 'select') is committing", () => {
		// Regression: the old denylist listed "select" and never matched "selectOption",
		// so a <select> change ran inline with no approval and no WYSIWYS binding.
		const signal = classifyCommitSignal({ verb: "selectOption" }, {});
		expect(signal.forceConfirm).toBe(true);
		expect(signal.reasons).toContain("action.verb.selectoption");
	});

	it("an unknown/future verb is committing (allowlist fails closed)", () => {
		expect(classifyCommitSignal({ verb: "drag" }, {}).forceConfirm).toBe(true);
		expect(classifyCommitSignal({ verb: "" }, {}).forceConfirm).toBe(true);
	});

	it("an observed mutation forces commit even for a non-committing verb (post-settle re-gate basis)", () => {
		expect(classifyCommitSignal({ verb: "fill" }, { navigation: true }).forceConfirm).toBe(true);
		expect(classifyCommitSignal({ verb: "type" }, { formSubmit: true }).forceConfirm).toBe(true);
		expect(classifyCommitSignal({ verb: "fill" }, { mutatingRequest: true }).forceConfirm).toBe(
			true,
		);
	});
});
