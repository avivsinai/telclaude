import crypto from "node:crypto";

import { sortKeysDeep } from "../crypto/canonical-hash.js";

export const BROWSER_ACT_EVIDENCE_SCHEMA_VERSION = "telclaude.browser.act-evidence.v1";

export type BrowserActJsonValue =
	| null
	| boolean
	| number
	| string
	| readonly BrowserActJsonValue[]
	| { readonly [key: string]: BrowserActJsonValue };

export interface BrowserActEvidencePage {
	url(): string;
	evaluate<T>(expression: string): Promise<T>;
	screenshot(options: { readonly type: "png"; readonly fullPage: true }): Promise<Uint8Array>;
}

export interface BrowserActScreenshotSink {
	storeScreenshot(input: {
		readonly bytes: Uint8Array;
		readonly contentType: "image/png";
		readonly hash: string;
	}): Promise<string>;
}

export interface BrowserActIntent {
	readonly verb: string;
	readonly target?: string;
	readonly submittedValues?: BrowserActJsonValue;
	/** Escalate-only: true forces confirmation; false/undefined never suppresses evidence. */
	readonly forceConfirm?: boolean;
}

export interface BrowserActObservedSignals {
	readonly navigation?: boolean;
	readonly formSubmit?: boolean;
	readonly mutatingRequest?: boolean;
	readonly mutatingRequestMethods?: readonly string[];
}

export interface BrowserActCommitSignal {
	readonly forceConfirm: boolean;
	readonly reasons: readonly string[];
	readonly observed: {
		readonly navigation: boolean;
		readonly formSubmit: boolean;
		readonly mutatingRequest: boolean;
	};
}

export interface BrowserPageEvidence {
	readonly schemaVersion: typeof BROWSER_ACT_EVIDENCE_SCHEMA_VERSION;
	readonly evidenceNonce: string;
	readonly urlHash: string;
	readonly urlOrigin: string | null;
	readonly domDigest: string;
	readonly screenshotHash: string;
	readonly screenshotRef: string;
	readonly revision: string;
	readonly externalRevision?: string;
}

export interface BrowserActEvidence extends BrowserPageEvidence {
	readonly submittedValuesHash: string;
	readonly commitSignal: BrowserActCommitSignal;
}

export interface CaptureBrowserActEvidenceOptions {
	readonly screenshotSink: BrowserActScreenshotSink;
	readonly commitmentSecret: string | Uint8Array;
	readonly observedSignals?: BrowserActObservedSignals;
	readonly evidenceNonce?: string;
	readonly externalRevision?: string;
	readonly domExtractor?: (page: BrowserActEvidencePage) => Promise<string>;
}

export async function captureBrowserActEvidence(
	page: BrowserActEvidencePage,
	action: BrowserActIntent,
	options: CaptureBrowserActEvidenceOptions,
): Promise<BrowserActEvidence> {
	const commitmentSecret = normalizeCommitmentSecret(options.commitmentSecret);
	const evidenceNonce = normalizeEvidenceNonce(options.evidenceNonce);
	const canonicalAction = canonicalizeAction(action);
	const url = page.url();
	const urlOrigin = safeUrlOrigin(url);
	const rawDom = await (options.domExtractor ?? defaultDomExtractor)(page);
	const domDigest = hashCanonical("dom", normalizeBrowserDom(rawDom));
	const screenshotBytes = await page.screenshot({ type: "png", fullPage: true });
	const screenshotHash = hashBytes(screenshotBytes);
	const capturedUrlAfterScreenshot = page.url();
	if (capturedUrlAfterScreenshot !== url) {
		throw new Error("browser act evidence capture observed page URL change during capture");
	}
	const urlHash = hmacCanonical("page-url", { evidenceNonce, url }, commitmentSecret);
	const screenshotRef = await options.screenshotSink.storeScreenshot({
		bytes: screenshotBytes,
		contentType: "image/png",
		hash: screenshotHash,
	});
	// The revision is the WYSIWYS binding anchor (deriveBrowserWriteBindingHash). It MUST
	// be DETERMINISTIC for an unchanged page: the committer recaptures the SAME live page at
	// execute time (browser-act-executor.ts recaptureEvidence) and the revision must
	// re-produce identically, or a legitimate approved write fails closed as binding drift.
	// screenshotHash is EXCLUDED on purpose: a fullPage PNG of a real page is NOT
	// byte-identical between two captures (render timing, animation, blinking cursor,
	// sub-pixel anti-aliasing, lazy images), so folding it into the binding makes every
	// real-page commit fail re-verification (caught by the live B canary; the committer-probe
	// missed it because it fakes a deterministic screenshot). The screenshot remains in the
	// evidence below (screenshotHash/screenshotRef) as the human's approval-card display +
	// audit — it is the VISUAL confirmation, not the crypto anchor. The binding still fails
	// on any DOM / url / submitted-value change (a real page mutation), which is the WYSIWYS
	// intent; a purely cosmetic re-render that does not change the DOM is intentionally not
	// drift.
	const revision = hmacCanonical(
		"page-revision",
		{
			domDigest,
			evidenceNonce,
			urlHash,
		},
		commitmentSecret,
	);
	const submittedValuesHash = hmacCanonical(
		"submitted-values",
		{
			evidenceNonce,
			pageRevision: revision,
			target: canonicalAction.target,
			values: canonicalAction.submittedValues,
			verb: canonicalAction.verb,
		},
		commitmentSecret,
	);

	return {
		schemaVersion: BROWSER_ACT_EVIDENCE_SCHEMA_VERSION,
		evidenceNonce,
		urlHash,
		urlOrigin,
		domDigest,
		screenshotHash,
		screenshotRef,
		revision,
		...(options.externalRevision ? { externalRevision: options.externalRevision } : {}),
		submittedValuesHash,
		commitSignal: classifyCommitSignal(
			{ ...action, verb: canonicalAction.verb },
			options.observedSignals ?? {},
		),
	};
}

export function normalizeBrowserDom(markup: string): string {
	return stripHtmlComments(markup)
		.replace(/\s(?:nonce|data-reactid|data-reactroot)=("[^"]*"|'[^']*')/g, "")
		.replace(/\s+/g, " ")
		.replace(/>\s+/g, ">")
		.replace(/\s+</g, "<")
		.trim();
}

function stripHtmlComments(markup: string): string {
	let output = "";
	let offset = 0;
	while (offset < markup.length) {
		const start = markup.indexOf("<!--", offset);
		if (start === -1) {
			output += markup.slice(offset);
			break;
		}
		output += markup.slice(offset, start);
		const end = markup.indexOf("-->", start + 4);
		if (end === -1) break;
		offset = end + 3;
	}
	return output;
}

export function classifyCommitSignal(
	action: BrowserActIntent,
	observedSignals: BrowserActObservedSignals = {},
): BrowserActCommitSignal {
	const reasons: string[] = [];
	const verb = action.verb.trim().toLowerCase();
	const mutatingRequest = Boolean(
		observedSignals.mutatingRequest ||
			observedSignals.mutatingRequestMethods?.some((method) =>
				MUTATING_HTTP_METHODS.has(method.trim().toUpperCase()),
			),
	);

	if (action.forceConfirm === true) reasons.push("action.force_confirm");
	if (!NON_COMMITTING_VERBS.has(verb)) reasons.push(`action.verb.${verb}`);
	if (observedSignals.navigation) reasons.push("playwright.navigation_observed");
	if (observedSignals.formSubmit) reasons.push("playwright.form_submit_observed");
	if (mutatingRequest) reasons.push("playwright.mutating_request_observed");

	return {
		forceConfirm: reasons.length > 0,
		reasons,
		observed: {
			navigation: Boolean(observedSignals.navigation),
			formSubmit: Boolean(observedSignals.formSubmit),
			mutatingRequest,
		},
	};
}

async function defaultDomExtractor(page: BrowserActEvidencePage): Promise<string> {
	return page.evaluate<string>(
		"document.documentElement ? document.documentElement.outerHTML : ''",
	);
}

function hashCanonical(kind: string, value: unknown): string {
	const canonical = JSON.stringify(
		sortKeysDeep({
			kind,
			schemaVersion: BROWSER_ACT_EVIDENCE_SCHEMA_VERSION,
			value,
		}),
	);
	return hashBytes(Buffer.from(canonical, "utf8"));
}

function hmacCanonical(kind: string, value: unknown, secret: Uint8Array): string {
	const canonical = JSON.stringify(
		sortKeysDeep({
			kind,
			schemaVersion: BROWSER_ACT_EVIDENCE_SCHEMA_VERSION,
			value,
		}),
	);
	return `hmac-sha256:${crypto.createHmac("sha256", secret).update(canonical).digest("hex")}`;
}

function hashBytes(bytes: Uint8Array): string {
	return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function normalizeCommitmentSecret(secret: string | Uint8Array): Uint8Array {
	const bytes = typeof secret === "string" ? Buffer.from(secret, "utf8") : Buffer.from(secret);
	if (bytes.byteLength < 32) {
		throw new Error("browser act evidence commitment secret must be at least 32 bytes");
	}
	return bytes;
}

function normalizeEvidenceNonce(nonce: string | undefined): string {
	const normalized = nonce?.trim() || crypto.randomBytes(16).toString("base64url");
	if (!normalized) throw new Error("browser act evidence nonce must be non-empty");
	return normalized;
}

function canonicalizeAction(action: BrowserActIntent): {
	readonly verb: string;
	readonly target: string | null;
	readonly submittedValues: BrowserActJsonValue;
} {
	return {
		verb: action.verb.trim().toLowerCase(),
		target: action.target?.trim() || null,
		submittedValues: normalizeJsonValue(action.submittedValues ?? null),
	};
}

function normalizeJsonValue(
	value: unknown,
	seen: WeakSet<object> = new WeakSet(),
): BrowserActJsonValue {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") {
		if (!Number.isFinite(value)) {
			throw new TypeError("browser act submitted values must contain only finite numbers");
		}
		return value;
	}
	if (Array.isArray(value)) {
		trackJsonObject(value, seen);
		return value.map((item) => normalizeJsonValue(item, seen));
	}
	if (typeof value === "object" && value !== null) {
		trackJsonObject(value, seen);
		const prototype = Object.getPrototypeOf(value);
		if (prototype !== Object.prototype && prototype !== null) {
			throw new TypeError("browser act submitted values must be plain JSON objects");
		}
		const normalized: Record<string, BrowserActJsonValue> = {};
		for (const key of Object.keys(value).sort()) {
			const item = (value as Record<string, unknown>)[key];
			if (item === undefined) {
				throw new TypeError("browser act submitted values must not contain undefined");
			}
			normalized[key] = normalizeJsonValue(item, seen);
		}
		return normalized;
	}
	throw new TypeError("browser act submitted values must be JSON values");
}

function trackJsonObject(value: object, seen: WeakSet<object>): void {
	if (seen.has(value)) {
		throw new TypeError("browser act submitted values must not contain cycles");
	}
	seen.add(value);
}

function safeUrlOrigin(url: string): string | null {
	try {
		const origin = new URL(url).origin;
		return origin === "null" ? null : origin;
	} catch {
		return null;
	}
}

// Provably NON-committing verbs: pure data entry into a single field that does not
// itself navigate or submit. This is an ALLOWLIST, not a denylist — every other verb
// is treated as committing and routed to prepare + human approval (fail-closed). That
// includes `selectOption` (a `<select>` change can auto-apply), `click`/`press`/`goto`,
// and any unknown/future `BrowserActVerb`. A denylist silently mis-classified the union
// value `selectOption` as the absent `select` and let it run inline with no approval; an
// allowlist makes a forgotten verb committing by default. The parity test in
// `tests/relay/browser-act-evidence.test.ts` asserts every `BrowserActVerb`.
//
// NOTE: a non-committing classification is necessary but NOT sufficient to run inline.
// A logged-in (cookie-bearing) act NEVER runs inline regardless of verb — the relay
// surface refuses it and requires prepare + approval. Inline acts are reserved for
// cookie-less public pages, where `act()` additionally fails closed if the settle step
// observes a mutation (navigation/submit/mutating request) the verb did not predict.
const NON_COMMITTING_VERBS = new Set<string>(["fill", "type"]);

const MUTATING_HTTP_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
