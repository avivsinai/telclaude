import { describe, expect, it } from "vitest";
import {
	MEDIA_ACTION_CONFIRMATION_COPY,
	mediaActionConfirmationCopy,
} from "../../src/relay/media-action-confirmation-copy.js";

describe("media action confirmation copy", () => {
	it("renders fixed female and male variants with canonical choices", () => {
		expect(mediaActionConfirmationCopy("choice_required", "f")).toContain("השיבי 1");
		expect(mediaActionConfirmationCopy("choice_required", "m")).toContain("השב 1");
		for (const gender of ["f", "m"] as const) {
			expect(mediaActionConfirmationCopy("choice_required", gender)).toContain("2 לביטול");
		}
	});

	it("contains no media content or internal identifiers", () => {
		const rendered = JSON.stringify(MEDIA_ACTION_CONFIRMATION_COPY);
		expect(rendered).not.toMatch(/confirmationId|turn_|sha256|quarantine|source|transcript/iu);
	});
});
