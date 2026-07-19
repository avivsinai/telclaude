export const HOUSEHOLD_OUTBOUND_SAFETY_CLASSIFIER_VERSION = "household_outbound_safety_v1";
export const HOUSEHOLD_OUTBOUND_SAFETY_MAX_SCALARS = 8_000;

export type HouseholdOutboundSafetyReasonCode =
	| "financial"
	| "credential"
	| "external_link"
	| "scam_action"
	| "classifier_fail_closed";

export type HouseholdOutboundSafetyClassification = {
	readonly classifierVersion: typeof HOUSEHOLD_OUTBOUND_SAFETY_CLASSIFIER_VERSION;
	readonly safeForAutoGrant: boolean;
	readonly reasonCodes: readonly HouseholdOutboundSafetyReasonCode[];
};

const HEBREW_FINAL_FORMS: Readonly<Record<string, string>> = {
	ך: "כ",
	ם: "מ",
	ן: "נ",
	ף: "פ",
	ץ: "צ",
};

const FINANCIAL_PHRASES_V1 = normalizedPhrases([
	"כסף",
	"הכסף",
	"בכסף",
	"תשלום",
	"התשלום",
	"לתשלום",
	"בתשלום",
	"לשלם",
	"אשראי",
	"כרטיס אשראי",
	"חשבון בנק",
	"money",
	"pay",
	"payment",
	"wire money",
	"credit card",
	"bank account",
]);

const CREDENTIAL_PHRASES_V1 = normalizedPhrases([
	"קוד אימות",
	"קוד האימות",
	"קוד חד פעמי",
	"קוד חד-פעמי",
	"סיסמה",
	"הסיסמה",
	"pin",
	"otp",
	"תז",
	'ת"ז',
	"ת׳ז",
	"ת״ז",
	"תעודת זהות",
	"מספר זהות",
	"password",
	"passcode",
	"verification code",
]);

const SCAM_ACTION_PHRASES_V1 = normalizedPhrases([
	"לחץ כאן",
	"לחצי כאן",
	"לחצו כאן",
	"אמת חשבון",
	"אמת את החשבון",
	"אמתי חשבון",
	"אמתי את החשבון",
	"אמתו חשבון",
	"אמתו את החשבון",
	"אשר חשבון",
	"אשר את החשבון",
	"אשרי חשבון",
	"אשרי את החשבון",
	"אשרו חשבון",
	"אשרו את החשבון",
	"click here",
	"verify account",
	"verify the account",
	"verify your account",
	"confirm account",
	"confirm the account",
	"confirm your account",
]);

const EXTERNAL_LINK_V1 =
	/(?:\bhttps?:\/\/|\bwww\.|\b(?:bit\.ly|t\.co|tinyurl\.com|rb\.gy|goo\.gl|is\.gd|cutt\.ly|wa\.me)(?:[/:?#]|\b)|\b(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,62}[\p{L}\p{N}])?\.)+(?:com|org|net|info|biz|io|me|ly|app|co\.il|gov\.il|org\.il|ac\.il|il)(?:[/:?#]|\b))/iu;

export function classifyHouseholdOutboundSafetyV1(
	text: string,
): HouseholdOutboundSafetyClassification {
	try {
		if (
			Array.from(text).length > HOUSEHOLD_OUTBOUND_SAFETY_MAX_SCALARS ||
			hasInvalidUnicode(text)
		) {
			return failClosed();
		}
		const normalized = normalizeForMatching(text);
		const reasonCodes: HouseholdOutboundSafetyReasonCode[] = [];
		if (containsPhrase(normalized, FINANCIAL_PHRASES_V1)) reasonCodes.push("financial");
		if (containsPhrase(normalized, CREDENTIAL_PHRASES_V1)) reasonCodes.push("credential");
		if (EXTERNAL_LINK_V1.test(normalized)) reasonCodes.push("external_link");
		if (containsPhrase(normalized, SCAM_ACTION_PHRASES_V1)) reasonCodes.push("scam_action");
		return {
			classifierVersion: HOUSEHOLD_OUTBOUND_SAFETY_CLASSIFIER_VERSION,
			safeForAutoGrant: reasonCodes.length === 0,
			reasonCodes,
		};
	} catch {
		return failClosed();
	}
}

function normalizedPhrases(phrases: readonly string[]): readonly string[] {
	return phrases.map(normalizeForMatching);
}

function normalizeForMatching(text: string): string {
	return text
		.normalize("NFKC")
		.replace(/\p{Cf}+/gu, "")
		.normalize("NFD")
		.replace(/\p{M}+/gu, "")
		.toLowerCase()
		.replace(/[ךםןףץ]/gu, (value) => HEBREW_FINAL_FORMS[value] ?? value)
		.replace(/\s+/gu, " ")
		.trim();
}

function containsPhrase(text: string, phrases: readonly string[]): boolean {
	return phrases.some((phrase) => {
		const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		return new RegExp(`(?:^|[^\\p{L}\\p{N}])${escaped}(?=$|[^\\p{L}\\p{N}])`, "u").test(text);
	});
}

function hasInvalidUnicode(text: string): boolean {
	return /[\uD800-\uDFFF]/u.test(text);
}

function failClosed(): HouseholdOutboundSafetyClassification {
	return {
		classifierVersion: HOUSEHOLD_OUTBOUND_SAFETY_CLASSIFIER_VERSION,
		safeForAutoGrant: false,
		reasonCodes: ["classifier_fail_closed"],
	};
}
