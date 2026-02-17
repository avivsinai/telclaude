/**
 * Unicode homoglyph protection.
 *
 * Folds visually similar Unicode characters to their ASCII equivalents.
 * Defends against prompt injection via lookalike characters that bypass
 * regex-based security checks (e.g., fullwidth brackets, CJK punctuation,
 * mathematical symbols that resemble ASCII control chars).
 */

/**
 * Mapping of Unicode homoglyph codepoints to their ASCII equivalents.
 * Covers: fullwidth forms, CJK punctuation, mathematical symbols,
 * modifier letters, and common lookalike characters.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
	// Fullwidth ASCII variants (U+FF01–U+FF5E)
	"\uFF01": "!",
	"\uFF02": '"',
	"\uFF03": "#",
	"\uFF04": "$",
	"\uFF05": "%",
	"\uFF06": "&",
	"\uFF07": "'",
	"\uFF08": "(",
	"\uFF09": ")",
	"\uFF0A": "*",
	"\uFF0B": "+",
	"\uFF0C": ",",
	"\uFF0D": "-",
	"\uFF0E": ".",
	"\uFF0F": "/",
	// Fullwidth digits
	"\uFF10": "0",
	"\uFF11": "1",
	"\uFF12": "2",
	"\uFF13": "3",
	"\uFF14": "4",
	"\uFF15": "5",
	"\uFF16": "6",
	"\uFF17": "7",
	"\uFF18": "8",
	"\uFF19": "9",
	"\uFF1A": ":",
	"\uFF1B": ";",
	"\uFF1C": "<",
	"\uFF1D": "=",
	"\uFF1E": ">",
	"\uFF1F": "?",
	"\uFF20": "@",
	// Fullwidth uppercase letters
	"\uFF21": "A",
	"\uFF22": "B",
	"\uFF23": "C",
	"\uFF24": "D",
	"\uFF25": "E",
	"\uFF26": "F",
	"\uFF27": "G",
	"\uFF28": "H",
	"\uFF29": "I",
	"\uFF2A": "J",
	"\uFF2B": "K",
	"\uFF2C": "L",
	"\uFF2D": "M",
	"\uFF2E": "N",
	"\uFF2F": "O",
	"\uFF30": "P",
	"\uFF31": "Q",
	"\uFF32": "R",
	"\uFF33": "S",
	"\uFF34": "T",
	"\uFF35": "U",
	"\uFF36": "V",
	"\uFF37": "W",
	"\uFF38": "X",
	"\uFF39": "Y",
	"\uFF3A": "Z",
	"\uFF3B": "[",
	"\uFF3C": "\\",
	"\uFF3D": "]",
	"\uFF3E": "^",
	"\uFF3F": "_",
	"\uFF40": "`",
	// Fullwidth lowercase letters
	"\uFF41": "a",
	"\uFF42": "b",
	"\uFF43": "c",
	"\uFF44": "d",
	"\uFF45": "e",
	"\uFF46": "f",
	"\uFF47": "g",
	"\uFF48": "h",
	"\uFF49": "i",
	"\uFF4A": "j",
	"\uFF4B": "k",
	"\uFF4C": "l",
	"\uFF4D": "m",
	"\uFF4E": "n",
	"\uFF4F": "o",
	"\uFF50": "p",
	"\uFF51": "q",
	"\uFF52": "r",
	"\uFF53": "s",
	"\uFF54": "t",
	"\uFF55": "u",
	"\uFF56": "v",
	"\uFF57": "w",
	"\uFF58": "x",
	"\uFF59": "y",
	"\uFF5A": "z",
	"\uFF5B": "{",
	"\uFF5C": "|",
	"\uFF5D": "}",
	"\uFF5E": "~",

	// CJK punctuation lookalikes
	"\u3001": ",", // Ideographic comma
	"\u3002": ".", // Ideographic full stop
	"\u3008": "<", // Left angle bracket
	"\u3009": ">", // Right angle bracket
	"\u300A": "<<", // Left double angle bracket
	"\u300B": ">>", // Right double angle bracket
	"\u300C": "[", // Left corner bracket
	"\u300D": "]", // Right corner bracket
	"\u300E": "[", // Left white corner bracket
	"\u300F": "]", // Right white corner bracket
	"\u3010": "[", // Left black lenticular bracket
	"\u3011": "]", // Right black lenticular bracket
	"\u3014": "(", // Left tortoise shell bracket
	"\u3015": ")", // Right tortoise shell bracket

	// Mathematical operators that look like ASCII
	"\u2212": "-", // Minus sign
	"\u2215": "/", // Division slash
	"\u2216": "\\", // Set minus
	"\u2217": "*", // Asterisk operator
	"\u2223": "|", // Divides
	"\u2236": ":", // Ratio
	"\u223C": "~", // Tilde operator

	// Modifier letters
	"\u02B9": "'", // Modifier letter prime
	"\u02BA": '"', // Modifier letter double prime
	"\u02BB": "'", // Modifier letter turned comma
	"\u02BC": "'", // Modifier letter apostrophe
	"\u02BD": "'", // Modifier letter reversed comma
	"\u02C8": "'", // Modifier letter vertical line
	"\u02CA": "'", // Modifier letter acute accent
	"\u02CB": "`", // Modifier letter grave accent

	// Common lookalikes from other scripts
	"\u0410": "A", // Cyrillic А
	"\u0412": "B", // Cyrillic В
	"\u0421": "C", // Cyrillic С
	"\u0415": "E", // Cyrillic Е
	"\u041D": "H", // Cyrillic Н
	"\u041A": "K", // Cyrillic К
	"\u041C": "M", // Cyrillic М
	"\u041E": "O", // Cyrillic О
	"\u0420": "P", // Cyrillic Р
	"\u0422": "T", // Cyrillic Т
	"\u0425": "X", // Cyrillic Х
	"\u0430": "a", // Cyrillic а
	"\u0435": "e", // Cyrillic е
	"\u043E": "o", // Cyrillic о
	"\u0440": "p", // Cyrillic р
	"\u0441": "c", // Cyrillic с
	"\u0443": "y", // Cyrillic у
	"\u0445": "x", // Cyrillic х

	// Zero-width and invisible characters (fold to empty)
	"\u200B": "", // Zero-width space
	"\u200C": "", // Zero-width non-joiner
	"\u200D": "", // Zero-width joiner
	"\u200E": "", // Left-to-right mark
	"\u200F": "", // Right-to-left mark
	"\uFEFF": "", // Zero-width no-break space (BOM)
	"\u00AD": "", // Soft hyphen
	"\u2060": "", // Word joiner
	"\u2061": "", // Function application
	"\u2062": "", // Invisible times
	"\u2063": "", // Invisible separator
	"\u2064": "", // Invisible plus
};

// Build regex from map keys for fast replacement
const HOMOGLYPH_REGEX = new RegExp(
	`[${Object.keys(HOMOGLYPH_MAP)
		.map((ch) => `\\u{${ch.codePointAt(0)?.toString(16)}}`)
		.join("")}]`,
	"gu",
);

/**
 * Fold Unicode homoglyphs to ASCII equivalents.
 * Returns the normalized string.
 */
export function foldHomoglyphs(input: string): string {
	return input.replace(HOMOGLYPH_REGEX, (ch) => HOMOGLYPH_MAP[ch] ?? ch);
}

/**
 * Check if a string contains any known homoglyph characters.
 */
export function containsHomoglyphs(input: string): boolean {
	return HOMOGLYPH_REGEX.test(input);
}

/**
 * Get a list of homoglyph characters found in the input.
 * Returns array of { original, replacement, codePoint } for each unique homoglyph.
 */
export function detectHomoglyphs(
	input: string,
): Array<{ original: string; replacement: string; codePoint: string }> {
	const found = new Map<string, { original: string; replacement: string; codePoint: string }>();

	for (const ch of input) {
		if (ch in HOMOGLYPH_MAP && !found.has(ch)) {
			found.set(ch, {
				original: ch,
				replacement: HOMOGLYPH_MAP[ch],
				codePoint: `U+${ch.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}`,
			});
		}
	}

	return Array.from(found.values());
}
