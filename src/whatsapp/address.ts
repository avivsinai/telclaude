const WHATSAPP_ADDRESS_PREFIX = "whatsapp:";
const WHATSAPP_DIRECT_JID_SUFFIX = "@s.whatsapp.net";

export function normalizeWhatsAppAddressRef(value: string): string | null {
	const trimmed = value.trim();
	const e164 = trimmed.startsWith(WHATSAPP_ADDRESS_PREFIX)
		? trimmed.slice(WHATSAPP_ADDRESS_PREFIX.length)
		: trimmed;
	if (!/^\+[1-9]\d{6,14}$/.test(e164)) return null;
	return `${WHATSAPP_ADDRESS_PREFIX}${e164}`;
}

export function whatsAppDirectConversationKey(addressRef: string): string | null {
	const normalized = normalizeWhatsAppAddressRef(addressRef);
	if (!normalized) return null;
	const digits = normalized.slice(`${WHATSAPP_ADDRESS_PREFIX}+`.length);
	return `${WHATSAPP_ADDRESS_PREFIX}${digits}${WHATSAPP_DIRECT_JID_SUFFIX}`;
}
