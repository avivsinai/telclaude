/**
 * Secrets management module.
 *
 * Provides secure storage for API keys and other sensitive credentials
 * using OS keychain (macOS/Linux/Windows) or encrypted file storage.
 */

export {
	deleteSecret,
	getSecret,
	getStorageProviderName,
	hasSecret,
	isSecretsStorageAvailable,
	SECRET_KEYS,
	storeSecret,
} from "./keychain.js";
