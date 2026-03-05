/**
 * Shared keytar (OS keychain) store.
 *
 * Provides a key-value store backed by the OS keychain via keytar.
 * Used by both TOTP storage and secrets keychain.
 */

const SERVICE_NAME = "telclaude";

export class KeytarStore {
	private keytar: typeof import("keytar") | null = null;

	private async getKeytar() {
		if (!this.keytar) {
			try {
				const mod = await import("keytar");
				this.keytar = (mod.default ?? mod) as typeof import("keytar");
			} catch (err) {
				throw new Error(`keytar not available: ${String(err)}`);
			}
		}
		return this.keytar;
	}

	async store(key: string, value: string): Promise<void> {
		const keytar = await this.getKeytar();
		await keytar.setPassword(SERVICE_NAME, key, value);
	}

	async get(key: string): Promise<string | null> {
		const keytar = await this.getKeytar();
		return keytar.getPassword(SERVICE_NAME, key);
	}

	async delete(key: string): Promise<boolean> {
		const keytar = await this.getKeytar();
		return keytar.deletePassword(SERVICE_NAME, key);
	}

	async has(key: string): Promise<boolean> {
		const keytar = await this.getKeytar();
		const secret = await keytar.getPassword(SERVICE_NAME, key);
		return secret !== null;
	}
}
