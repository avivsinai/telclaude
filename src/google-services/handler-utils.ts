/**
 * Shared utilities for Google service handlers.
 */

import { google } from "googleapis";

export function formatError(err: unknown): string {
	if (err instanceof Error) return err.message;
	return String(err);
}

export function createGoogleAuth(accessToken: string): InstanceType<typeof google.auth.OAuth2> {
	const auth = new google.auth.OAuth2();
	auth.setCredentials({ access_token: accessToken });
	return auth;
}
