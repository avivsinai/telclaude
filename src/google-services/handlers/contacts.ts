/**
 * Contacts handler — dispatches FetchRequest actions to the Google People API.
 */

import { google } from "googleapis";
import type { FetchRequest, FetchResponse } from "../types.js";

const PERSON_FIELDS = "names,emailAddresses,phoneNumbers,organizations,photos";

export async function handleContacts(
	request: FetchRequest,
	accessToken: string,
): Promise<FetchResponse> {
	const auth = new google.auth.OAuth2();
	auth.setCredentials({ access_token: accessToken });
	const people = google.people({ version: "v1", auth });

	switch (request.action) {
		case "search":
			return handleSearch(people, request.params);
		case "list":
			return handleList(people, request.params);
		case "get":
			return handleGet(people, request.params);
		default:
			return {
				status: "error",
				error: `Unknown Contacts action: ${request.action}`,
				attachments: [],
			};
	}
}

type People = ReturnType<typeof google.people>;

async function handleSearch(
	people: People,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await people.people.searchContacts({
			query: params.query as string,
			pageSize: (params.maxResults as number) ?? 10,
			readMask: PERSON_FIELDS,
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleList(people: People, params: Record<string, unknown>): Promise<FetchResponse> {
	try {
		const res = await people.people.connections.list({
			resourceName: "people/me",
			pageSize: (params.maxResults as number) ?? 10,
			pageToken: params.pageToken as string | undefined,
			personFields: PERSON_FIELDS,
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleGet(people: People, params: Record<string, unknown>): Promise<FetchResponse> {
	try {
		const res = await people.people.get({
			resourceName: params.resourceName as string,
			personFields: PERSON_FIELDS,
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

function formatError(err: unknown): string {
	if (err instanceof Error) return err.message;
	return String(err);
}
