/**
 * Calendar handler — dispatches FetchRequest actions to the Google Calendar API.
 */

import { google } from "googleapis";
import type { FetchRequest, FetchResponse } from "../types.js";

export async function handleCalendar(
	request: FetchRequest,
	accessToken: string,
): Promise<FetchResponse> {
	const auth = new google.auth.OAuth2();
	auth.setCredentials({ access_token: accessToken });
	const calendar = google.calendar({ version: "v3", auth });

	switch (request.action) {
		case "list_events":
			return handleListEvents(calendar, request.params);
		case "search_events":
			return handleSearchEvents(calendar, request.params);
		case "get_event":
			return handleGetEvent(calendar, request.params);
		case "freebusy":
			return handleFreebusy(calendar, request.params);
		case "list_calendars":
			return handleListCalendars(calendar);
		case "create_event":
			return handleCreateEvent(calendar, request.params);
		default:
			return {
				status: "error",
				error: `Unknown Calendar action: ${request.action}`,
				attachments: [],
			};
	}
}

type Calendar = ReturnType<typeof google.calendar>;

async function handleListEvents(
	calendar: Calendar,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await calendar.events.list({
			calendarId: (params.calendarId as string) ?? "primary",
			timeMin: params.timeMin as string | undefined,
			timeMax: params.timeMax as string | undefined,
			maxResults: (params.maxResults as number) ?? 10,
			singleEvents: true,
			orderBy: "startTime",
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleSearchEvents(
	calendar: Calendar,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await calendar.events.list({
			calendarId: (params.calendarId as string) ?? "primary",
			q: params.q as string,
			timeMin: params.timeMin as string | undefined,
			timeMax: params.timeMax as string | undefined,
			singleEvents: true,
			orderBy: "startTime",
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleGetEvent(
	calendar: Calendar,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await calendar.events.get({
			calendarId: (params.calendarId as string) ?? "primary",
			eventId: params.eventId as string,
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleFreebusy(
	calendar: Calendar,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const calendarIds = (params.calendarIds as string[]) ?? ["primary"];
		const items = calendarIds.map((id) => ({ id }));
		const res = await calendar.freebusy.query({
			requestBody: {
				timeMin: params.timeMin as string,
				timeMax: params.timeMax as string,
				items,
			},
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleListCalendars(calendar: Calendar): Promise<FetchResponse> {
	try {
		const res = await calendar.calendarList.list();
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleCreateEvent(
	calendar: Calendar,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		// SECURITY: No attendees in v1 (prevents email exfiltration)
		const res = await calendar.events.insert({
			calendarId: (params.calendarId as string) ?? "primary",
			requestBody: {
				summary: params.summary as string,
				description: params.description as string | undefined,
				location: params.location as string | undefined,
				start: { dateTime: params.start as string },
				end: { dateTime: params.end as string },
			},
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
