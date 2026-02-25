/**
 * Action registry for all Google service operations.
 * Defines every supported action with its type (read/action), params, and required scope.
 */

import type { ActionDefinition, ActionType } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Gmail Actions
// ═══════════════════════════════════════════════════════════════════════════════

const GMAIL_ACTIONS: ActionDefinition[] = [
	{
		id: "search",
		service: "gmail",
		type: "read",
		description: "Search emails by query",
		params: {
			q: { type: "string", required: true, description: "Gmail search query" },
			maxResults: {
				type: "number",
				required: false,
				description: "Max results (default 10)",
				default: 10,
			},
			pageToken: { type: "string", required: false, description: "Pagination token" },
		},
		scope: "https://www.googleapis.com/auth/gmail.readonly",
	},
	{
		id: "read_message",
		service: "gmail",
		type: "read",
		description: "Read a single email message",
		params: {
			messageId: { type: "string", required: true, description: "Message ID" },
			format: {
				type: "string",
				required: false,
				description: "Format: full, metadata, minimal",
				default: "full",
			},
		},
		scope: "https://www.googleapis.com/auth/gmail.readonly",
	},
	{
		id: "read_thread",
		service: "gmail",
		type: "read",
		description: "Read an email thread",
		params: {
			threadId: { type: "string", required: true, description: "Thread ID" },
		},
		scope: "https://www.googleapis.com/auth/gmail.readonly",
	},
	{
		id: "list_labels",
		service: "gmail",
		type: "read",
		description: "List all Gmail labels",
		params: {},
		scope: "https://www.googleapis.com/auth/gmail.readonly",
	},
	{
		id: "download_attachment",
		service: "gmail",
		type: "read",
		description: "Download an email attachment",
		params: {
			messageId: { type: "string", required: true, description: "Message ID" },
			attachmentId: { type: "string", required: true, description: "Attachment ID" },
		},
		scope: "https://www.googleapis.com/auth/gmail.readonly",
	},
	{
		id: "create_draft",
		service: "gmail",
		type: "action",
		description: "Create an email draft (requires approval)",
		params: {
			to: { type: "string", required: true, description: "Recipient email" },
			subject: { type: "string", required: true, description: "Email subject" },
			body: { type: "string", required: true, description: "Email body (plain text)" },
			cc: { type: "string", required: false, description: "CC recipients (comma-separated)" },
		},
		scope: "https://www.googleapis.com/auth/gmail.compose",
	},
];

// ═══════════════════════════════════════════════════════════════════════════════
// Calendar Actions
// ═══════════════════════════════════════════════════════════════════════════════

const CALENDAR_ACTIONS: ActionDefinition[] = [
	{
		id: "list_events",
		service: "calendar",
		type: "read",
		description: "List upcoming events",
		params: {
			calendarId: {
				type: "string",
				required: false,
				description: "Calendar ID (default: primary)",
				default: "primary",
			},
			timeMin: { type: "string", required: false, description: "Start time (ISO 8601)" },
			timeMax: { type: "string", required: false, description: "End time (ISO 8601)" },
			maxResults: {
				type: "number",
				required: false,
				description: "Max results (default 10)",
				default: 10,
			},
		},
		scope: "https://www.googleapis.com/auth/calendar.events.readonly",
	},
	{
		id: "search_events",
		service: "calendar",
		type: "read",
		description: "Search events by query",
		params: {
			q: { type: "string", required: true, description: "Search query" },
			calendarId: {
				type: "string",
				required: false,
				description: "Calendar ID (default: primary)",
				default: "primary",
			},
			timeMin: { type: "string", required: false, description: "Start time (ISO 8601)" },
			timeMax: { type: "string", required: false, description: "End time (ISO 8601)" },
		},
		scope: "https://www.googleapis.com/auth/calendar.events.readonly",
	},
	{
		id: "get_event",
		service: "calendar",
		type: "read",
		description: "Get a single event by ID",
		params: {
			calendarId: {
				type: "string",
				required: false,
				description: "Calendar ID (default: primary)",
				default: "primary",
			},
			eventId: { type: "string", required: true, description: "Event ID" },
		},
		scope: "https://www.googleapis.com/auth/calendar.events.readonly",
	},
	{
		id: "freebusy",
		service: "calendar",
		type: "read",
		description: "Check free/busy status",
		params: {
			timeMin: { type: "string", required: true, description: "Start time (ISO 8601)" },
			timeMax: { type: "string", required: true, description: "End time (ISO 8601)" },
			calendarIds: {
				type: "string[]",
				required: false,
				description: "Calendar IDs (default: primary)",
			},
		},
		scope: "https://www.googleapis.com/auth/calendar.freebusy",
	},
	{
		id: "list_calendars",
		service: "calendar",
		type: "read",
		description: "List all calendars",
		params: {},
		scope: "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
	},
	{
		id: "create_event",
		service: "calendar",
		type: "action",
		description: "Create a calendar event (self-only, no attendees, requires approval)",
		params: {
			summary: { type: "string", required: true, description: "Event title" },
			start: { type: "string", required: true, description: "Start time (ISO 8601)" },
			end: { type: "string", required: true, description: "End time (ISO 8601)" },
			description: { type: "string", required: false, description: "Event description" },
			location: { type: "string", required: false, description: "Event location" },
			calendarId: {
				type: "string",
				required: false,
				description: "Calendar ID (default: primary)",
				default: "primary",
			},
		},
		scope: "https://www.googleapis.com/auth/calendar.events.owned",
	},
];

// ═══════════════════════════════════════════════════════════════════════════════
// Drive Actions
// ═══════════════════════════════════════════════════════════════════════════════

const DRIVE_ACTIONS: ActionDefinition[] = [
	{
		id: "search",
		service: "drive",
		type: "read",
		description: "Search files by query",
		params: {
			q: { type: "string", required: true, description: "Drive search query" },
			maxResults: {
				type: "number",
				required: false,
				description: "Max results (default 10)",
				default: 10,
			},
			pageToken: { type: "string", required: false, description: "Pagination token" },
		},
		scope: "https://www.googleapis.com/auth/drive.metadata.readonly",
	},
	{
		id: "list_files",
		service: "drive",
		type: "read",
		description: "List files in a folder",
		params: {
			folderId: {
				type: "string",
				required: false,
				description: "Folder ID (default: root)",
				default: "root",
			},
			maxResults: {
				type: "number",
				required: false,
				description: "Max results (default 10)",
				default: 10,
			},
			pageToken: { type: "string", required: false, description: "Pagination token" },
		},
		scope: "https://www.googleapis.com/auth/drive.metadata.readonly",
	},
	{
		id: "read_metadata",
		service: "drive",
		type: "read",
		description: "Get file metadata",
		params: {
			fileId: { type: "string", required: true, description: "File ID" },
		},
		scope: "https://www.googleapis.com/auth/drive.metadata.readonly",
	},
	{
		id: "download",
		service: "drive",
		type: "read",
		description: "Download a file",
		params: {
			fileId: { type: "string", required: true, description: "File ID" },
		},
		scope: "https://www.googleapis.com/auth/drive.readonly",
	},
	{
		id: "list_shared",
		service: "drive",
		type: "read",
		description: "List files shared with me",
		params: {
			maxResults: {
				type: "number",
				required: false,
				description: "Max results (default 10)",
				default: 10,
			},
			pageToken: { type: "string", required: false, description: "Pagination token" },
		},
		scope: "https://www.googleapis.com/auth/drive.metadata.readonly",
	},
];

// ═══════════════════════════════════════════════════════════════════════════════
// Contacts Actions
// ═══════════════════════════════════════════════════════════════════════════════

const CONTACTS_ACTIONS: ActionDefinition[] = [
	{
		id: "search",
		service: "contacts",
		type: "read",
		description: "Search contacts",
		params: {
			query: { type: "string", required: true, description: "Search query" },
			maxResults: {
				type: "number",
				required: false,
				description: "Max results (default 10)",
				default: 10,
			},
		},
		scope: "https://www.googleapis.com/auth/contacts.readonly",
	},
	{
		id: "list",
		service: "contacts",
		type: "read",
		description: "List contacts",
		params: {
			maxResults: {
				type: "number",
				required: false,
				description: "Max results (default 10)",
				default: 10,
			},
			pageToken: { type: "string", required: false, description: "Pagination token" },
		},
		scope: "https://www.googleapis.com/auth/contacts.readonly",
	},
	{
		id: "get",
		service: "contacts",
		type: "read",
		description: "Get a single contact",
		params: {
			resourceName: {
				type: "string",
				required: true,
				description: "Contact resource name (e.g., people/c123)",
			},
		},
		scope: "https://www.googleapis.com/auth/contacts.readonly",
	},
];

// ═══════════════════════════════════════════════════════════════════════════════
// Registry
// ═══════════════════════════════════════════════════════════════════════════════

const ALL_ACTIONS: ActionDefinition[] = [
	...GMAIL_ACTIONS,
	...CALENDAR_ACTIONS,
	...DRIVE_ACTIONS,
	...CONTACTS_ACTIONS,
];

const actionMap = new Map<string, ActionDefinition>();
for (const action of ALL_ACTIONS) {
	actionMap.set(`${action.service}:${action.id}`, action);
}

export function getAction(service: string, actionId: string): ActionDefinition | undefined {
	return actionMap.get(`${service}:${actionId}`);
}

export function getActionsForService(service: string): ActionDefinition[] {
	return ALL_ACTIONS.filter((a) => a.service === service);
}

export function isActionType(service: string, actionId: string): ActionType | undefined {
	return actionMap.get(`${service}:${actionId}`)?.type;
}

export function getAllActions(): ActionDefinition[] {
	return ALL_ACTIONS;
}
