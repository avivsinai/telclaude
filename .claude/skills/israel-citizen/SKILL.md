---
name: israel-citizen
description: Access Israeli citizen services (Clalit health, appointments, lab results, prescriptions). Use when users ask about Israeli healthcare, medical appointments, or prescription renewals.
permissions:
  tools: [Bash]
---

You help users access their Israeli citizen services through the citizen-services API.

## Getting the User ID

**CRITICAL**: Your system prompt contains a tag like `<request-context user-id="453371121" />`.
Extract the numeric user ID from this tag and use it in ALL API calls.

**FIRST**, before any curl command, set the USER_ID variable:
```bash
USER_ID="<the number from request-context user-id attribute>"
```

For example, if your system prompt contains `<request-context user-id="453371121" />`, then:
```bash
USER_ID="453371121"
```

Then use `$USER_ID` in the `X-Actor-User-Id` header for all API calls.

## Available Services

Currently supported:
- **health-api** - Clalit Health Services (medical records, appointments, prescriptions)

## Available Actions for Clalit

| Action | Description | Parameters |
|--------|-------------|------------|
| `appointments` | View upcoming and past appointments | none |
| `lab_results` | View laboratory test results | none |
| `prescriptions` | View active prescriptions | none |
| `my_doctors` | View assigned doctors | none |
| `messages` | View messages from healthcare providers | none |
| `vaccines` | View vaccination history | none |
| `referrals` | View specialist referrals | none |
| `hospital_labs` | View hospital laboratory results | `hospital` (Hebrew name) |
| `hospital_summaries` | View hospital discharge summaries | `hospital` (Hebrew name) |
| `visit_summaries` | List clinic visit summaries (metadata only) | none |
| `visit_summary_pdf` | **Download the full visit summary PDF** | none |
| `medical_approvals` | View medical approvals/authorizations | none |

## IMPORTANT: Getting Full Visit Summary Content

When a user asks for the FULL visit summary content (not just metadata/list), you MUST use `visit_summary_pdf`:

```bash
curl -s -X POST http://citizen-services:3001/v1/health-api/visit_summary_pdf \
  -H "Content-Type: application/json" \
  -H "X-Actor-User-Id: $USER_ID" \
  -d '{}'
```

This downloads the most recent visit summary as a PDF. The response includes:
- `status`: "ok" if successful
- `attachments`: Array containing the PDF with `filename`, `mimeType`, `size`, and `inline` (base64 content)

## How to Use

Make HTTP requests to the citizen-services API:

```bash
curl -s -X POST http://citizen-services:3001/v1/health-api/{action} \
  -H "Content-Type: application/json" \
  -H "X-Actor-User-Id: $USER_ID" \
  -d '{}'
```

For actions requiring hospital parameter:
```bash
curl -s -X POST http://citizen-services:3001/v1/health-api/hospital_summaries \
  -H "Content-Type: application/json" \
  -H "X-Actor-User-Id: $USER_ID" \
  -d '{"hospital": "שיבא"}'
```

## Handling Responses

The API returns JSON with a `status` field:

### status: "ok"
Success! Check for:
- `data.noResults`: No records found (valid empty response, NOT an error)
- `data.items`: Array of results
- `attachments`: Downloaded files (PDFs) - check for `inline` field with base64 content

### status: "auth_required"
User needs to set up credentials first.

### status: "challenge_pending"
2FA required (SMS code). Tell user to check phone and provide code via `/otp health-api <code>`.

### status: "error"
Error occurred, message in `error` field.

## Hospital Names (Hebrew)

For hospital_summaries and hospital_labs:
- שיבא (Sheba)
- איכילוב (Ichilov)
- רמב"ם (Rambam)
- הדסה (Hadassah)
- סורוקה (Soroka)

## Important Notes

- **For visit summary CONTENT, use `visit_summary_pdf`** - not `visit_summaries` which only returns metadata
- Empty results (`noResults` field) is a valid response, NOT an error
- API uses browser automation - may take 10-30 seconds
- All data is real medical data - handle with care and respect privacy
