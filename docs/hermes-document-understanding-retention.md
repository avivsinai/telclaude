# Hosted document understanding retention gate

Status: **dark; not approved for live document processing**.

The relay document adapter sends sanitized image or PDF bytes inline to the OpenAI Responses API. It does not use the Files API, does not provide tools, and sets `store: false` on every request. Raw relay-side quarantine bytes remain subject to the existing 24-hour hard deletion bound and are deleted immediately after a terminal extraction result.

`store: false` is necessary but is not a zero-retention guarantee. OpenAI documents that Responses requests may still be retained in abuse-monitoring logs for up to 30 days by default. For organizations without Zero Data Retention, supported models may also use extended prompt caching with application state retained for up to 24 hours. Approved Zero Data Retention or Modified Abuse Monitoring controls can change that posture, subject to provider eligibility and limitations. OpenAI also documents a separate image/file safety scan exception that may retain a flagged input for manual review even when a data-retention control is enabled.

Sources reviewed 2026-07-18:

- [OpenAI data controls and endpoint retention](https://developers.openai.com/api/docs/guides/your-data#data-retention-controls-for-abuse-monitoring)
- [OpenAI Responses statefulness and `store: false`](https://developers.openai.com/api/docs/guides/migrate-to-responses#4-decide-when-to-use-statefulness)
- [OpenAI inline file inputs](https://developers.openai.com/api/docs/guides/file-inputs#base64-encoded-files)

## Activation gate

Before enabling this adapter for any household binding, the operator must record evidence that:

1. the exact OpenAI organization and project have an approved data-control posture appropriate for the pilot;
2. applicable health-data contractual and legal requirements, including endpoint and model eligibility, have been reviewed and accepted;
3. the versioned model allowlist and provider policy above are still current;
4. the media kill switch and the specific household binding are explicitly eligible; and
5. a redacted dark-state trace proves that no raw bytes, paths, EXIF, filenames, provider request IDs, or attachment IDs reach Hermes, logs, approvals, or user copy.

If any item is missing or stale, live document extraction remains disabled.
