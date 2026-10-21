# Error codes

All components (agent, server, SDK) return errors as `{"ok": false, "error": {"code", "message"}}` and the
SDK throws `SignerError` with `code`. Branch on the code, show the message to users.

| Code | HTTP | Meaning / what to do |
|---|---|---|
| `BAD_REQUEST` | 400 | Invalid input (message explains which field) |
| `UNAUTHORIZED` | 401 | Missing/invalid API key, token or admin session |
| `TOKEN_INVALID` | 401 | Token malformed, signed by an unknown key, or for another audience |
| `TOKEN_EXPIRED` | 401 | Request a new token (default lifetime 5 minutes) |
| `TOKEN_REPLAYED` | 401 | Token already used for its allowed number of documents; request a new one per transaction |
| `FORBIDDEN` | 403 | Operation not permitted by the token, tenant suspended, or role insufficient |
| `ORIGIN_NOT_ALLOWED` | 403 | The page origin is not registered for the tenant / allowed on the agent |
| `LICENSE_INVALID` | 403 | Server licence missing a feature, expired, or tenant limit reached |
| `NOT_FOUND` | 404 | Unknown transaction, session, tenant... |
| `CONFLICT` | 409 | Already completed / already exists |
| `BUSY` | 409 | Another signing request is waiting for confirmation on this PC |
| `PAYLOAD_TOO_LARGE` | 413 | Document larger than the configured limit (default 25 MB) |
| `PDF_INVALID` | 422 | Not a PDF or damaged |
| `PDF_PASSWORD_REQUIRED` | 422 | Encrypted PDF: pass `pdfPassword` |
| `PDF_SIGNING_NOT_ALLOWED` | 422 | Document certified with "no changes allowed" |
| `SIGNATURE_TOO_LARGE` | 422 | Signature does not fit the reserved space (very long chains) |
| `TOKEN_NOT_PRESENT` | 424 | No USB token / certificate found: insert the token |
| `CERTIFICATE_NOT_FOUND` | 424 | No certificate matches the requested signer |
| `CERTIFICATE_EXPIRED` | 424 | Selected certificate expired or not yet valid |
| `PIN_INCORRECT` | 424 | Wrong PIN (the agent lets the user retry up to 3 times) |
| `PIN_LOCKED` | 424 | PIN blocked: unblock with the token vendor's utility |
| `USER_CANCELLED` | 424 | The user clicked Cancel or the window timed out |
| `QUOTA_EXCEEDED` | 429 | Tenant monthly quota or licence limit reached |
| `RATE_LIMITED` | 429 | Too many failed logins |
| `TIMESTAMP_FAILED` | 502 | Timestamp authority unreachable/refused, or none configured |
| `REVOCATION_FETCH_FAILED` | 502 | OCSP/CRL could not be fetched for LTV |
| `SIGNING_FAILED` | 500 | Token or driver error (message has details) |
| `INTERNAL_ERROR` | 500 | Unexpected error (see logs) |

SDK-only codes: `AGENT_UNREACHABLE` (agent not installed/running or blocked by the browser), `TIMEOUT`,
`BAD_RESPONSE`.
