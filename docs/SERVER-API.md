# Signer Server API

Base URL: your server, e.g. `https://signer.example.gov.in`. All bodies are JSON (`Content-Type:
application/json`); binary data (PDFs, signatures, certificates) is Base64. Errors use the common shape
`{"ok": false, "error": {"code": "...", "message": "..."}}` ([error codes](ERROR-CODES.md)).

## Authentication

| Caller | Header | Used for |
|---|---|---|
| Your application's **back end** | `X-API-Key: sk_...` | Issuing tokens and any tenant endpoint |
| The **browser** (with a token your back end obtained) | `Authorization: Bearer <transaction token>` | prepare / complete / verify / transaction status for that transaction |
| Admin console | `Authorization: Bearer <admin session>` | `/api/admin/**` |

Browser calls are allowed by CORS only from origins registered for an active tenant. The token
endpoint is **never** exposed to browsers (no CORS): API keys must stay on the server.

---

## Public endpoints

### GET /.well-known/signer-keys

Ed25519 public keys used to verify transaction tokens (fetched and cached by agents).

```jsonc
{ "keys": [ { "kid": "zDMvqc2sKRA-PDse", "kty": "OKP", "crv": "Ed25519", "x": "q2...", "use": "sig", "alg": "EdDSA" } ] }
```

### GET /api/v1/health

`{"ok": true, "time": "...", "timestampAuthority": true}`. Spring Boot health is also available at
`/actuator/health`.

---

## Transaction tokens

### POST /api/v1/tokens  (API key)

Issues a single-use token. Each call creates one billable **transaction**.

```jsonc
{
  "origin": "https://eoffice.example.gov.in",   // required: page origin that will call the agent
  "operations": ["certificates", "sign"],        // default both
  "maxDocuments": 1,                             // documents that may be signed (batch), default 1
  "ttlSeconds": 300,                             // 30 .. signer.token.max-ttl-seconds
  "reference": "GAD01/123/2026"                  // free text, shown to the user and in reports
}
```

```jsonc
{ "ok": true, "token": "eyJhbGciOiJFZERTQSIs...", "txn": "05228604-c734-...", "expiresAt": "2026-10-21T11:45:07Z",
  "operations": ["certificates", "sign"], "maxDocuments": 1 }
```

Rejected with `ORIGIN_NOT_ALLOWED` (origin not registered for the tenant), `QUOTA_EXCEEDED` (tenant
monthly quota or server licence limit), `FORBIDDEN` (tenant suspended or expired), `UNAUTHORIZED`
(unknown/revoked key).

### GET /api/v1/transactions/{txn}  (API key or that transaction's token)

```jsonc
{ "ok": true, "transaction": { "id": "...", "tenantId": "...", "origin": "...", "status": "COMPLETED", "documents": 1,
  "signerName": "RAVI KUMAR", "signerSerial": "1A2B3C", "reference": "GAD01/123/2026", "issuedAt": "...", "completedAt": "..." } }
```

### POST /api/v1/transactions/{txn}/complete  (API key or that transaction's token)

Records the outcome of a desktop-signed transaction (the browser SDK does this automatically when
`serverUrl` is configured; server-prepared signing records it itself).

```jsonc
{ "status": "COMPLETED", "documents": 1, "signerName": "RAVI KUMAR", "signerSerial": "1A2B3C",
  "documentHash": "sha256-hex", "error": null }
```

---

## Server-prepared signing

### POST /api/v1/pdf/prepare  (API key, or token with `sign`)

```jsonc
{
  "pdf": "JVBERi0...",
  "name": "note-file.pdf",
  "certificate": "MIIF...",        // signer certificate from the agent (name in the box; enforced at completion)
  "options": { "page": "last", "x": 360, "y": 40, "width": 200, "height": 70,
               "reason": "Approved", "location": "Amaravati", "timestamp": true, "subFilter": "ETSI.CAdES.detached" }
}
```

Options are the same as for the agent ([table](AGENT-API.md#signature-options)) except `fontPath`.
`timestamp` uses the server's TSA (`signer.tsa.url`); `ltv` makes the server fetch OCSP/CRL data.

```jsonc
{ "ok": true, "sessionId": "f0d1...", "digest": "q1w2e3...=", "digestAlgorithm": "SHA-256", "format": "pades",
  "expiresAt": "2026-10-21T12:10:00Z" }
```

Pass `digest` and `format` to the agent's `/api/v1/sign/hash`.

### POST /api/v1/pdf/complete  (API key, or token with `sign`)

```jsonc
{ "sessionId": "f0d1...", "signature": "MIAGCSqGSIb3DQEHAqCA..." }
```

The server checks that the CMS message-digest equals the prepared digest and that the signer certificate
is the one given at preparation, embeds the signature (adding timestamp / LTV if requested), verifies the
result and deletes its copy of the document.

```jsonc
{ "ok": true, "pdf": "JVBERi0...", "size": 51022, "sha256": "...", "signer": { ...certificate info... },
  "timestamped": true, "ltv": false }
```

A session can be completed once (`CONFLICT` afterwards) and expires after
`signer.sessions.ttl-minutes` (default 30).

### POST /api/v1/pdf/verify  (API key or any valid token)

```jsonc
{ "pdf": "JVBERi0...", "password": null }
```

```jsonc
{ "ok": true, "report": {
  "signatureCount": 2, "allValid": true, "hasDss": false,
  "signatures": [ {
    "fieldName": "Signature1", "status": "VALID", "signerName": "RAVI KUMAR", "certificate": {...},
    "chain": ["RAVI KUMAR", "e-Mudhra Sub CA ...", "CCA India 2022"],
    "signingTime": "...", "timestamped": true, "timestampTime": "...", "timestampAuthority": "...",
    "reason": "Approved", "location": "Amaravati", "subFilter": "adbe.pkcs7.detached",
    "integrityValid": true, "coversWholeDocument": false, "certificateValidAtSigningTime": true,
    "chainTrusted": true, "revocation": "GOOD", "certificationLevel": 0, "notes": ["..."] } ] } }
```

| `status` | Meaning |
|---|---|
| `VALID` | Document unchanged since signing, certificate valid at signing time, chain ends at a configured trusted root (CCA India), revocation not found revoked |
| `VALID_UNTRUSTED` | Document intact, but trust could not be fully established (no trust anchors configured, unknown root, revocation unknown) |
| `INVALID` | Document altered after signing, signature broken, or certificate revoked |

Place the CCA India root certificates (`.cer`) in `signer.verification.trust-anchors-dir`
(default `data/trust`) so that Indian DSCs verify as `VALID`. Set `signer.verification.check-revocation=true`
to query OCSP/CRL during verification.

---

## Admin API (used by the console)

All under `/api/admin`, authenticated with the session token from `POST /api/admin/login`.
VIEWER users can read; ADMIN users can also change data.

| Method | Path | Purpose |
|---|---|---|
| POST | `/login` | `{username, password}` → session token (`mustChangePassword` on first login) |
| POST | `/password` | Change own password |
| GET | `/me` | Current user |
| GET | `/overview` | Dashboard figures, licence, agent configuration snippet |
| GET, POST | `/tenants` | List / create tenants |
| GET, PUT | `/tenants/{id}` | Tenant details incl. API keys / update |
| POST | `/tenants/{id}/status` | `{status}` = `ACTIVE` or `SUSPENDED` |
| POST | `/tenants/{id}/keys` | Create API key (secret returned once) |
| DELETE | `/keys/{id}` | Revoke API key |
| GET | `/transactions?tenantId&status&from&to&q&page&size` | Search transactions |
| GET | `/usage?month=YYYY-MM`, `/usage.csv?month=` | Monthly usage per tenant (billing) |
| GET | `/audit?page&size` | Audit log |
| GET, POST | `/users`; POST `/users/{id}/password`; DELETE `/users/{id}` | Console users |
| GET, POST | `/license` | Licence status / install licence text |

## Server configuration

See [`application.yml`](../signer-server/src/main/resources/application.yml). Every key can be set as an
environment variable (`signer.public-url` → `SIGNER_PUBLIC_URL`, `spring.datasource.url` →
`SPRING_DATASOURCE_URL`, ...).
