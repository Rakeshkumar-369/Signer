# Signer Agent API

The agent listens on **`http://127.0.0.1:1645`** (configurable with `agent.port`). It accepts requests
only on the loopback interface, only with a `Host` header of `127.0.0.1`, `localhost` or `[::1]`
(DNS-rebinding protection), and answers CORS / Private Network Access pre-flight requests for permitted
origins.

Most applications use the [browser SDK](../sdk/js/signer.js) instead of calling these endpoints directly.

## Authentication

In the default **token mode** every request except `status` must carry a transaction token issued by
the Signer Server for the calling page's origin:

```
Authorization: Bearer <token>        (or header X-Signer-Token, or JSON field "token")
```

In **allow-list mode** (`security.mode=allowlist`) no token is needed, but only origins listed in
`security.allowedOrigins` are served.

## Responses

Success: `{"ok": true, ...}` with HTTP 200. Failure: HTTP 4xx/5xx with

```jsonc
{ "ok": false, "error": { "code": "PIN_INCORRECT", "message": "Incorrect token PIN" } }
```

See [ERROR-CODES.md](ERROR-CODES.md).

---

## GET /api/v1/status

No authentication. Used to detect whether the agent is installed and a token is plugged in.

```jsonc
{
  "ok": true, "product": "Signer Agent", "version": "1.0.0", "mode": "token",
  "timestampAuthority": false, "legacyApi": true, "maxDocumentBytes": 26214400, "maxBatch": 50,
  "tokens": [ { "name": "pkcs11:eps2003csp11.dll#0", "certificates": 1, "pinPromptByAgent": true } ],
  "tokenPresent": true
}
```

## GET /

Human-readable diagnostics page (version, token connections, certificates, configuration files). Useful
for help-desk staff: ask the user to open <http://127.0.0.1:1645/>.

---

## POST /api/v1/certificates

Token operation: `certificates`.

Request (all fields optional):

```jsonc
{ "certificate": { "commonName": "RAVI", "issuer": "e-Mudhra", "serialNumber": "1A2B", "certificateClass": "Class 3" } }
```

Response:

```jsonc
{
  "ok": true, "txn": "8a85...",
  "certificates": [{
    "id": "4F1C...E2",                 // SHA-1 thumbprint, use it to pick this certificate later
    "commonName": "RAVI KUMAR",
    "subject": "CN=RAVI KUMAR,OU=...,O=Government of Andhra Pradesh,C=IN",
    "organization": "Government of Andhra Pradesh", "organizationalUnit": "GAD", "title": "Deputy Secretary",
    "email": null, "serialNumber": "1A2B3C", "issuer": "CN=e-Mudhra Sub CA ...", "issuerCommonName": "e-Mudhra Sub CA ...",
    "notBefore": "2025-04-01T00:00:00Z", "notAfter": "2027-03-31T23:59:59Z", "currentlyValid": true,
    "keyUsage": ["digitalSignature", "nonRepudiation"], "keyAlgorithm": "RSA", "keySize": 2048,
    "certificateClass": "Class 3", "policies": ["2.16.356.100.2.3"],
    "source": "pkcs11:eps2003csp11.dll#0",
    "certificate": "MIIF..."           // Base64 DER
  }]
}
```

### Certificate filter

Used by `certificates`, `sign/pdf` and `sign/hash` (`"certificate": {...}`). All given criteria must
match. Text fields are case-insensitive "contains" matches.

| Field | Meaning |
|---|---|
| `id` | Exact SHA-1 thumbprint (from the list above) |
| `commonName`, `issuer`, `organization`, `organizationalUnit`, `title`, `email`, `certificateClass` | Contains |
| `serialNumber` | Exact, hexadecimal, leading zeros ignored |
| `validOnly` | Default `true` |
| `signingOnly` | Default `true` (key usage digitalSignature / nonRepudiation) |

If several certificates match, the user chooses in the consent window.

---

## POST /api/v1/sign/pdf

Token operation: `sign`. Signs one or more PDFs on the desktop.

Single document:

```jsonc
{
  "name": "note-file.pdf",
  "pdf": "JVBERi0xLjc...",
  "options": { "page": "last", "x": 360, "y": 40, "width": 200, "height": 70, "reason": "Approved", "location": "Amaravati" },
  "certificate": { "commonName": "RAVI KUMAR" }
}
```

Batch (one PIN entry):

```jsonc
{
  "options": { "reason": "Approved" },
  "documents": [
    { "name": "a.pdf", "data": "JVBER..." },
    { "name": "b.pdf", "data": "JVBER...", "options": { "page": "1", "x": 40 } }
  ]
}
```

Response:

```jsonc
{
  "ok": true, "txn": "8a85...", "signedAt": "2026-10-21T11:40:07Z",
  "certificate": { ...certificate info... },
  "chain": ["RAVI KUMAR", "e-Mudhra Sub CA for Class 3 Individual 2022", "e-Mudhra CA 2022", "CCA India 2022"],
  "documents": [ { "name": "note-file.pdf", "size": 48211, "sha256": "9c1e...", "data": "JVBER..." } ]
}
```

### Signature options

| Option | Default | Description |
|---|---|---|
| `visible` | `true` | Draw a signature box; `false` creates an invisible signature |
| `page` | `"last"` | `1`, `2`, ..., `"first"`, `"last"`, or negative numbers counted from the end (`-1` = last) |
| `x`, `y`, `width`, `height` | `360, 40, 200, 70` | Box position and size in points (1/72 inch) on the page as displayed |
| `origin` | `"bottom-left"` | `"top-left"` measures `y` from the top edge (screen style) |
| `reason`, `location`, `contactInfo` | – | Stored in the signature; reason and location are also printed in the box |
| `signerName` | certificate CN | Name printed in the box |
| `dateFormat` | `dd-MMM-yyyy hh:mm a` | Java pattern; .NET `tt` is accepted for AM/PM |
| `timeZone` | `Asia/Kolkata` | Time zone used for the printed date and the signature time |
| `greenTick` | `true` | Semi-transparent green check mark behind the text |
| `border` | `false` | Thin border around the box |
| `customText` | – | Extra lines (`\n` separated), e.g. file number |
| `showReason`, `showLocation` | `true` | Print these lines |
| `fontSize` | auto | Fixed font size; by default text is fitted into the box |
| `imageBase64` | – | PNG/JPEG drawn on the left (scanned signature, seal) |
| `fontPath` | – | TrueType font file on the PC, embedded for non-Latin names (agent only) |
| `fieldName` | auto | Name of the signature field |
| `subFilter` | `adbe.pkcs7.detached` | Or `ETSI.CAdES.detached` (PAdES) |
| `certificationLevel` | – | `1` no changes, `2` form filling + signing, `3` + annotations (first signature only) |
| `timestamp` | `false` | Add an RFC 3161 timestamp (needs `tsa.url` on the agent) |
| `ltv` | `false` | Embed chain + OCSP/CRL (needs internet access to the CA) |
| `pdfPassword` | – | Password of an encrypted PDF |

---

## POST /api/v1/sign/hash

Token operation: `sign`. Signs SHA-256 digests prepared elsewhere (by the Signer Server or your own
server code).

```jsonc
{
  "digest": "q1w2e3...=",                       // or "hashes": [ {"id": "doc1", "digest": "..."} ]
  "format": "cms",                              // cms | pades | raw
  "timestamp": false,
  "certificate": { "id": "4F1C...E2" },
  "documentNames": ["note-file.pdf"]            // shown in the consent window
}
```

| `format` | Returns |
|---|---|
| `cms` | Detached CMS/PKCS#7 SignedData (`adbe.pkcs7.detached`) whose message-digest is your digest |
| `pades` | Same, PAdES profile (signing-certificate-v2, no signing-time) for `ETSI.CAdES.detached` |
| `raw` | Bare PKCS#1 v1.5 (RSA) or ECDSA signature value over the digest, for integrators assembling XML-DSig or their own CMS |

Response:

```jsonc
{ "ok": true, "txn": "8a85...", "format": "cms", "certificate": {...}, "chain": [...],
  "signatures": [ { "id": "hash-0", "signature": "MIAGCSqGSIb3DQEHAqCAMIACAQEx..." } ] }
```

---

## POST / — APTS / PKI Network compatible command API

Enabled by `legacy.enabled=true` (default). Accepts the request format of the "Browser Signing Solution"
so existing integrations only need a new token source and URL. The token goes in `request.token`.

### pkiNetworkCertExt

```jsonc
{ "request": { "command": "pkiNetworkCertExt", "ts": "2026-01-02T13:54:59.245Z", "txn": "T1", "token": "<token>",
               "certificate": { "attribute": ["AP=1", "CN=", "SN=", "TC=SG"] }, "file": { "attribute": [] } } }
```

Attributes with a value filter the certificates (`CN`, `SN`, `O`, `OU`, `T`, `E`, `CA`=issuer); empty
attributes and vendor flags (`AP`, `TC`) are ignored. Response:

```jsonc
{ "ok": true, "response": { "command": "pkiNetworkCertExt", "txn": "T1", "status": "success", "code": "0",
  "message": "1 certificate(s) found",
  "certificates": [ { "CN": "RAVI KUMAR", "O": "...", "OU": "...", "T": "...", "E": "", "SN": "1A2B3C", "CA": "e-Mudhra Sub CA ...",
                      "validFrom": "...", "validTo": "...", "thumbprint": "4F1C...", "class": "Class 3", "certificate": "MIIF..." } ] } }
```

### pkinetworksign

```jsonc
{ "request": { "command": "pkinetworksign", "txn": "T2", "token": "<token>",
  "certificate": { "attribute": ["CN=RAVI KUMAR", "TC=SG", "AP=1"] },
  "file": { "attribute": ["type=pdf"] },
  "pdf": { "cood": "10,10", "page": "1", "size": "200,100", "isgreentick": "yes", "location": "Amaravati",
           "enableltv": "no", "enabletimestamp": "yes", "reason": "Sign by RAVI KUMAR",
           "dateformat": "dd-MMM-yyyy hh:mm tt", "customtext": "" },
  "data": "<BASE64_PDF>" } }
```

Response: `response.status` = `success` and `response.data` = signed PDF (Base64). Failures return
`response.status` = `failed` with `response.code` set to an [error code](ERROR-CODES.md). If a timestamp
is requested but the agent has no TSA configured, the document is signed without one and a message is
added to `response.warnings`.

---

## Configuration reference

Run `"Signer Agent.exe" --print-defaults` (or see
[agent-defaults.properties](../signer-agent/src/main/resources/agent-defaults.properties)) for every
setting with comments. Configuration files are read in this order, later ones winning:

1. built-in defaults
2. `agent.properties` in the installation folder (deployed by IT)
3. `%APPDATA%\Signer\agent.properties` (Windows) or `~/.config/signer/agent.properties` (per user)
4. JVM system properties `-Dsigner.<key>=<value>`

Logs: `%LOCALAPPDATA%\Signer\logs\agent.log`; signing audit trail: `audit-YYYY-MM.log` in the same folder.
