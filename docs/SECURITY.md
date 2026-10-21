# Security

## Assets

1. The signer's private key (on the USB token) and their **intent** to sign.
2. Documents being signed.
3. API keys and the server's token-signing key.
4. Billing/usage records.

## Threats and controls

| Threat | Control |
|---|---|
| A malicious website makes the agent sign without the user knowing | Every signing transaction opens a consent window owned by the agent showing website, organisation, file reference, documents and certificate; PKCS#11 tokens additionally require the PIN; tokens are bound to the origin they were issued for. |
| A malicious website uses the agent at all (list certificates, probe) | Token mode: requests need a token signed by your server for that exact origin. Allow-list mode: only configured origins. CORS headers are only returned for permitted origins. |
| DNS rebinding (attacker domain resolving to 127.0.0.1) | The agent rejects any `Host` header other than `127.0.0.1`, `localhost` or `[::1]` with its port. |
| Remote access to the agent | Bound to the loopback interface only. |
| Token replay | Each token has a unique id, expires (default 5 minutes) and allows at most `maxDocuments` signatures on the agent; failed attempts are refunded so the user can retry after a wrong PIN. |
| Forged tokens | Ed25519 signatures; agents only accept keys from the configured server (cached) or pasted keys. |
| API key theft | Keys are random 256-bit secrets, stored as SHA-256 hashes, shown once, revocable; the token endpoint is not reachable by browsers (no CORS). |
| Substituting another document or signer during server-prepared signing | The server accepts a signature only if its message-digest equals the prepared digest and the signer certificate equals the one declared at preparation; a session can be completed once. |
| Tampering with a signed PDF | Verification recomputes the digest over the signed byte range and checks the signature, timestamp, certificate validity, chain and (optionally) revocation; later changes are reported. |
| Admin console brute force | bcrypt (cost 12), lock-out after 5 failures for 15 minutes, sessions invalidated on password change, forced password change for initial accounts. |
| XSS in the consoles | Strict Content-Security-Policy (`script-src 'self'`), no inline scripts, all data inserted with `textContent`. |
| Click-jacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'`. |
| Over-large requests | Request size limits on agent and server. |
| Spoofed client IPs in logs | `X-Forwarded-*` headers are honoured only from private/loopback proxies. |

## Recommendations for operators

* Serve the Signer Server and your applications over HTTPS only.
* Keep `consent.mode=dialog` on user PCs (`auto` is for kiosks and automated tests only).
* Configure `security.allowedOrigins` on the agent as a second line of defence.
* Sign the agent MSI with a code-signing certificate and distribute it from a trusted share.
* Restrict access to `data/keys/` and back it up.
* Install CCA root certificates as trust anchors so verification reports `VALID` instead of `VALID_UNTRUSTED`.
* Commission a security audit by a CERT-In empanelled auditor before production use in government.

## What the agent stores

* `%LOCALAPPDATA%\Signer\logs\agent.log` – technical log (no document content, no PINs).
* `%LOCALAPPDATA%\Signer\logs\audit-YYYY-MM.log` – one JSON line per signing attempt: time, website,
  transaction, certificate name, number of documents, result.
* `%LOCALAPPDATA%\Signer\server-keys.json` – cached public keys of the server.

PINs are held only in memory for the duration of the token login and cleared afterwards.

## Reporting vulnerabilities

Report security issues privately to the maintainer at k.rakeshkumar369@gmail.com.
