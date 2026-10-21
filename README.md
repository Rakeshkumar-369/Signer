# Signer

**Digital signature platform for USB-token (DSC) signing from web applications** such as e-Office, HRMS,
file-tracking and procurement portals. A web page asks the **Signer Agent** on the user's computer to
sign; the agent talks to the USB token (ePass2003, ProxKey, mToken, eToken, ...), asks the user to confirm
and enter the PIN, and returns a legally valid PDF signature. The **Signer Server** licenses and meters
every signing transaction, prepares documents so that only a 32-byte hash goes to the token, verifies
signatures and gives you an admin console for customers, API keys and usage billing.

```
 Browser (e-Office / any web app)                 Signer Server (your VM / cloud)
   │  signer.js SDK                                  ├─ tenants, API keys, quotas, licence
   │                                                 ├─ single-use transaction tokens (Ed25519)
   │  ① token  ◄──── your back end ── API key ─────► ├─ PDF prepare / complete (hash signing)
   │                                                 ├─ timestamp (RFC 3161), LTV, verification
   │  ② sign   ──► http://127.0.0.1:1645             └─ admin console, usage & billing reports
   ▼
 Signer Agent (Windows MSI / Linux .deb, runs in the tray)
   ├─ verifies the token offline (origin-bound, single use)
   ├─ consent window + token PIN
   └─ PKCS#11 driver / Windows certificate store ──► USB token (private key never leaves it)
```

## Components

| Folder | What it is | Technology |
|---|---|---|
| [`signer-core`](signer-core) | PDF signing engine: visible signatures, PKCS#7 / PAdES, two-phase (hash) signing, timestamps, LTV, verification, transaction tokens, licence files | Java 21, Apache PDFBox, Bouncy Castle |
| [`signer-agent`](signer-agent) | Desktop agent installed on each PC (replaces the vendor "Browser Signing Solution" EXE) | Java 21 + bundled runtime, PKCS#11 / Windows CNG, Swing |
| [`signer-server`](signer-server) | Licensing, token issuing, server-side signing, verification, admin console, demo | Spring Boot 4, H2 / PostgreSQL / MariaDB / MySQL |
| [`sdk/js`](sdk/js) | Browser SDK (`signer.js` + TypeScript typings) | Plain JavaScript (no dependencies) |
| [`sdk/node`](sdk/node) | Back-end client for Node.js applications | Node 18+ |
| [`examples/node-integration`](examples/node-integration) | Minimal application showing a complete integration | Node 18+ |
| [`packaging`](packaging) | MSI / .deb builds, roll-out scripts, systemd, nginx | jpackage, WiX, PowerShell |

## Two ways to sign

1. **Server-prepared (recommended)** – the server adds the signature field and appearance and keeps the
   PDF; the agent signs only the SHA-256 digest; the server embeds the signature, optional trusted
   timestamp and LTV data. Large files never travel to the desktop.
2. **Desktop** – the whole PDF is sent to the agent, which returns the signed PDF (same model as the
   APTS / PKI Network "Browser Signing Solution"). The agent also accepts that product's
   `pkiNetworkCertExt` / `pkinetworksign` command format, so existing integrations can migrate with
   minimal changes (see the [integration guide](docs/INTEGRATION-GUIDE.md#migrating-from-the-apts-browser-signing-solution)).

## Quick start (developer machine)

Requirements: JDK 21, Maven 3.9.

```bash
mvn -B verify                                   # build + 40 automated tests
java -jar signer-server/target/signer-server.jar  # http://localhost:8080 (admin password printed in the log)
java -jar signer-agent/target/signer-agent.jar    # the agent (tray icon); or install the MSI
```

Open <http://localhost:8080/demo/> to sign a sample document with your USB token, and
<http://localhost:8080/admin/> for the admin console. For a first test the agent needs to know the server:
create `%APPDATA%\Signer\agent.properties` (Windows) or `~/.config/signer/agent.properties` with

```properties
security.serverUrl=http://localhost:8080
```

## Documentation

| Document | For |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | How the pieces fit, signing flows, trust model |
| [Integration guide](docs/INTEGRATION-GUIDE.md) | Developers adding DSC signing to an application; migration from the APTS utility |
| [Agent API](docs/AGENT-API.md) | Local HTTP API of the desktop agent |
| [Server API](docs/SERVER-API.md) | Token, signing, verification and admin endpoints |
| [Deployment](docs/DEPLOYMENT.md) | Installing the server and rolling out the agent; Chrome/Edge settings |
| [Security](docs/SECURITY.md) | Threat model and controls |
| [Error codes](docs/ERROR-CODES.md) | Stable error codes returned by every component |
| [Business & compliance](docs/BUSINESS-AND-COMPLIANCE.md) | CCA / IT Act position, licensing model, go-to-market checklist |

## Building installers

* Windows MSI: `packaging\agent\windows\build-msi.ps1` (needs WiX 3.14) or run the **Release installers**
  GitHub workflow, which builds the MSI on a Windows runner and the .deb on Linux.
* Linux .deb: `packaging/agent/linux/build-deb.sh`
* Server: `signer-server/target/signer-server.jar`, `Dockerfile`, or `docker compose up -d`.

## Licence

Proprietary. See [LICENSE](LICENSE) and [third-party notices](THIRD-PARTY-NOTICES.md).
