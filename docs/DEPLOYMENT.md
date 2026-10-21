# Deployment

## 1. Signer Server

### Sizing

A single VM with 2 vCPU / 4 GB RAM handles thousands of signatures per hour (server work per signature is a
few milliseconds; the PIN entry on the desktop dominates). Use PostgreSQL or MariaDB/MySQL for production;
the embedded H2 database is fine for pilots.

### Option A – Java on a VM (same model as your current set-up)

```bash
sudo apt install openjdk-21-jre-headless postgresql
sudo -u postgres psql -c "CREATE USER signer PASSWORD 'change-me'" -c "CREATE DATABASE signer OWNER signer"
sudo useradd --system --home /opt/signer --shell /usr/sbin/nologin signer
sudo mkdir -p /opt/signer && sudo cp signer-server.jar /opt/signer/ && sudo chown -R signer /opt/signer
sudo cp packaging/server/signer.env.example /etc/signer.env && sudo chmod 600 /etc/signer.env   # edit it
sudo cp packaging/server/signer-server.service /etc/systemd/system/
sudo systemctl enable --now signer-server
sudo journalctl -u signer-server | grep -A4 "Initial administrator"     # first admin password
```

Put nginx in front for HTTPS: [`packaging/server/nginx-signer.conf`](../packaging/server/nginx-signer.conf).

### Option B – Docker

```bash
cp .env.example .env      # set DB_PASSWORD, PUBLIC_URL, ...
docker compose up -d
docker compose logs signer | grep -A4 "Initial administrator"
```

### Settings that matter

| Setting (env var) | Purpose |
|---|---|
| `SIGNER_PUBLIC_URL` | External HTTPS URL; agents download keys from `<url>/.well-known/signer-keys` |
| `SPRING_DATASOURCE_URL/USERNAME/PASSWORD` | `jdbc:postgresql://host:5432/signer` or `jdbc:mariadb://host:3306/signer` (works for MySQL 8 too) |
| `SIGNER_DATA_DIR` | Holds the **token signing key** (`keys/token-signing.pem`), trust anchors and the H2 database. Back it up and protect it. |
| `SIGNER_TSA_URL` (+ `_USERNAME`, `_PASSWORD`) | RFC 3161 timestamp authority (most licensed CAs offer one to customers) |
| `SIGNER_VERIFICATION_TRUST_ANCHORS_DIR` | Folder with CCA India root certificates for verification |
| `SIGNER_DEMO_ENABLED` | `false` in production |
| `SIGNER_ADMIN_INITIAL_PASSWORD` | Optional first admin password (must be changed at first login) |

### Trust anchors (CCA India roots)

Download the current "CCA India" root certificates from the Controller of Certifying Authorities web site
(cca.gov.in) and copy the `.cer` files to `data/trust/` (server) and, if you want the agent to build complete
chains offline, to `trust\` in the agent installation folder.

### Backups

* Database (tenants, keys, transactions = your billing records).
* `data/keys/token-signing.pem` – losing it only means agents must download the new public key; leaking it
  allows forging tokens, so keep the file readable by the service account only.

### Key rotation

1. Move the old key file away; restart: a new key is generated.
2. Put the old public key into `SIGNER_TOKEN_ADDITIONAL_PUBLIC_KEYS` (`kid=base64url`) for one day so tokens
   issued just before the switch still verify. Agents refresh keys automatically.

## 2. Signer Agent on user computers

### Build or download the installer

* Windows: run the **Release installers** GitHub workflow (or `packaging\agent\windows\build-msi.ps1` on a
  Windows build machine with WiX 3.14). Sign the MSI with your organisation's code-signing certificate so
  Windows SmartScreen and antivirus software trust it.
* Linux (Ubuntu/BOSS): `packaging/agent/linux/build-deb.sh`.

The installer contains its own Java runtime; nothing else needs to be installed.

### Silent roll-out (SCCM / Intune / GPO)

```powershell
powershell -ExecutionPolicy Bypass -File deploy-agent.ps1 -Msi "\\server\share\Signer Agent-1.0.0.msi" `
    -ServerUrl https://signer.example.gov.in -AllowedOrigins https://eoffice.ap.gov.in
```

The script installs the MSI quietly, writes `agent.properties` into the installation folder and registers
the agent to start at every user's logon.

### Token drivers

Install the token vendor's driver as today (ePass2003, ProxKey/Watchdata, mToken/CryptoID, SafeNet eToken,
Gemalto IDPrime, TrustKey, ...). The agent finds certificates in two ways:

* **Windows certificate store** – works for every token whose driver installs a smart-card minidriver/CSP;
  the driver shows its own PIN window.
* **PKCS#11** – the agent loads the vendor library (list in `pkcs11.libraries`) and asks for the PIN in its
  own window. Add your token's DLL to that list if it is not detected.

### Browser settings

* Pages served over **HTTPS may call `http://127.0.0.1`**: Chrome, Edge and Firefox treat the loopback
  address as a secure context, so no certificate is needed on the agent.
* Recent Chrome/Edge versions ask the user once per site for permission to access apps on the local
  device ("Local Network Access"). Administrators can pre-approve your application origins through
  enterprise policy (in current versions: `LocalNetworkAccessAllowedForUrls`; check the Chrome/Edge
  enterprise policy list for your browser version).
* The agent already answers the browser's Private/Local Network Access pre-flight requests.

### Help-desk checklist

1. Open <http://127.0.0.1:1645/> on the user's PC: shows agent version, detected tokens and certificates.
2. No certificates → token not inserted, driver missing, or library not in `pkcs11.libraries`.
3. Logs: `%LOCALAPPDATA%\Signer\logs\agent.log`.
4. `ORIGIN_NOT_ALLOWED` → the application's origin is not registered for the tenant (server) or not in
   `security.allowedOrigins` (agent).
5. `TOKEN_INVALID` with "unknown key" → the agent cannot reach `security.serverUrl`; check the URL or paste
   the `security.trustedKeys=` line from **Admin → Agent setup** into `agent.properties`.

## 3. Licences for your customers (vendor tasks)

```bash
# once: create your vendor licensing key pair (keep the private key offline)
java -jar signer-server.jar license generate-keys --out vendor-keys
#   -> paste the public key into signer-server/src/main/resources/license/vendor-public-key.txt and rebuild

# per customer installation
java -jar signer-server.jar license issue --key vendor-keys/vendor-private.pem \
     --licensee "Department of X, Government of Andhra Pradesh" --expires 2027-12-31 \
     --tenants 25 --monthly 500000 --edition enterprise --out customer.lic
```

The customer installs the licence under **Admin → Licence** (or copies it to `data/license.lic`). Without
a licence the server runs in evaluation mode (3 tenants, 1,000 transactions per month).
