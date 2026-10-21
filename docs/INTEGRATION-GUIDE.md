# Integration guide

This guide is for developers of a web application (e-Office, HRMS, procurement, file tracking, ...) that
needs USB-token digital signatures.

## What you build

1. **One back-end endpoint** that exchanges your secret API key for a short-lived transaction token.
2. **A few lines of browser code** using `signer.js`.

That's all. The agent, the consent window, PIN entry, token drivers, PDF signature format, timestamps
and verification are handled by Signer.

## Step 1 – Register your application

In the admin console (**Tenants → New tenant**):

* **Code / name** – your organisation or application.
* **Allowed web origins** – the exact origins of the pages that will sign, e.g.
  `https://eoffice.ap.gov.in` (scheme + host + port, no path). Intranet `http://10.x.x.x:8080` origins are
  allowed too.
* **Create API key** – copy the `sk_...` value into your back end's secret configuration.

## Step 2 – Token endpoint in your back end

Check your own session/authorisation first (is this user allowed to sign this file?), then:

```bash
curl -X POST https://signer.example.gov.in/api/v1/tokens \
  -H "X-API-Key: $SIGNER_API_KEY" -H "Content-Type: application/json" \
  -d '{"origin":"https://eoffice.ap.gov.in","reference":"GAD01/123/2026","maxDocuments":1}'
```

### Java (any framework)

```java
HttpClient http = HttpClient.newHttpClient();
String body = """
    {"origin":"https://eoffice.ap.gov.in","reference":"%s","maxDocuments":1}""".formatted(fileNo);
HttpRequest req = HttpRequest.newBuilder(URI.create(signerUrl + "/api/v1/tokens"))
        .header("X-API-Key", apiKey).header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body)).build();
String json = http.send(req, HttpResponse.BodyHandlers.ofString()).body();   // {"ok":true,"token":"...","txn":"..."}
```

### C# / .NET

```csharp
using var http = new HttpClient();
http.DefaultRequestHeaders.Add("X-API-Key", apiKey);
var resp = await http.PostAsJsonAsync($"{signerUrl}/api/v1/tokens",
    new { origin = "https://eoffice.ap.gov.in", reference = fileNo, maxDocuments = 1 });
var token = (await resp.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString();
```

### PHP

```php
$ch = curl_init("$signerUrl/api/v1/tokens");
curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true,
  CURLOPT_HTTPHEADER => ["X-API-Key: $apiKey", "Content-Type: application/json"],
  CURLOPT_POSTFIELDS => json_encode(["origin" => "https://eoffice.ap.gov.in", "reference" => $fileNo])]);
$token = json_decode(curl_exec($ch), true)["token"];
```

### Node.js

```js
const { SignerServerClient } = require('./sdk/node/signer-server-client');
const signer = new SignerServerClient({ serverUrl: process.env.SIGNER_URL, apiKey: process.env.SIGNER_API_KEY });
const { token } = await signer.issueToken({ origin: 'https://eoffice.ap.gov.in', reference: fileNo });
```

Return only the `token` to the browser. A complete runnable example is in
[`examples/node-integration`](../examples/node-integration).

## Step 3 – Browser code

```html
<script src="https://signer.example.gov.in/sdk/signer.js"></script>
<script>
  const signer = new Signer.SignerClient({
    serverUrl: 'https://signer.example.gov.in',
    getToken: () => fetch('/esign/token', { method: 'POST' }).then(r => r.json()).then(j => j.token)
  });

  async function signFile(pdfBlob) {
    if (!(await signer.isAvailable())) {
      alert('Please install and start the Signer Agent');      // link to your MSI download
      return;
    }
    try {
      const signed = await signer.signPdfOnServer({
        pdf: pdfBlob,                       // File, Blob, ArrayBuffer, Uint8Array or Base64
        name: 'note-file.pdf',
        options: { page: 'last', x: 360, y: 40, width: 200, height: 70,
                   reason: 'Approved', location: 'Amaravati', customText: 'File No. GAD01/123/2026', timestamp: true }
      });
      // signed.blob / signed.base64 / signed.certificate.commonName / signed.txn
      await uploadToYourServer(signed.blob);
    } catch (e) {
      // e.code: TOKEN_NOT_PRESENT, PIN_INCORRECT, PIN_LOCKED, USER_CANCELLED, AGENT_UNREACHABLE, ...
      showMessage(e.message);
    }
  }
</script>
```

Other SDK calls:

| Call | Use |
|---|---|
| `signer.status()` / `isAvailable()` | Detect the agent and a connected token |
| `signer.certificates({ filter })` | Show the user's certificates (e.g. to register a signer's certificate in your user master) |
| `signer.signPdf({ pdf, options })` | Desktop mode: the agent signs the whole PDF |
| `signer.signPdfs({ documents, options })` | Batch: several PDFs, one PIN entry (token `maxDocuments` ≥ count) |
| `signer.signHash({ digest, format })` | Sign a SHA-256 digest you prepared yourself (`cms`, `pades` or `raw`) |
| `signer.verify({ pdf })` | Verify all signatures of a PDF on the server |
| `Signer.download(blob, name)` | Save a file in the browser |

### Restricting who signs

Pass a certificate filter so only the expected officer's certificate can be used:

```js
signer.signPdfOnServer({ pdf, certificate: { serialNumber: officer.dscSerial } })
```

### Signing from your server instead of the browser

If your server already holds the PDF, call `POST /api/v1/pdf/prepare` with your API key, send only the
returned `digest` to the browser for `signer.signHash({ digest, format, serverCompletes: true })`, and
post the signature back to `POST /api/v1/pdf/complete` from your server. The PDF then never touches the
browser.

## e-Office specifics

* Place the signature box with `page: "last"` and coordinates matching your note-sheet template;
  `origin: "top-left"` lets you use the same numbers as screen layouts.
* Multiple approvers can sign the same PDF one after another; earlier signatures remain valid.
* Use `reference` for the file number; it appears in the consent window, in transaction reports and in
  the audit log.
* For dispatch/approval of many letters, request a token with `maxDocuments: N` and use `signPdfs`.

## Migrating from the APTS Browser Signing Solution

| Today (APTS / PKI Network) | With Signer |
|---|---|
| `POST https://www.pki.network/api/v1.0/generatekey` with `authtoken` header | `POST https://<your-signer>/api/v1/tokens` with `X-API-Key` header and `{"origin": "..."}` |
| Local service `http://127.0.0.1:1620` | `http://127.0.0.1:1645` – or set `agent.port=1620` on the agents after uninstalling the old utility |
| `command: pkiNetworkCertExt` | Same JSON accepted on `POST /`; put the new token in `request.token` |
| `command: pkinetworksign` with `pdf.cood/size/page/isgreentick/enabletimestamp/...` | Same JSON accepted; response `response.data` holds the signed PDF |
| Response format not documented | Documented: `response.status`, `response.code`, `response.message`, `response.data` / `response.certificates` |

Recommended path: switch the token call and the port first (no other code changes), then move to
`signer.js` and server-prepared signing at your own pace.

## Testing without a token

* Use the **demo page** (`/demo/`) of your Signer Server to see the full flow.
* For automated tests, configure the agent with a test certificate file and automatic consent
  (never on user PCs):

  ```properties
  token.providers=pkcs12
  pkcs12.file=C:/test/test-signer.p12
  pkcs12.password=secret
  consent.mode=auto
  ```
