# Example integration (Node.js, no dependencies)

A minimal "department application" that signs PDFs with the user's USB token through Signer.

1. In the Signer admin console create a tenant with allowed origin `http://localhost:3000` and an API key.
2. Start the example:

   ```bash
   SIGNER_URL=http://localhost:8080 SIGNER_API_KEY=sk_... node server.js
   ```

3. Open <http://localhost:3000>, choose a PDF and click **Sign with my DSC token**.

The only server-side code is `POST /esign/token` in `server.js`: it uses the secret API key to obtain a
single-use transaction token and hands that token to the browser. The page then calls
`signer.signPdfOnServer(...)` from the browser SDK.
