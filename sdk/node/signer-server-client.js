'use strict';
/**
 * Minimal Node.js (18+) client for the Signer Server, for use in YOUR application's back end.
 * Keep the API key on the server; hand only the short-lived transaction token to the browser.
 *
 *   const { SignerServerClient } = require('./signer-server-client');
 *   const signer = new SignerServerClient({ serverUrl: process.env.SIGNER_URL, apiKey: process.env.SIGNER_API_KEY });
 *   app.post('/esign/token', async (req, res) => {
 *     const t = await signer.issueToken({ origin: 'https://eoffice.example.gov.in', reference: req.body.fileNo });
 *     res.json({ token: t.token });
 *   });
 */
class SignerServerClient {
  constructor({ serverUrl, apiKey, timeoutMs = 30000 }) {
    if (!serverUrl || !apiKey) {
      throw new Error('serverUrl and apiKey are required');
    }
    this.serverUrl = serverUrl.replace(/\/+$/, '');
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  async _call(method, path, body) {
    const res = await fetch(this.serverUrl + path, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs)
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || json.ok === false) {
      const err = new Error((json.error && json.error.message) || 'HTTP ' + res.status);
      err.code = (json.error && json.error.code) || 'HTTP_' + res.status;
      err.status = res.status;
      throw err;
    }
    return json;
  }

  /** Issues a single-use transaction token for the given browser origin. */
  issueToken({ origin, operations, maxDocuments, ttlSeconds, reference }) {
    return this._call('POST', '/api/v1/tokens', { origin, operations, maxDocuments, ttlSeconds, reference });
  }

  getTransaction(txn) {
    return this._call('GET', '/api/v1/transactions/' + encodeURIComponent(txn));
  }

  completeTransaction(txn, { status = 'COMPLETED', documents, signerName, signerSerial, documentHash, error } = {}) {
    return this._call('POST', '/api/v1/transactions/' + encodeURIComponent(txn) + '/complete',
      { status, documents, signerName, signerSerial, documentHash, error });
  }

  /** Server-side preparation: pdf is a Buffer; returns { sessionId, digest, format }. */
  preparePdf({ pdf, name, options, certificate }) {
    return this._call('POST', '/api/v1/pdf/prepare', { pdf: Buffer.from(pdf).toString('base64'), name, options, certificate });
  }

  /** Embeds the CMS signature produced by the agent; resolves to the signed PDF as a Buffer. */
  async completePdf({ sessionId, signature }) {
    const r = await this._call('POST', '/api/v1/pdf/complete', { sessionId, signature });
    return Object.assign({}, r, { pdf: Buffer.from(r.pdf, 'base64') });
  }

  async verifyPdf(pdf, password) {
    const r = await this._call('POST', '/api/v1/pdf/verify', { pdf: Buffer.from(pdf).toString('base64'), password });
    return r.report;
  }
}

module.exports = { SignerServerClient };
