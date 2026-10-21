/*!
 * Signer browser SDK v1.0.0
 * Talks to the Signer Agent running on the user's computer (USB token signing) and, optionally,
 * to the Signer Server for server-prepared ("hash only") signing.
 *
 * Usage (script tag):   <script src="https://your-signer-server/sdk/signer.js"></script>
 *                       const signer = new Signer.SignerClient({ getToken: () => fetch('/my/token').then(r => r.json()).then(j => j.token) });
 * Usage (bundler):      const { SignerClient } = require('./signer.js');
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Signer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var DEFAULT_AGENT_URL = 'http://127.0.0.1:1645';

  /** Error with a stable machine-readable code (see docs/ERROR-CODES.md). */
  class SignerError extends Error {
    constructor(code, message, status) {
      super(message);
      this.name = 'SignerError';
      this.code = code;
      this.status = status || 0;
    }
  }

  // ------------------------------------------------------------------ helpers

  function bytesToBase64(bytes) {
    var CHUNK = 0x8000;
    var parts = [];
    for (var i = 0; i < bytes.length; i += CHUNK) {
      parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    return btoa(parts.join(''));
  }

  function base64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  /** Accepts Blob/File, ArrayBuffer, Uint8Array or a Base64 string and returns Base64. */
  async function toBase64(input) {
    if (input == null) {
      throw new SignerError('BAD_REQUEST', 'No document supplied');
    }
    if (typeof input === 'string') {
      var comma = input.indexOf(',');
      return input.indexOf('data:') === 0 && comma > 0 ? input.substring(comma + 1) : input;
    }
    if (typeof Blob !== 'undefined' && input instanceof Blob) {
      return bytesToBase64(new Uint8Array(await input.arrayBuffer()));
    }
    if (input instanceof ArrayBuffer) {
      return bytesToBase64(new Uint8Array(input));
    }
    if (ArrayBuffer.isView(input)) {
      return bytesToBase64(new Uint8Array(input.buffer, input.byteOffset, input.byteLength));
    }
    throw new SignerError('BAD_REQUEST', 'Unsupported document type');
  }

  function pdfResult(b64) {
    var bytes = base64ToBytes(b64);
    return {
      base64: b64,
      bytes: bytes,
      blob: typeof Blob !== 'undefined' ? new Blob([bytes], { type: 'application/pdf' }) : null
    };
  }

  /** Triggers a browser download of a Blob. */
  function download(blob, fileName) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = fileName || 'signed.pdf';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      URL.revokeObjectURL(url);
      a.remove();
    }, 1000);
  }

  async function postJson(url, body, token, timeoutMs) {
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = controller ? setTimeout(function () { controller.abort(); }, timeoutMs) : null;
    var headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers.Authorization = 'Bearer ' + token;
    }
    var res;
    try {
      res = await fetch(url, {
        method: body === undefined ? 'GET' : 'POST',
        headers: headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller ? controller.signal : undefined
      });
    } catch (e) {
      if (e && e.name === 'AbortError') {
        throw new SignerError('TIMEOUT', 'The request timed out');
      }
      throw new SignerError('AGENT_UNREACHABLE', 'Could not reach ' + url + ' (' + (e && e.message) + ')');
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
    var json;
    try {
      json = await res.json();
    } catch (e) {
      throw new SignerError('BAD_RESPONSE', 'Unexpected response (HTTP ' + res.status + ')', res.status);
    }
    if (!res.ok || json.ok === false) {
      var err = json.error || {};
      throw new SignerError(err.code || 'HTTP_' + res.status, err.message || 'Request failed', res.status);
    }
    return json;
  }

  // ------------------------------------------------------------------ client

  /**
   * @param {object} opts
   * @param {string} [opts.agentUrl]   Desktop agent URL (default http://127.0.0.1:1645)
   * @param {string} [opts.serverUrl]  Signer Server URL, needed only for signPdfOnServer/verify
   * @param {function(): Promise<string>} [opts.getToken] Returns a fresh transaction token from YOUR back end
   * @param {number} [opts.timeoutMs]  Timeout for signing calls (default 180 s: the user has to type the PIN)
   * @param {boolean} [opts.reportCompletion] Report desktop-signed transactions to serverUrl (default true)
   */
  class SignerClient {
    constructor(opts) {
      opts = opts || {};
      this.agentUrl = (opts.agentUrl || DEFAULT_AGENT_URL).replace(/\/+$/, '');
      this.serverUrl = opts.serverUrl ? opts.serverUrl.replace(/\/+$/, '') : null;
      this.getToken = opts.getToken || null;
      this.timeoutMs = opts.timeoutMs || 180000;
      this.reportCompletion = opts.reportCompletion !== false;
    }

    /** Records a desktop-signed transaction as completed on the Signer Server (best effort, used for billing). */
    _report(txn, token, documents, certificate) {
      if (!this.serverUrl || !this.reportCompletion || !txn) {
        return Promise.resolve();
      }
      return postJson(this.serverUrl + '/api/v1/transactions/' + encodeURIComponent(txn) + '/complete', {
        status: 'COMPLETED',
        documents: documents,
        signerName: certificate && certificate.commonName,
        signerSerial: certificate && certificate.serialNumber
      }, token, 15000).catch(function () { /* reporting must never break signing */ });
    }

    async _token(token) {
      if (token) {
        return token;
      }
      if (!this.getToken) {
        throw new SignerError('UNAUTHORIZED', 'No transaction token: pass {token} or configure getToken');
      }
      var t = await this.getToken();
      if (t && typeof t === 'object' && t.token) {
        t = t.token;
      }
      return t;
    }

    /** Agent status: version, mode, whether a token is connected. Throws AGENT_UNREACHABLE when not installed/running. */
    async status() {
      return postJson(this.agentUrl + '/api/v1/status', undefined, null, 5000);
    }

    /** True when the agent is installed and running. */
    async isAvailable() {
      try {
        await this.status();
        return true;
      } catch (e) {
        return false;
      }
    }

    /** Lists signing certificates on the connected token(s). */
    async certificates(args) {
      args = args || {};
      var token = await this._token(args.token);
      var r = await postJson(this.agentUrl + '/api/v1/certificates', { certificate: args.filter || null }, token, 30000);
      return r.certificates;
    }

    /**
     * Signs a PDF on the user's computer (the whole document is sent to the local agent).
     * @param {object} args { pdf, name?, options?, certificate?, token? }
     * @returns {Promise<{base64:string, bytes:Uint8Array, blob:Blob, certificate:object, txn:string}>}
     */
    async signPdf(args) {
      args = args || {};
      var token = await this._token(args.token);
      var body = {
        name: args.name || 'document.pdf',
        pdf: await toBase64(args.pdf),
        options: args.options || {},
        certificate: args.certificate || null
      };
      var r = await postJson(this.agentUrl + '/api/v1/sign/pdf', body, token, this.timeoutMs);
      await this._report(r.txn, token, 1, r.certificate);
      var out = pdfResult(r.documents[0].data);
      out.certificate = r.certificate;
      out.chain = r.chain;
      out.txn = r.txn;
      return out;
    }

    /** Signs several PDFs with one PIN entry. documents: [{pdf, name?, options?}] */
    async signPdfs(args) {
      args = args || {};
      var token = await this._token(args.token);
      var docs = [];
      for (var i = 0; i < args.documents.length; i++) {
        var d = args.documents[i];
        docs.push({ name: d.name || 'document-' + (i + 1) + '.pdf', data: await toBase64(d.pdf), options: d.options || null });
      }
      var r = await postJson(this.agentUrl + '/api/v1/sign/pdf',
        { documents: docs, options: args.options || {}, certificate: args.certificate || null }, token, this.timeoutMs);
      await this._report(r.txn, token, r.documents.length, r.certificate);
      return {
        txn: r.txn,
        certificate: r.certificate,
        documents: r.documents.map(function (d) {
          var o = pdfResult(d.data);
          o.name = d.name;
          return o;
        })
      };
    }

    /**
     * Signs SHA-256 digest(s) prepared elsewhere. format: 'cms' | 'pades' | 'raw'.
     * digest may be a Base64 string or an array of {id, digest}.
     */
    async signHash(args) {
      args = args || {};
      var token = await this._token(args.token);
      var body = {
        format: args.format || 'cms',
        timestamp: !!args.timestamp,
        certificate: args.certificate || null,
        documentNames: args.documentNames || []
      };
      if (Array.isArray(args.digest)) {
        body.hashes = args.digest;
      } else {
        body.digest = args.digest;
      }
      var r = await postJson(this.agentUrl + '/api/v1/sign/hash', body, token, this.timeoutMs);
      if (!args.serverCompletes) {
        await this._report(r.txn, token, r.signatures.length, r.certificate);
      }
      return r;
    }

    /**
     * Recommended for large documents: the Signer Server prepares the PDF, only a 32-byte digest goes to
     * the token, and the server embeds the signature (plus timestamp/LTV when requested).
     * The token must allow both 'certificates' and 'sign'.
     */
    async signPdfOnServer(args) {
      args = args || {};
      if (!this.serverUrl) {
        throw new SignerError('BAD_REQUEST', 'serverUrl is required for server-side signing');
      }
      var token = await this._token(args.token);
      var certs = await postJson(this.agentUrl + '/api/v1/certificates', { certificate: args.certificate || null }, token, 30000);
      if (!certs.certificates.length) {
        throw new SignerError('TOKEN_NOT_PRESENT', 'No signing certificate found. Insert your DSC token.');
      }
      var cert = certs.certificates[0];
      if (certs.certificates.length > 1 && typeof args.chooseCertificate === 'function') {
        cert = await args.chooseCertificate(certs.certificates);
      }
      var prepared = await postJson(this.serverUrl + '/api/v1/pdf/prepare', {
        pdf: await toBase64(args.pdf),
        name: args.name || 'document.pdf',
        options: args.options || {},
        certificate: cert.certificate
      }, token, 60000);
      var signed = await postJson(this.agentUrl + '/api/v1/sign/hash', {
        digest: prepared.digest,
        format: prepared.format,
        certificate: { id: cert.id },
        documentNames: [args.name || 'document.pdf']
      }, token, this.timeoutMs);
      var done = await postJson(this.serverUrl + '/api/v1/pdf/complete', {
        sessionId: prepared.sessionId,
        signature: signed.signatures[0].signature
      }, token, 60000);
      var out = pdfResult(done.pdf);
      out.certificate = done.signer;
      out.timestamped = done.timestamped;
      out.txn = certs.txn;
      return out;
    }

    /** Verifies all signatures of a PDF on the Signer Server. */
    async verify(args) {
      if (!this.serverUrl) {
        throw new SignerError('BAD_REQUEST', 'serverUrl is required for verification');
      }
      var token = await this._token(args && args.token);
      var r = await postJson(this.serverUrl + '/api/v1/pdf/verify', { pdf: await toBase64(args.pdf), password: args.password || null },
        token, 60000);
      return r.report;
    }
  }

  return {
    SignerClient: SignerClient,
    SignerError: SignerError,
    toBase64: toBase64,
    base64ToBytes: base64ToBytes,
    download: download,
    version: '1.0.0'
  };
});
