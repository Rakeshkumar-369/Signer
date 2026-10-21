(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var pdfBlob = null;
  var pdfName = null;
  var signedBlob = null;

  function log(msg, kind) {
    var line = '[' + new Date().toLocaleTimeString() + '] ' + (kind === 'error' ? 'ERROR: ' : '') + msg + '\n';
    $('log').textContent += line;
    $('log').scrollTop = $('log').scrollHeight;
  }

  function client() {
    return new Signer.SignerClient({
      agentUrl: $('agentUrl').value.trim(),
      serverUrl: window.location.origin,
      // In a real application this call goes to YOUR back end, which uses its API key to get a token.
      getToken: function () {
        return fetch('/demo/api/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ maxDocuments: 1, reference: pdfName || 'DEMO' })
        }).then(function (r) { return r.json(); }).then(function (j) {
          if (!j.ok) { throw new Signer.SignerError(j.error.code, j.error.message); }
          return j.token;
        });
      }
    });
  }

  function setStatus(text, kind) {
    var el = $('agentStatus');
    el.textContent = text;
    el.className = 'notice ' + (kind || '');
  }

  function cell(tr, text) {
    var td = document.createElement('td');
    td.textContent = text == null ? '' : String(text);
    tr.appendChild(td);
    return td;
  }

  function table(headers, rows) {
    var t = document.createElement('table');
    var head = document.createElement('tr');
    headers.forEach(function (h) {
      var th = document.createElement('th');
      th.textContent = h;
      head.appendChild(th);
    });
    t.appendChild(head);
    rows.forEach(function (r) {
      var tr = document.createElement('tr');
      r.forEach(function (c) {
        if (c instanceof Node) {
          var td = document.createElement('td');
          td.appendChild(c);
          tr.appendChild(td);
        } else {
          cell(tr, c);
        }
      });
      t.appendChild(tr);
    });
    return t;
  }

  function pill(text, kind) {
    var s = document.createElement('span');
    s.className = 'pill ' + (kind || '');
    s.textContent = text;
    return s;
  }

  function date(s) {
    return s ? new Date(s).toLocaleString() : '';
  }

  async function checkAgent() {
    setStatus('Checking the signing agent...');
    try {
      var s = await client().status();
      if (s.tokenPresent) {
        setStatus('Signer Agent ' + s.version + ' is running (' + s.mode + ' mode). A signing certificate is available.', 'ok');
      } else {
        setStatus('Signer Agent ' + s.version + ' is running, but no USB token / certificate was found. Insert your DSC token.', 'warn');
      }
    } catch (e) {
      setStatus('The Signer Agent is not running on this computer. Install it and start "Signer Agent", then click "Check agent". (' + e.message + ')', 'bad');
    }
  }

  async function listCerts() {
    try {
      var list = await client().certificates();
      var rows = list.map(function (c) {
        return [c.commonName, c.issuerCommonName, c.certificateClass || '', date(c.notAfter), c.serialNumber, c.source];
      });
      var wrap = $('certTable');
      wrap.textContent = '';
      wrap.appendChild(table(['Name', 'Issued by', 'Class', 'Valid till', 'Serial', 'Source'], rows));
      wrap.classList.remove('hidden');
      log(list.length + ' certificate(s) found');
    } catch (e) {
      log(e.code + ' - ' + e.message, 'error');
    }
  }

  function options() {
    var o = {
      page: $('page').value.trim() || 'last',
      x: Number($('x').value), y: Number($('y').value),
      width: Number($('w').value), height: Number($('h').value),
      reason: $('reason').value, location: $('location').value,
      greenTick: $('greenTick').checked,
      timestamp: $('timestamp').checked
    };
    if ($('custom').value.trim()) { o.customText = $('custom').value.trim(); }
    if ($('pades').checked) { o.subFilter = 'ETSI.CAdES.detached'; }
    return o;
  }

  async function verify(blob, token) {
    try {
      var report = await client().verify({ pdf: blob, token: token });
      var rows = report.signatures.map(function (s) {
        var kind = s.status === 'VALID' ? 'ok' : s.status === 'INVALID' ? 'bad' : 'warn';
        return [s.signerName, pill(s.status.replace('_', ' '), kind), date(s.timestampTime || s.signingTime),
          s.timestamped ? 'Yes (' + (s.timestampAuthority || 'TSA') + ')' : 'No', s.reason, (s.notes || []).join('; ')];
      });
      var wrap = $('verifyTable');
      wrap.textContent = '';
      wrap.appendChild(table(['Signer', 'Status', 'Signed at', 'Timestamp', 'Reason', 'Notes'], rows));
    } catch (e) {
      log('Verification failed: ' + e.message, 'error');
    }
  }

  async function sign() {
    if (!pdfBlob) {
      log('Choose a PDF or use the sample document first', 'error');
      return;
    }
    var mode = document.querySelector('input[name=mode]:checked').value;
    $('sign').disabled = true;
    try {
      log('Requesting a transaction token...');
      var c = client();
      var token = await c.getToken();
      log('Token received. Confirm the signature in the Signer window (enter the token PIN if asked)...');
      var result = mode === 'server'
        ? await c.signPdfOnServer({ token: token, pdf: pdfBlob, name: pdfName, options: options() })
        : await c.signPdf({ token: token, pdf: pdfBlob, name: pdfName, options: options() });
      signedBlob = result.blob;
      log('Signed by ' + result.certificate.commonName + ' (transaction ' + result.txn + ')');
      $('result').classList.remove('hidden');
      $('preview').src = URL.createObjectURL(signedBlob);
      await verify(signedBlob, token);
    } catch (e) {
      log((e.code || 'ERROR') + ' - ' + e.message, 'error');
    } finally {
      $('sign').disabled = false;
    }
  }

  $('checkAgent').addEventListener('click', checkAgent);
  $('listCerts').addEventListener('click', listCerts);
  $('sign').addEventListener('click', sign);
  $('file').addEventListener('change', function (e) {
    var f = e.target.files[0];
    if (f) {
      pdfBlob = f;
      pdfName = f.name;
      $('fileName').textContent = f.name + ' (' + Math.round(f.size / 1024) + ' KB)';
    }
  });
  $('useSample').addEventListener('click', function () {
    fetch('/demo/sample.pdf').then(function (r) { return r.blob(); }).then(function (b) {
      pdfBlob = b;
      pdfName = 'sample-note-file.pdf';
      $('fileName').textContent = pdfName + ' (sample)';
      log('Sample document loaded');
    });
  });
  $('download').addEventListener('click', function () {
    if (signedBlob) {
      Signer.download(signedBlob, (pdfName || 'document.pdf').replace(/\.pdf$/i, '') + '-signed.pdf');
    }
  });

  fetch('/api/v1/health').then(function (r) { return r.json(); }).then(function (h) {
    if (!h.timestampAuthority) {
      $('timestamp').disabled = true;
      $('timestamp').parentElement.title = 'No timestamp authority configured on the server (signer.tsa.url)';
    }
  });
  checkAgent();
})();
