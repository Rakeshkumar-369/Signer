(function () {
  'use strict';

  var app = document.getElementById('app');
  var state = { token: null, user: null };

  // ---------------------------------------------------------------- storage

  function load(key) {
    try { return sessionStorage.getItem(key); } catch (e) { return null; }
  }
  function save(key, value) {
    try {
      if (value == null) { sessionStorage.removeItem(key); } else { sessionStorage.setItem(key, value); }
    } catch (e) { /* storage unavailable: session lasts until reload */ }
  }

  // ------------------------------------------------------------------- DOM

  function el(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) { return; }
        if (k === 'class') { node.className = v; }
        else if (k.indexOf('on') === 0) { node.addEventListener(k.substring(2), v); }
        else if (k === 'value') { node.value = v; }
        else if (k === 'checked') { node.checked = !!v; }
        else { node.setAttribute(k, v === true ? '' : v); }
      });
    }
    for (var i = 2; i < arguments.length; i++) { append(node, arguments[i]); }
    return node;
  }
  function append(node, child) {
    if (child == null || child === false) { return; }
    if (Array.isArray(child)) { child.forEach(function (c) { append(node, c); }); return; }
    node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } return node; }
  function field(label, input) { return el('div', null, el('label', null, label), input); }
  function pill(text, kind) { return el('span', { class: 'pill ' + (kind || '') }, text); }
  function fmtDate(s) { return s ? new Date(s).toLocaleString() : ''; }
  function fmtDay(s) { return s ? new Date(s).toLocaleDateString() : ''; }
  function num(n) { return n == null ? '' : Number(n).toLocaleString(); }
  function notice(text, kind) { return el('div', { class: 'notice ' + (kind || '') }, text); }
  function table(headers, rows, numeric) {
    numeric = numeric || [];
    return el('div', { class: 'table-wrap' }, el('table', null,
      el('tr', null, headers.map(function (h, i) { return el('th', { class: numeric.indexOf(i) >= 0 ? 'num' : null }, h); })),
      rows.length ? rows.map(function (r) {
        return el('tr', null, r.map(function (c, i) { return el('td', { class: numeric.indexOf(i) >= 0 ? 'num' : null }, c); }));
      }) : el('tr', null, el('td', { colspan: headers.length, class: 'muted' }, 'Nothing to show'))));
  }

  // ------------------------------------------------------------------- API

  function api(method, path, body) {
    var headers = { 'Content-Type': 'application/json' };
    if (state.token) { headers.Authorization = 'Bearer ' + state.token; }
    return fetch(path, { method: method, headers: headers, body: body === undefined ? undefined : JSON.stringify(body) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (r.status === 401 && path !== '/api/admin/login') { logout(); }
          if (!r.ok || j.ok === false) {
            var e = new Error((j.error && j.error.message) || ('HTTP ' + r.status));
            e.code = j.error && j.error.code;
            throw e;
          }
          return j;
        });
      });
  }

  function failInto(container) {
    return function (e) { container.insertBefore(notice(e.message, 'bad'), container.firstChild); };
  }

  // ---------------------------------------------------------------- session

  function setSession(s) {
    state.token = s.token;
    state.user = s.user;
    save('signer.admin.token', s.token);
  }
  function logout() {
    state.token = null;
    state.user = null;
    save('signer.admin.token', null);
    location.hash = '#/login';
    render();
  }

  // ---------------------------------------------------------------- layout

  var NAV = [
    ['#/dashboard', 'Dashboard'], ['#/tenants', 'Tenants'], ['#/transactions', 'Transactions'],
    ['#/usage', 'Usage & billing'], ['#/audit', 'Audit log'], ['#/users', 'Users', true],
    ['#/license', 'Licence'], ['#/setup', 'Agent setup']
  ];

  function shell(active, title) {
    var content = el('main', { class: 'content' }, el('h1', null, title));
    var side = el('nav', { class: 'side' }, NAV.filter(function (n) { return !n[2] || state.user.role === 'ADMIN'; }).map(function (n) {
      return el('a', { href: n[0], class: active === n[0] ? 'active' : null }, n[1]);
    }));
    clear(app);
    app.appendChild(el('header', { class: 'topbar' },
      el('div', { class: 'logo' }, '\u2713'), el('div', { class: 'title' }, 'Signer Admin'), el('div', { class: 'spacer' }),
      el('span', null, state.user.username + ' (' + state.user.role.toLowerCase() + ')'),
      el('button', { class: 'link', onclick: logout }, 'Log out')));
    app.appendChild(el('div', { class: 'layout' }, side, content));
    return content;
  }

  // ----------------------------------------------------------------- views

  function viewLogin(mustChange) {
    clear(app);
    var msg = el('div');
    if (mustChange) {
      var cur = el('input', { type: 'password', autocomplete: 'current-password' });
      var p1 = el('input', { type: 'password', autocomplete: 'new-password' });
      var p2 = el('input', { type: 'password', autocomplete: 'new-password' });
      var form = el('form', {
        onsubmit: function (e) {
          e.preventDefault();
          clear(msg);
          if (p1.value !== p2.value) { msg.appendChild(notice('The new passwords do not match', 'bad')); return; }
          api('POST', '/api/admin/password', { currentPassword: cur.value, newPassword: p1.value })
            .then(function (s) { setSession(s); location.hash = '#/dashboard'; render(); })
            .catch(function (e2) { msg.appendChild(notice(e2.message, 'bad')); });
        }
      }, el('h1', null, 'Choose a new password'),
        el('p', { class: 'muted' }, 'At least 10 characters with letters and digits.'), msg,
        el('div', { class: 'grid' }, field('Current password', cur), field('New password', p1), field('Repeat new password', p2)),
        el('div', { class: 'form-actions' }, el('button', { type: 'submit' }, 'Save password')));
      app.appendChild(el('div', { class: 'login' }, el('div', { class: 'card' }, form)));
      return;
    }
    var u = el('input', { type: 'text', autocomplete: 'username', value: 'admin' });
    var p = el('input', { type: 'password', autocomplete: 'current-password' });
    app.appendChild(el('div', { class: 'login' }, el('div', { class: 'card' }, el('form', {
      onsubmit: function (e) {
        e.preventDefault();
        clear(msg);
        api('POST', '/api/admin/login', { username: u.value, password: p.value }).then(function (s) {
          setSession(s);
          if (s.mustChangePassword) { viewLogin(true); } else { location.hash = '#/dashboard'; render(); }
        }).catch(function (e2) { msg.appendChild(notice(e2.message, 'bad')); });
      }
    }, el('h1', null, 'Signer Admin'), el('p', { class: 'muted' }, 'Sign in to manage tenants, keys and usage.'), msg,
      el('div', { class: 'grid' }, field('Username', u), field('Password', p)),
      el('div', { class: 'form-actions' }, el('button', { type: 'submit' }, 'Sign in'))))));
    p.focus();
  }

  function chart(daily) {
    var W = 720, H = 170, pad = 22;
    var days = [];
    var byDay = {};
    daily.forEach(function (d) { byDay[d.day] = d; });
    for (var i = 29; i >= 0; i--) {
      var dt = new Date(Date.now() - i * 86400000);
      var key = dt.toISOString().substring(0, 10);
      days.push(byDay[key] || { day: key, issued: 0, completed: 0, failed: 0 });
    }
    var max = Math.max.apply(null, days.map(function (d) { return d.issued; }).concat([1]));
    var bw = (W - pad) / days.length;
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('class', 'chart');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Transactions per day, last 30 days');
    days.forEach(function (d, idx) {
      var h = (H - pad) * d.issued / max;
      var r = document.createElementNS(svg.namespaceURI, 'rect');
      r.setAttribute('x', pad + idx * bw + 2);
      r.setAttribute('y', H - pad - h);
      r.setAttribute('width', Math.max(1, bw - 4));
      r.setAttribute('height', h);
      r.setAttribute('class', 'bar');
      var t = document.createElementNS(svg.namespaceURI, 'title');
      t.textContent = d.day + ': ' + d.issued + ' issued, ' + d.completed + ' completed, ' + d.failed + ' failed';
      r.appendChild(t);
      svg.appendChild(r);
      if (idx % 5 === 0) {
        var lbl = document.createElementNS(svg.namespaceURI, 'text');
        lbl.setAttribute('x', pad + idx * bw);
        lbl.setAttribute('y', H - 6);
        lbl.textContent = d.day.substring(5);
        svg.appendChild(lbl);
      }
    });
    var top = document.createElementNS(svg.namespaceURI, 'text');
    top.setAttribute('x', 0);
    top.setAttribute('y', 12);
    top.textContent = String(max);
    svg.appendChild(top);
    return svg;
  }

  function viewDashboard() {
    var c = shell('#/dashboard', 'Dashboard');
    api('GET', '/api/admin/overview').then(function (o) {
      var lic = o.license;
      if (lic.evaluation) {
        c.appendChild(notice(lic.message + ' - limited to ' + lic.license.maxTenants + ' tenants and ' +
          num(lic.license.maxSignaturesPerMonth) + ' transactions per month. Install a licence under "Licence".', 'warn'));
      } else if (lic.expired) {
        c.appendChild(notice(lic.message, 'bad'));
      }
      c.appendChild(el('div', { class: 'tiles', style: 'margin-top:12px' },
        tile('Tenants', o.tenants), tile('Transactions this month', o.transactionsThisMonth),
        tile('Today', o.transactionsToday), tile('Completed this month', o.completedThisMonth),
        tile('Failed this month', o.failedThisMonth)));
      c.appendChild(el('div', { class: 'card' }, el('h2', null, 'Transactions per day (last 30 days)'), chart(o.daily)));
      c.appendChild(el('div', { class: 'card' }, el('h2', null, 'Server'), table(['Setting', 'Value'], [
        ['Public URL', o.publicUrl], ['Token signing key id', o.tokenKeyId],
        ['Timestamp authority', o.timestampAuthority ? 'Configured' : 'Not configured'], ['Licence', lic.message]])));
    }).catch(failInto(c));
  }
  function tile(k, v) { return el('div', { class: 'tile' }, el('div', { class: 'k' }, k), el('div', { class: 'v' }, num(v))); }

  function tenantForm(t, onSave) {
    t = t || {};
    var code = el('input', { type: 'text', value: t.code || '', disabled: !!t.id });
    var name = el('input', { type: 'text', value: t.name || '' });
    var email = el('input', { type: 'email', value: t.contactEmail || '' });
    var plan = el('input', { type: 'text', value: t.plan || 'standard' });
    var quota = el('input', { type: 'number', min: '0', value: t.monthlyQuota != null ? t.monthlyQuota : 0 });
    var until = el('input', { type: 'date', value: t.validUntil ? t.validUntil.substring(0, 10) : '' });
    var origins = el('textarea', { placeholder: 'https://eoffice.example.gov.in\nhttps://hrms.example.gov.in' });
    origins.value = (t.allowedOrigins || []).join('\n');
    var msg = el('div');
    return el('form', {
      onsubmit: function (e) {
        e.preventDefault();
        clear(msg);
        onSave({
          code: code.value.trim(), name: name.value.trim(), contactEmail: email.value.trim(), plan: plan.value.trim(),
          monthlyQuota: Number(quota.value || 0),
          validUntil: until.value ? new Date(until.value + 'T23:59:59Z').toISOString() : null,
          allowedOrigins: origins.value.split(/[\s,]+/).filter(Boolean)
        }).catch(function (e2) { msg.appendChild(notice(e2.message, 'bad')); });
      }
    }, msg, el('div', { class: 'grid cols-3' },
      field('Code (short id, e.g. gad)', code), field('Organisation name', name), field('Contact e-mail', email),
      field('Plan', plan), field('Monthly quota (0 = unlimited)', quota), field('Subscription valid until', until)),
      el('div', { style: 'margin-top:12px' }, field('Allowed web origins (one per line) - the sites that may use the agent', origins)),
      el('div', { class: 'form-actions' }, el('button', { type: 'submit' }, t.id ? 'Save changes' : 'Create tenant')));
  }

  function viewTenants() {
    var c = shell('#/tenants', 'Tenants');
    var isAdmin = state.user.role === 'ADMIN';
    var formBox = el('div', { class: 'card hidden' }, el('h2', null, 'New tenant'), tenantForm(null, function (body) {
      return api('POST', '/api/admin/tenants', body).then(function (r) { location.hash = '#/tenant/' + r.tenant.id; });
    }));
    if (isAdmin) {
      c.appendChild(el('div', { class: 'row end', style: 'margin-bottom:12px' },
        el('button', { onclick: function () { formBox.classList.toggle('hidden'); } }, 'New tenant')));
    }
    c.appendChild(formBox);
    var list = el('div', { class: 'card' });
    c.appendChild(list);
    api('GET', '/api/admin/tenants').then(function (r) {
      list.appendChild(table(['Code', 'Name', 'Plan', 'Status', 'Used / quota', 'Valid until', 'Origins'], r.tenants.map(function (x) {
        var t = x.tenant;
        return [el('a', { href: '#/tenant/' + t.id }, t.code), t.name, t.plan,
          pill(t.status, t.status === 'ACTIVE' ? 'ok' : 'bad'),
          num(x.usedThisMonth) + ' / ' + (t.monthlyQuota ? num(t.monthlyQuota) : '\u221e'),
          t.validUntil ? fmtDay(t.validUntil) : 'No end date', el('span', { class: 'origins' }, t.allowedOrigins.join(', '))];
      })));
    }).catch(failInto(c));
  }

  function viewTenant(id, newSecret) {
    var c = shell('#/tenants', 'Tenant');
    var isAdmin = state.user.role === 'ADMIN';
    api('GET', '/api/admin/tenants/' + encodeURIComponent(id)).then(function (r) {
      var t = r.tenant;
      c.querySelector('h1').textContent = t.name;
      c.appendChild(el('div', { class: 'row', style: 'margin-bottom:12px' }, pill(t.status, t.status === 'ACTIVE' ? 'ok' : 'bad'),
        el('span', { class: 'muted' }, 'Code ' + t.code + ' \u00b7 ' + num(r.usedThisMonth) + ' transactions this month'),
        isAdmin ? el('button', {
          class: t.status === 'ACTIVE' ? 'danger' : 'secondary',
          onclick: function () {
            api('POST', '/api/admin/tenants/' + t.id + '/status', { status: t.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE' })
              .then(function () { viewTenant(id); }).catch(failInto(c));
          }
        }, t.status === 'ACTIVE' ? 'Suspend' : 'Reactivate') : null));

      var keysCard = el('div', { class: 'card' }, el('h2', null, 'API keys'),
        el('p', { class: 'muted small' }, 'Used by the tenant\'s back-end server to request transaction tokens (X-API-Key header). Never put an API key in browser code.'));
      if (newSecret) {
        keysCard.appendChild(el('div', { class: 'notice ok', style: 'margin-bottom:12px' },
          el('div', null, 'New API key - copy it now, it will not be shown again:'),
          el('div', { class: 'secret', style: 'margin-top:6px' }, newSecret)));
      }
      keysCard.appendChild(table(['Label', 'Key', 'Created', 'Last used', 'Status', ''], r.apiKeys.map(function (k) {
        return [k.label, k.prefix + '\u2026', fmtDate(k.createdAt), fmtDate(k.lastUsedAt),
          k.revokedAt ? pill('Revoked', 'bad') : pill('Active', 'ok'),
          isAdmin && !k.revokedAt ? el('button', {
            class: 'link', onclick: function () {
              if (confirm('Revoke this API key? Applications using it will stop working immediately.')) {
                api('DELETE', '/api/admin/keys/' + k.id).then(function () { viewTenant(id); }).catch(failInto(c));
              }
            }
          }, 'Revoke') : ''];
      })));
      if (isAdmin) {
        var label = el('input', { type: 'text', placeholder: 'Label, e.g. eoffice-production' });
        keysCard.appendChild(el('div', { class: 'row', style: 'margin-top:12px' }, label, el('button', {
          onclick: function () {
            api('POST', '/api/admin/tenants/' + t.id + '/keys', { label: label.value }).then(function (k) {
              viewTenant(id, k.secret);
            }).catch(failInto(c));
          }
        }, 'Create API key')));
      }
      c.appendChild(keysCard);
      if (isAdmin) {
        c.appendChild(el('div', { class: 'card' }, el('h2', null, 'Settings'), tenantForm(t, function (body) {
          return api('PUT', '/api/admin/tenants/' + t.id, body).then(function () { viewTenant(id); });
        })));
      }
    }).catch(failInto(c));
  }

  function viewTransactions() {
    var c = shell('#/transactions', 'Transactions');
    var f = { tenant: el('select'), status: el('select'), from: el('input', { type: 'date' }), to: el('input', { type: 'date' }),
      q: el('input', { type: 'text', placeholder: 'Transaction id, reference or signer' }) };
    f.tenant.appendChild(el('option', { value: '' }, 'All tenants'));
    ['', 'ISSUED', 'COMPLETED', 'FAILED'].forEach(function (s) { f.status.appendChild(el('option', { value: s }, s || 'Any status')); });
    var page = 1;
    var results = el('div', { class: 'card' });
    function run() {
      var qs = new URLSearchParams({ page: page, size: 25 });
      if (f.tenant.value) { qs.set('tenantId', f.tenant.value); }
      if (f.status.value) { qs.set('status', f.status.value); }
      if (f.from.value) { qs.set('from', f.from.value); }
      if (f.to.value) { qs.set('to', f.to.value); }
      if (f.q.value.trim()) { qs.set('q', f.q.value.trim()); }
      api('GET', '/api/admin/transactions?' + qs).then(function (r) {
        clear(results);
        results.appendChild(table(['Issued', 'Tenant', 'Status', 'Reference', 'Signer', 'Docs', 'Origin', 'Transaction'], r.items.map(function (x) {
          var t = x.transaction;
          var kind = t.status === 'COMPLETED' ? 'ok' : t.status === 'FAILED' ? 'bad' : '';
          return [fmtDate(t.issuedAt), x.tenantCode, pill(t.status, kind), t.reference || '', t.signerName || '', num(t.documents),
            t.origin, el('code', { title: t.error || '' }, t.id)];
        }), [5]));
        var pages = Math.max(1, Math.ceil(r.total / r.size));
        results.appendChild(el('div', { class: 'pager' }, el('span', { class: 'muted' }, num(r.total) + ' transactions \u00b7 page ' + page + ' of ' + pages),
          el('button', { class: 'secondary', disabled: page <= 1, onclick: function () { page--; run(); } }, 'Previous'),
          el('button', { class: 'secondary', disabled: page >= pages, onclick: function () { page++; run(); } }, 'Next')));
      }).catch(failInto(c));
    }
    c.appendChild(el('div', { class: 'card' }, el('div', { class: 'grid cols-4' },
      field('Tenant', f.tenant), field('Status', f.status), field('From', f.from), field('To', f.to)),
      el('div', { class: 'row', style: 'margin-top:12px' }, f.q, el('button', { onclick: function () { page = 1; run(); } }, 'Search'))));
    c.appendChild(results);
    api('GET', '/api/admin/tenants').then(function (r) {
      r.tenants.forEach(function (x) { f.tenant.appendChild(el('option', { value: x.tenant.id }, x.tenant.code + ' - ' + x.tenant.name)); });
    });
    run();
  }

  function viewUsage() {
    var c = shell('#/usage', 'Usage & billing');
    var month = el('input', { type: 'month', value: new Date().toISOString().substring(0, 7) });
    var out = el('div', { class: 'card' });
    function run() {
      api('GET', '/api/admin/usage?month=' + month.value).then(function (r) {
        clear(out);
        var totals = r.rows.reduce(function (a, x) { a.i += x.issued; a.c += x.completed; a.d += x.documents; return a; }, { i: 0, c: 0, d: 0 });
        out.appendChild(table(['Tenant', 'Name', 'Plan', 'Quota', 'Issued', 'Completed', 'Failed', 'Documents'], r.rows.map(function (x) {
          return [x.code, x.name, x.plan, x.monthlyQuota ? num(x.monthlyQuota) : '\u221e', num(x.issued), num(x.completed), num(x.failed), num(x.documents)];
        }).concat([[el('b', null, 'Total'), '', '', '', el('b', null, num(totals.i)), el('b', null, num(totals.c)), '', el('b', null, num(totals.d))]]),
        [3, 4, 5, 6, 7]));
      }).catch(failInto(c));
    }
    c.appendChild(el('div', { class: 'card' }, el('div', { class: 'row' }, field('Month', month),
      el('button', { onclick: run, style: 'align-self:flex-end' }, 'Show'),
      el('button', {
        class: 'secondary', style: 'align-self:flex-end', onclick: function () {
          fetch('/api/admin/usage.csv?month=' + month.value, { headers: { Authorization: 'Bearer ' + state.token } })
            .then(function (r) { if (!r.ok) { throw new Error('Download failed'); } return r.blob(); })
            .then(function (b) {
              var a = el('a', { href: URL.createObjectURL(b), download: 'signer-usage-' + month.value + '.csv' });
              document.body.appendChild(a); a.click(); a.remove();
            }).catch(failInto(c));
        }
      }, 'Download CSV')),
      el('p', { class: 'muted small' }, 'One transaction = one issued transaction token. Use this report for invoicing.')));
    c.appendChild(out);
    run();
  }

  function viewAudit() {
    var c = shell('#/audit', 'Audit log');
    var page = 1;
    var out = el('div', { class: 'card' });
    c.appendChild(out);
    function run() {
      api('GET', '/api/admin/audit?size=50&page=' + page).then(function (r) {
        clear(out);
        out.appendChild(table(['Time', 'User', 'Action', 'Target', 'Detail', 'IP'], r.items.map(function (a) {
          return [fmtDate(a.occurredAt), a.actor, a.action, a.target || '', a.detail || '', a.ip || ''];
        })));
        var pages = Math.max(1, Math.ceil(r.total / r.size));
        out.appendChild(el('div', { class: 'pager' }, el('span', { class: 'muted' }, 'Page ' + page + ' of ' + pages),
          el('button', { class: 'secondary', disabled: page <= 1, onclick: function () { page--; run(); } }, 'Previous'),
          el('button', { class: 'secondary', disabled: page >= pages, onclick: function () { page++; run(); } }, 'Next')));
      }).catch(failInto(c));
    }
    run();
  }

  function viewUsers() {
    var c = shell('#/users', 'Users');
    var out = el('div', { class: 'card' });
    var u = el('input', { type: 'text' });
    var p = el('input', { type: 'password', autocomplete: 'new-password' });
    var role = el('select', null, el('option', { value: 'VIEWER' }, 'Viewer (read only)'), el('option', { value: 'ADMIN' }, 'Administrator'));
    c.appendChild(el('div', { class: 'card' }, el('h2', null, 'Add user'), el('div', { class: 'grid cols-3' },
      field('Username', u), field('Temporary password', p), field('Role', role)),
      el('div', { class: 'form-actions' }, el('button', {
        onclick: function () {
          api('POST', '/api/admin/users', { username: u.value, password: p.value, role: role.value })
            .then(function () { u.value = ''; p.value = ''; run(); }).catch(failInto(c));
        }
      }, 'Add user'))));
    c.appendChild(out);
    function run() {
      api('GET', '/api/admin/users').then(function (r) {
        clear(out).appendChild(table(['Username', 'Role', 'Created', 'Last login', ''], r.users.map(function (x) {
          return [x.username, x.role, fmtDate(x.createdAt), fmtDate(x.lastLoginAt), el('div', { class: 'row' },
            el('button', {
              class: 'link', onclick: function () {
                var np = prompt('New temporary password for ' + x.username + ' (min. 10 characters, letters and digits):');
                if (np) { api('POST', '/api/admin/users/' + x.id + '/password', { password: np }).then(run).catch(failInto(c)); }
              }
            }, 'Reset password'),
            x.id !== state.user.id ? el('button', {
              class: 'link', onclick: function () {
                if (confirm('Delete user ' + x.username + '?')) { api('DELETE', '/api/admin/users/' + x.id).then(run).catch(failInto(c)); }
              }
            }, 'Delete') : '')];
        })));
      }).catch(failInto(c));
    }
    run();
  }

  function viewLicense() {
    var c = shell('#/license', 'Licence');
    var box = el('div', { class: 'card' });
    c.appendChild(box);
    api('GET', '/api/admin/license').then(function (r) {
      var s = r.status, l = s.license;
      box.appendChild(notice(s.message, s.evaluation ? 'warn' : s.expired ? 'bad' : 'ok'));
      box.appendChild(el('div', { style: 'margin-top:12px' }, table(['Item', 'Value'], [
        ['Licence id', l.licenseId], ['Licensee', l.licensee], ['Edition', l.edition],
        ['Expires', l.expiresAt ? fmtDay(l.expiresAt) : 'Never'],
        ['Tenants allowed', l.maxTenants ? num(l.maxTenants) : 'Unlimited'],
        ['Transactions per month', l.maxSignaturesPerMonth ? num(l.maxSignaturesPerMonth) : 'Unlimited']])));
    }).catch(failInto(c));
    if (state.user.role === 'ADMIN') {
      var text = el('textarea', { placeholder: 'Paste the licence text you received' });
      c.appendChild(el('div', { class: 'card' }, el('h2', null, 'Install licence'), text,
        el('div', { class: 'form-actions' }, el('button', {
          onclick: function () { api('POST', '/api/admin/license', { license: text.value }).then(viewLicense).catch(failInto(c)); }
        }, 'Install'))));
    }
  }

  function viewSetup() {
    var c = shell('#/setup', 'Agent setup');
    api('GET', '/api/admin/overview').then(function (o) {
      c.appendChild(el('div', { class: 'card' }, el('h2', null, '1. Install the Signer Agent on each computer'),
        el('p', null, 'Install the Signer Agent MSI on every computer where users sign with a USB token. It starts automatically at logon and appears in the system tray.'),
        el('p', null, 'Copy the following into C:\\Program Files\\Signer Agent\\agent.properties (or distribute it with the MSI / group policy):'),
        el('pre', null, o.agentConfig)));
      c.appendChild(el('div', { class: 'card' }, el('h2', null, '2. Integrate your web application'),
        el('p', null, 'Your back end requests a transaction token with its API key; the browser passes the token to the agent.'),
        el('pre', null, [
          '// Back end (any language): POST ' + o.publicUrl + '/api/v1/tokens',
          '//   headers: X-API-Key: sk_...      body: {"origin":"https://your-app.example.gov.in","reference":"FILE-123"}',
          '',
          '// Browser',
          '<script src="' + o.publicUrl + '/sdk/signer.js"></script>',
          'const signer = new Signer.SignerClient({',
          '  serverUrl: "' + o.publicUrl + '",',
          '  getToken: () => fetch("/your-backend/esign-token", { method: "POST" }).then(r => r.json()).then(j => j.token)',
          '});',
          'const signed = await signer.signPdfOnServer({ pdf: file, options: { reason: "Approved", page: "last" } });',
          'Signer.download(signed.blob, "signed.pdf");'].join('\n')),
        el('p', null, el('a', { href: '/demo/' }, 'Open the demo page'), ' to try the complete flow.')));
    }).catch(failInto(c));
  }

  // ---------------------------------------------------------------- router

  function render() {
    var hash = location.hash || '#/dashboard';
    if (!state.token) { viewLogin(false); return; }
    if (!state.user) {
      api('GET', '/api/admin/me').then(function (r) { state.user = r.user; render(); }).catch(function () { logout(); });
      return;
    }
    var m = hash.match(/^#\/tenant\/(.+)$/);
    if (m) { viewTenant(decodeURIComponent(m[1])); return; }
    switch (hash) {
      case '#/tenants': viewTenants(); break;
      case '#/transactions': viewTransactions(); break;
      case '#/usage': viewUsage(); break;
      case '#/audit': viewAudit(); break;
      case '#/users': viewUsers(); break;
      case '#/license': viewLicense(); break;
      case '#/setup': viewSetup(); break;
      default: viewDashboard();
    }
  }

  window.addEventListener('hashchange', render);
  state.token = load('signer.admin.token');
  render();
})();
