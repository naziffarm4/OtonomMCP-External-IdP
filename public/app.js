/* OtonomMCP External IdP - approval UI.
 * Security rules: no innerHTML/outerHTML/insertAdjacentHTML/document.write anywhere;
 * every server-provided string is inserted with createTextNode/textContent. */
(function (root) {
  'use strict';

  var state = { csrf: null, user: null, needsSetup: false };

  // ---------- DOM helpers (text-only) ----------
  var SAFE_ATTRS = { id: 1, className: 1, type: 1, name: 1, value: 1, htmlFor: 1, maxLength: 1, placeholder: 1, checked: 1, disabled: 1, autocomplete: 1, rows: 1 };

  function el(doc, tag, attrs) {
    var node = doc.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'href') {
          var h = String(attrs[k]);
          if (h.charAt(0) !== '#') throw new Error('only in-app links allowed');
          node.setAttribute('href', h);
        } else if (k === 'onclick' || k === 'onsubmit' || k === 'onchange') {
          node.addEventListener(k.slice(2), attrs[k]);
        } else if (SAFE_ATTRS[k]) {
          node[k] = attrs[k];
        } else {
          throw new Error('attribute not allowed: ' + k);
        }
      });
    }
    for (var i = 3; i < arguments.length; i++) append(doc, node, arguments[i]);
    return node;
  }

  function append(doc, node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(doc, node, c); }); return; }
    if (typeof child === 'object' && child.nodeType) { node.appendChild(child); return; }
    node.appendChild(doc.createTextNode(String(child)));
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function fmtTime(iso) {
    try { return new Date(iso).toLocaleString('tr-TR'); } catch (e) { return String(iso); }
  }

  function remaining(iso, now) {
    var ms = Date.parse(iso) - (now || Date.now());
    if (!(ms > 0)) return 'süresi doldu';
    var m = Math.floor(ms / 60000), s = Math.floor((ms % 60000) / 1000);
    return m + ' dk ' + s + ' sn kaldı';
  }

  function kvTable(doc, rows) {
    var t = el(doc, 'table', { className: 'kv' });
    rows.forEach(function (r) {
      if (r[1] === undefined || r[1] === null || r[1] === '') return;
      t.appendChild(el(doc, 'tr', null, el(doc, 'td', { className: 'k' }, r[0]), el(doc, 'td', null, String(r[1]))));
    });
    return t;
  }

  function renderSummary(doc, summary) {
    if (summary === undefined || summary === null) return null;
    if (typeof summary === 'string') return el(doc, 'div', { className: 'summary' }, summary);
    return kvTable(doc, Object.keys(summary).map(function (k) {
      var val = summary[k];
      return [k, Array.isArray(val) ? val.join(', ') : val];
    }));
  }

  function statusBadge(doc, s) { return el(doc, 'span', { className: 'status ' + String(s).replace(/[^A-Z]/g, '') }, s); }

  // ---------- pure renderers (exported for tests) ----------
  function renderApprovalDetail(doc, v, handlers) {
    var card = el(doc, 'section', { className: 'card' },
      el(doc, 'h1', null, 'Onay isteği ', statusBadge(doc, v.status)),
      el(doc, 'h2', null, 'Özet'),
      renderSummary(doc, v.summary),
      el(doc, 'h2', null, 'Bağlam (token\'a imzalanacak alanlar)'),
      kvTable(doc, [
        ['requestId', v.requestId], ['projectId', v.projectId], ['packageId', v.packageId], ['revision', v.revision],
        ['operation', v.operation], ['contextFingerprint', v.contextFingerprint], ['specFingerprint', v.specFingerprint],
        ['directorSessionId', v.directorSessionId], ['taskId', v.taskId], ['nonce', v.nonce],
        ['İstek zamanı', fmtTime(v.requestedAt)], ['Son geçerlilik', fmtTime(v.expiresAt) + ' (' + remaining(v.expiresAt) + ')'],
      ]));
    if (v.decision) {
      card.appendChild(el(doc, 'div', { className: 'msg info' },
        'Karar: ' + v.decision.decision + ' — ' + fmtTime(v.decision.decidedAt) + (v.decision.reason ? ' — Gerekçe: ' + v.decision.reason : '')));
    }
    if (v.status === 'PENDING' && handlers) {
      var reason = el(doc, 'textarea', { id: 'reject-reason', maxLength: 1000, placeholder: 'Reddetme gerekçesi (zorunlu)' });
      card.appendChild(el(doc, 'div', null,
        el(doc, 'button', { className: 'ok', type: 'button', id: 'approve-btn', onclick: function () { handlers.approve(); } }, 'Windows Hello ile ONAYLA'),
        el(doc, 'label', { htmlFor: 'reject-reason' }, 'Reddet'),
        reason,
        el(doc, 'button', { className: 'bad', type: 'button', id: 'reject-btn', onclick: function () { handlers.reject(reason.value); } }, 'Reddet')));
    }
    return card;
  }

  function renderDecisionDetail(doc, v, handlers) {
    var card = el(doc, 'section', { className: 'card' },
      el(doc, 'h1', null, 'Karar isteği ', statusBadge(doc, v.status)),
      el(doc, 'h2', { className: 'question' }, v.question),
      renderSummary(doc, v.summary),
      kvTable(doc, [
        ['decisionId', v.decisionId], ['projectId', v.projectId], ['runId', v.runId], ['taskId', v.taskId],
        ['contextFingerprint', v.contextFingerprint], ['nonce', v.nonce],
        ['Son geçerlilik', fmtTime(v.expiresAt) + ' (' + remaining(v.expiresAt) + ')'],
      ]));
    var form = el(doc, 'div', { className: 'options' });
    (v.options || []).forEach(function (o) {
      var input = el(doc, 'input', { type: 'radio', name: 'decision-option', value: o.id, disabled: v.status !== 'PENDING' });
      if (v.answer && v.answer.selectedOptionId === o.id) input.checked = true;
      form.appendChild(el(doc, 'label', { className: 'opt' }, input, ' ', o.label,
        o.id === v.recommendedOptionId ? el(doc, 'span', { className: 'badge' }, 'Önerilen') : null,
        o.description ? el(doc, 'span', { className: 'desc' }, o.description) : null));
    });
    card.appendChild(form);
    var free = null;
    if (v.allowFreeText) {
      free = el(doc, 'textarea', { id: 'free-text', maxLength: v.maxFreeTextLength || 2000, placeholder: 'İsteğe bağlı açıklama / serbest cevap', disabled: v.status !== 'PENDING' });
      card.appendChild(el(doc, 'label', { htmlFor: 'free-text' }, 'Serbest metin (en fazla ' + (v.maxFreeTextLength || 2000) + ' karakter)'));
      card.appendChild(free);
    }
    if (v.answer) {
      card.appendChild(el(doc, 'div', { className: 'msg info' }, 'Cevaplandı: ' + (v.answer.selectedOptionId || '-') +
        (v.answer.freeText ? ' — ' + v.answer.freeText : '') + ' (' + fmtTime(v.answer.answeredAt) + ')'));
    }
    if (v.status === 'PENDING' && handlers) {
      card.appendChild(el(doc, 'button', { className: 'ok', type: 'button', id: 'answer-btn', onclick: function () {
        var sel = null;
        var radios = form.querySelectorAll ? form.querySelectorAll('input[name="decision-option"]') : [];
        for (var i = 0; i < radios.length; i++) if (radios[i].checked) sel = radios[i].value;
        handlers.answer(sel, free ? free.value : '');
      } }, 'Windows Hello ile GÖNDER'));
    }
    return card;
  }

  function renderPending(doc, data) {
    var wrap = el(doc, 'div');
    var a = el(doc, 'ul', { className: 'list' });
    (data.approvals || []).forEach(function (r) {
      a.appendChild(el(doc, 'li', null, el(doc, 'a', { href: '#/approvals/' + encodeURIComponent(r.requestId) }, r.operation + ' — ' + r.projectId),
        ' · ' + remaining(r.expiresAt)));
    });
    var d = el(doc, 'ul', { className: 'list' });
    (data.decisions || []).forEach(function (r) {
      d.appendChild(el(doc, 'li', null, el(doc, 'a', { href: '#/decisions/' + encodeURIComponent(r.decisionId) }, r.question),
        ' · ' + r.projectId + ' · ' + remaining(r.expiresAt)));
    });
    wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Bekleyen onaylar (' + (data.approvals || []).length + ')'),
      (data.approvals || []).length ? a : el(doc, 'p', null, 'Bekleyen onay yok.')));
    wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Bekleyen kararlar (' + (data.decisions || []).length + ')'),
      (data.decisions || []).length ? d : el(doc, 'p', null, 'Bekleyen karar yok.')));
    return wrap;
  }

  // ---------- network ----------
  function api(method, url, body) {
    var headers = { 'Accept': 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (state.csrf && method !== 'GET') headers['X-CSRF-Token'] = state.csrf;
    return fetch(url, { method: method, headers: headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) { var e = new Error(j.message || ('HTTP ' + r.status)); e.code = j.error; e.status = r.status; throw e; }
          return j;
        });
      });
  }

  function wa() {
    if (!root.SimpleWebAuthnBrowser) throw new Error('WebAuthn kütüphanesi yüklenemedi');
    return root.SimpleWebAuthnBrowser;
  }

  // ---------- views ----------
  function view() { return root.document.getElementById('app'); }

  function showError(err) {
    var v = view();
    var box = el(root.document, 'div', { className: 'msg err' }, 'Hata: ' + (err && err.message ? err.message : String(err)));
    v.insertBefore(box, v.firstChild);
  }

  function setWho() {
    var w = root.document.getElementById('who');
    clear(w);
    if (state.user) {
      append(root.document, w, state.user.displayName + ' (' + state.user.role + ') ');
      w.appendChild(el(root.document, 'button', { className: 'link', type: 'button', onclick: function () {
        api('POST', '/api/auth/logout', {}).then(function () { state.user = null; state.csrf = null; route(); });
      } }, 'Çıkış'));
    }
  }

  function loadState() {
    return api('GET', '/api/ui/state').then(function (s) { state.needsSetup = s.needsSetup; state.user = s.user; state.csrf = s.csrfToken; setWho(); });
  }

  function showSetup() {
    var doc = root.document, v = view();
    clear(v);
    var code = el(doc, 'input', { type: 'text', id: 'setup-code', autocomplete: 'off', placeholder: 'XXXXXX-XXXXXX-XXXXXX' });
    var user = el(doc, 'input', { type: 'text', id: 'setup-user', autocomplete: 'username', placeholder: 'nazif' });
    var disp = el(doc, 'input', { type: 'text', id: 'setup-display', placeholder: 'Nazif Açıkgöz' });
    v.appendChild(el(doc, 'section', { className: 'card' },
      el(doc, 'h1', null, 'İlk kurulum'),
      el(doc, 'p', null, 'Sunucu konsolunda yazan tek kullanımlık kurulum kodunu girin, ardından Windows Hello ile passkey oluşturun.'),
      el(doc, 'label', { htmlFor: 'setup-code' }, 'Kurulum kodu'), code,
      el(doc, 'label', { htmlFor: 'setup-user' }, 'Kullanıcı adı'), user,
      el(doc, 'label', { htmlFor: 'setup-display' }, 'Görünen ad'), disp,
      el(doc, 'p', null, el(doc, 'button', { type: 'button', id: 'setup-btn', onclick: function () {
        api('POST', '/api/setup/options', { setupCode: code.value, username: user.value, displayName: disp.value })
          .then(function (opts) { return wa().startRegistration({ optionsJSON: opts }); })
          .then(function (resp) { return api('POST', '/api/setup/verify', { response: resp }); })
          .then(function () { return loadState(); }).then(route).catch(showError);
      } }, 'Passkey oluştur (Windows Hello)'))));
  }

  function showLogin() {
    var doc = root.document, v = view();
    clear(v);
    v.appendChild(el(doc, 'section', { className: 'card' },
      el(doc, 'h1', null, 'Giriş'),
      el(doc, 'p', null, 'Parola yok: yalnızca passkey (Windows Hello / güvenlik anahtarı) ile giriş.'),
      el(doc, 'button', { type: 'button', id: 'login-btn', onclick: function () {
        api('POST', '/api/auth/login/options', {})
          .then(function (opts) { return wa().startAuthentication({ optionsJSON: opts }); })
          .then(function (resp) { return api('POST', '/api/auth/login/verify', { response: resp }); })
          .then(function () { return loadState(); }).then(route).catch(showError);
      } }, 'Passkey ile giriş yap')));
  }

  function showHome() {
    var doc = root.document, v = view();
    return api('GET', '/api/ui/pending').then(function (data) {
      clear(v);
      v.appendChild(renderPending(doc, data));
      v.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Passkey yönetimi'),
        el(doc, 'button', { type: 'button', id: 'add-passkey', onclick: function () {
          api('POST', '/api/passkeys/options', {})
            .then(function (opts) { return wa().startRegistration({ optionsJSON: opts }); })
            .then(function (resp) { return api('POST', '/api/passkeys/verify', { response: resp }); })
            .then(function () { root.alert('Yeni passkey eklendi.'); }).catch(showError);
        } }, 'Yedek passkey ekle')));
    });
  }

  function showApproval(id) {
    var doc = root.document, v = view();
    var base = '/api/ui/approvals/' + encodeURIComponent(id);
    return api('GET', base).then(function (data) {
      clear(v);
      v.appendChild(renderApprovalDetail(doc, data, {
        approve: function () {
          api('POST', base + '/options', {})
            .then(function (opts) { return wa().startAuthentication({ optionsJSON: opts }); })
            .then(function (assertion) { return api('POST', base + '/approve', { assertion: assertion }); })
            .then(function () { return showApproval(id); }).catch(showError);
        },
        reject: function (reason) {
          api('POST', base + '/reject', { reason: reason }).then(function () { return showApproval(id); }).catch(showError);
        },
      }));
    });
  }

  function showDecision(id) {
    var doc = root.document, v = view();
    var base = '/api/ui/decisions/' + encodeURIComponent(id);
    return api('GET', base).then(function (data) {
      clear(v);
      v.appendChild(renderDecisionDetail(doc, data, {
        answer: function (sel, freeText) {
          api('POST', base + '/options', {})
            .then(function (opts) { return wa().startAuthentication({ optionsJSON: opts }); })
            .then(function (assertion) { return api('POST', base + '/answer', { selectedOptionId: sel, freeText: freeText, assertion: assertion }); })
            .then(function () { return showDecision(id); }).catch(showError);
        },
      }));
    });
  }

  function route() {
    var h = root.location.hash || '#/';
    var p;
    if (state.needsSetup) return showSetup();
    if (!state.user) return showLogin();
    if ((p = /^#\/approvals\/([0-9a-fA-F-]{36})$/.exec(h))) return showApproval(p[1]).catch(showError);
    if ((p = /^#\/decisions\/([0-9a-fA-F-]{36})$/.exec(h))) return showDecision(p[1]).catch(showError);
    return showHome().catch(showError);
  }

  var exported = { el: el, renderApprovalDetail: renderApprovalDetail, renderDecisionDetail: renderDecisionDetail, renderPending: renderPending, remaining: remaining };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;

  if (root.document && !root.__IDP_TEST__) {
    root.addEventListener('hashchange', route);
    root.addEventListener('DOMContentLoaded', function () { loadState().then(route).catch(showError); });
  }
})(typeof window !== 'undefined' ? window : globalThis);
