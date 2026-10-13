/* OtonomMCP External IdP - approval UI.
 * Security rules: no innerHTML/outerHTML/insertAdjacentHTML/document.write anywhere;
 * every server-provided string is inserted with createTextNode/textContent. */
(function (root) {
  'use strict';

  var state = { csrf: null, user: null, needsSetup: false };

  // ---------- DOM helpers (text-only) ----------
  var SAFE_ATTRS = { selected: 1, max: 1, id: 1, className: 1, type: 1, name: 1, value: 1, htmlFor: 1, maxLength: 1, placeholder: 1, checked: 1, disabled: 1, autocomplete: 1, rows: 1, alt: 1, loading: 1 };

  function el(doc, tag, attrs) {
    var node = doc.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'href') {
          var h = String(attrs[k]);
          if (h.charAt(0) !== '#') throw new Error('only in-app links allowed');
          node.setAttribute('href', h);
        } else if (k === 'src') {
          var u = String(attrs[k]);
          if (tag !== 'img' || u.indexOf('/api/ui/runs/') !== 0) throw new Error('only run screenshot images allowed');
          node.setAttribute('src', u);
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
        ['packageId', v.packageId], ['revision', v.revision], ['operation', v.operation],
        ['contextFingerprint', v.contextFingerprint], ['nonce', v.nonce],
        ['Son geçerlilik', fmtTime(v.expiresAt) + ' (' + remaining(v.expiresAt) + ')'],
      ]));
    if (v.questions && v.questions.length) return renderClarification(doc, v, card, handlers);
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

  /** SPEC_CLARIFICATION: several questions, each with 2-4 options (+ the acceptance criteria each implies). */
  function renderClarification(doc, v, card, handlers) {
    var pending = v.status === 'PENDING';
    var given = {};
    ((v.answer && v.answer.answers) || []).forEach(function (a) { given[a.questionId] = a; });
    card.appendChild(el(doc, 'p', { className: 'msg info' },
      'Director spec\'i inceledi ve uygulamaya başlamadan önce bu noktaların netleşmesini istiyor. Önerilen seçenekler işaretli; ' +
      'her seçeneğin altındaki maddeler, o seçenekle görevlere eklenecek ölçülebilir kabul kriterleridir. Hepsini tek seferde Windows Hello ile gönderirsin.'));
    var blocks = [];
    var ordered = v.questions.map(function (q, qi) { return { q: q, qi: qi }; });
    var clar = ordered.filter(function (x) { return x.q.kind !== 'IMPROVEMENT'; });
    var impr = ordered.filter(function (x) { return x.q.kind === 'IMPROVEMENT'; });
    var n = 0;
    [[clar, 'Netleştirilecek noktalar'], [impr, 'Önerilen iyileştirmeler']].forEach(function (sec) {
      if (!sec[0].length) return;
      card.appendChild(el(doc, 'h2', null, sec[1]));
      sec[0].forEach(function (x) { addQuestion(x.q, x.qi, ++n); });
    });
    function addQuestion(q, qi, num) {
      var box = el(doc, 'fieldset', { className: 'card question-block' });
      box.appendChild(el(doc, 'legend', null, num + '. ' + q.question));
      if (q.reason) box.appendChild(el(doc, 'p', { className: 'desc' }, 'Neden soruyorum: ' + q.reason));
      var name = 'q-' + qi;
      q.options.forEach(function (o) {
        var checked = given[q.id] ? given[q.id].selectedOptionId === o.id : (pending && o.id === q.recommendedOptionId);
        var input = el(doc, 'input', { type: 'radio', name: name, value: o.id, disabled: !pending, checked: !!checked });
        var crit = null;
        if (o.criteria && o.criteria.length) {
          crit = el(doc, 'ul', { className: 'criteria' });
          o.criteria.forEach(function (c) { crit.appendChild(el(doc, 'li', null, c)); });
        }
        box.appendChild(el(doc, 'label', { className: 'opt' }, input, ' ', o.label,
          o.id === q.recommendedOptionId ? el(doc, 'span', { className: 'badge' }, 'Önerilen') : null,
          o.description ? el(doc, 'span', { className: 'desc' }, o.description) : null, crit));
      });
      var free = null;
      if (q.allowFreeText) {
        free = el(doc, 'textarea', { maxLength: v.maxFreeTextLength || 2000, placeholder: 'İsteğe bağlı not / farklı bir cevap', disabled: !pending, rows: 2 });
        if (given[q.id] && given[q.id].freeText) free.value = given[q.id].freeText;
        box.appendChild(free);
      }
      blocks.push({ q: q, box: box, name: name, free: free });
      card.appendChild(box);
    }
    if (v.answer) card.appendChild(el(doc, 'div', { className: 'msg info' }, 'Cevaplandı (' + fmtTime(v.answer.answeredAt) + ')'));
    if (pending && handlers) {
      card.appendChild(el(doc, 'button', { className: 'ok', type: 'button', id: 'answer-btn', onclick: function () {
        var answers = blocks.map(function (b) {
          var sel = null;
          var radios = b.box.querySelectorAll ? b.box.querySelectorAll('input[name="' + b.name + '"]') : [];
          for (var i = 0; i < radios.length; i++) if (radios[i].checked) sel = radios[i].value;
          var a = { questionId: b.q.id };
          if (sel) a.selectedOptionId = sel;
          if (b.free && b.free.value) a.freeText = b.free.value;
          return a;
        });
        handlers.answerAll(answers);
      } }, 'Tümünü Windows Hello ile GÖNDER'));
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
      d.appendChild(el(doc, 'li', null, el(doc, 'a', { href: '#/decisions/' + encodeURIComponent(r.decisionId) }, (r.operation === 'SPEC_CLARIFICATION' ? 'Spec netleştirme: ' : '') + r.question),
        ' · ' + r.projectId + ' · ' + remaining(r.expiresAt)));
    });
    wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Bekleyen onaylar (' + (data.approvals || []).length + ')'),
      (data.approvals || []).length ? a : el(doc, 'p', null, 'Bekleyen onay yok.')));
    wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Bekleyen kararlar (' + (data.decisions || []).length + ')'),
      (data.decisions || []).length ? d : el(doc, 'p', null, 'Bekleyen karar yok.')));
    return wrap;
  }

  // ---------- run monitor renderers (read-only, informational) ----------
  var RUN_STATUS_TR = {
    PENDING_APPROVAL: 'Onay bekliyor', RUNNING: 'Çalışıyor', BLOCKED_ON_HUMAN: 'İnsan bekliyor', WAITING_DECISION: 'Karar bekliyor',
    COMPLETED: 'Tamamlandı', FAILED: 'Başarısız', STOPPED: 'Durduruldu', CONFIGURATION_ERROR: 'Yapılandırma hatası', REJECTED: 'Reddedildi',
  };
  function runBadge(doc, s) { return el(doc, 'span', { className: 'status run-' + String(s).replace(/[^A-Z_]/g, '') }, RUN_STATUS_TR[s] || String(s)); }
  function usd(n) { return typeof n === 'number' && isFinite(n) ? '$' + n.toFixed(2) : '-'; }
  function ageSeconds(serverTime, receivedAt) {
    var d = Math.round((Date.parse(serverTime) - Date.parse(receivedAt)) / 1000);
    return isFinite(d) && d > 0 ? d : 0;
  }
  function ageText(sec) {
    if (sec < 60) return sec + ' sn önce';
    if (sec < 3600) return Math.floor(sec / 60) + ' dk ' + (sec % 60) + ' sn önce';
    return Math.floor(sec / 3600) + ' sa önce';
  }
  function isStale(run, serverTime) { return run.status === 'RUNNING' && ageSeconds(serverTime, run.receivedAt) > 120; }

  function budgetBar(doc, b) {
    if (!b) return el(doc, 'span', null, '-');
    var used = (b.committedUsd || 0) + (b.reservedUsd || 0);
    var pct = b.limitUsd > 0 ? Math.min(100, Math.max(0, Math.round((used / b.limitUsd) * 100))) : 0;
    var bar = el(doc, 'progress', { className: 'budget', max: 100, value: pct });
    return el(doc, 'span', { className: 'budget-wrap' }, bar, ' ' + usd(b.committedUsd) + ' harcandı + ' + usd(b.reservedUsd) + ' ayrıldı / ' + usd(b.limitUsd) + ' (%' + pct + ')');
  }

  function renderRunsList(doc, data, opts) {
    var runs = (data && data.runs) || [];
    var title = opts && opts.activeOnly ? 'Aktif çalıştırmalar (' + runs.length + ')' : 'Otonom çalıştırmalar (' + runs.length + ')';
    var card = el(doc, 'section', { className: 'card runs' }, el(doc, 'h2', null, title));
    if (!runs.length) { card.appendChild(el(doc, 'p', null, opts && opts.activeOnly ? 'Şu an aktif çalıştırma yok.' : 'Henüz çalıştırma yok.')); }
    else {
      var t = el(doc, 'table', { className: 'kv' },
        el(doc, 'tr', null, el(doc, 'td', { className: 'k' }, 'Proje'), el(doc, 'td', { className: 'k' }, 'Durum'), el(doc, 'td', { className: 'k' }, 'Bütçe'),
          el(doc, 'td', { className: 'k' }, 'Mevcut görev'), el(doc, 'td', { className: 'k' }, 'Son güncelleme'), el(doc, 'td', { className: 'k' }, '')));
      runs.forEach(function (r) {
        var b = r.budget;
        t.appendChild(el(doc, 'tr', null,
          el(doc, 'td', null, el(doc, 'a', { href: '#/runs/' + encodeURIComponent(r.runId) }, r.projectName || r.projectId || r.runId)),
          el(doc, 'td', null, runBadge(doc, r.status), isStale(r, data.serverTime) ? el(doc, 'span', { className: 'badge warn' }, 'bağlantı yok?') : null),
          el(doc, 'td', null, b ? usd((b.committedUsd || 0) + (b.reservedUsd || 0)) + ' / ' + usd(b.limitUsd) : '-'),
          el(doc, 'td', null, r.currentTaskId || '-'),
          el(doc, 'td', null, ageText(ageSeconds(data.serverTime, r.receivedAt))),
          el(doc, 'td', null, r.deletable && opts && opts.onDelete ? el(doc, 'button', { type: 'button', className: 'danger small', id: 'del-' + r.runId, onclick: function () { opts.onDelete(r); } }, 'Sil') : null)));
      });
      card.appendChild(t);
      var nDel = runs.filter(function (r) { return r.deletable; }).length;
      if (nDel && opts && opts.onCleanup) card.appendChild(el(doc, 'p', null, el(doc, 'button', { type: 'button', className: 'danger', id: 'runs-cleanup', onclick: function () { opts.onCleanup(nDel); } }, 'Bitmiş ve bayat çalıştırmaları temizle (' + nDel + ')')));
    }
    if (opts && opts.activeOnly) card.appendChild(el(doc, 'p', null, el(doc, 'a', { href: '#/runs' }, 'Tüm çalıştırmalar →')));
    return card;
  }

  var RESUME_STATUS_TR = { PENDING: 'OtonomMCP izleyicisinin almasını bekliyor', CLAIMED: 'Alındı, başlatılıyor', APPROVED: 'Onaylandı, çalışma devam ediyor', STARTED: 'Başlatıldı', FAILED: 'Başlatılamadı', EXPIRED: 'Süresi doldu (izleyici çalışmıyor olabilir)' };
  /** "Kaldığı yerden devam et" card for stopped runs; handlers.resume() asks for the passkey. */
  function renderResume(doc, r, handlers) {
    var card = el(doc, 'section', { className: 'card resume' }, el(doc, 'h2', null, 'Kaldığı yerden devam'));
    if (r.canResume) {
      card.appendChild(el(doc, 'p', null, 'Çalışma durdu. Passkey ile onaylarsan OtonomMCP aynı çalıştırmayı (' + r.runId + ') arka planda kaldığı yerden sürdürür; Antigravity gerekmez.'));
      if (handlers && handlers.resume) card.appendChild(el(doc, 'p', null, el(doc, 'button', { type: 'button', id: 'run-resume', onclick: function () { handlers.resume(); } }, 'Kaldığı yerden devam et')));
    } else if (r.reason && r.pending) {
      card.appendChild(el(doc, 'p', null, r.reason));
    }
    if (r.pending) {
      card.appendChild(kvTable(doc, [['Son devam isteği', RESUME_STATUS_TR[r.pending.status] || r.pending.status], ['Zaman', fmtTime(r.pending.createdAt)], ['Not', r.pending.note]]));
    }
    if (!r.canResume && !r.pending) return el(doc, 'span', null);
    return card;
  }

  var INSTR_STATUS_TR = { PENDING_DELIVERY: 'İletilmeyi bekliyor', RECEIVED: 'Alındı', APPLIED: 'Uygulandı', REJECTED: 'Reddedildi', EXPIRED: 'Süresi doldu' };
  var MODE_TR = { NOTE: 'Sadece not', PAUSE_AND_APPLY: 'Duraklat ve uygula', STOP: 'Durdur', ASK: 'Soru sor' };

  /** Instruction form + list. handlers: { draft:{mode,text,taskId}, send(draft) }. */
  function renderInstructions(doc, data, handlers) {
    var s = (data.run && data.run.snapshot) || {};
    var ch = data.instructionChannel || { canInstruct: false };
    var card = el(doc, 'section', { className: 'card instructions' }, el(doc, 'h2', null, "Director'a talimat ver"));
    if (ch.canInstruct && handlers) {
      var draft = handlers.draft || (handlers.draft = { mode: 'NOTE', text: '', taskId: '' });
      var radios = el(doc, 'div', { className: 'modes' });
      ['NOTE', 'PAUSE_AND_APPLY', 'STOP', 'ASK'].forEach(function (m) {
        var r = el(doc, 'input', { type: 'radio', name: 'instr-mode', value: m, checked: draft.mode === m,
          onchange: function () { draft.mode = m; } });
        radios.appendChild(el(doc, 'label', { className: 'opt' }, r, ' ' + MODE_TR[m]));
      });
      var ta = el(doc, 'textarea', { id: 'instr-text', maxLength: 2000, placeholder: 'ör. "dur, iletişim formu ekle" / "başlık rengini düzelt"', value: draft.text });
      ta.addEventListener('input', function () { draft.text = ta.value; });
      var sel = el(doc, 'select', { id: 'instr-task', onchange: function () { draft.taskId = sel.value; } },
        el(doc, 'option', { value: '' }, '(görev seçilmedi — genel talimat)'));
      (s.tasks || []).forEach(function (t) {
        var o = el(doc, 'option', { value: t.taskId }, t.taskId + ' — ' + t.title);
        if (draft.taskId === t.taskId) o.selected = true;
        sel.appendChild(o);
      });
      card.appendChild(el(doc, 'p', { className: 'muted' }, 'Talimat Windows Hello ile imzalanır; mühürlü yetkinin (dosya yolları, bütçe) dışına çıkan işler için ayrıca onay istenir.'));
      card.appendChild(radios);
      card.appendChild(el(doc, 'label', { htmlFor: 'instr-text' }, 'Talimat (en fazla 2000 karakter; Durdur için isteğe bağlı)'));
      card.appendChild(ta);
      card.appendChild(el(doc, 'label', { htmlFor: 'instr-task' }, 'Hedef görev (isteğe bağlı)'));
      card.appendChild(sel);
      card.appendChild(el(doc, 'p', null, el(doc, 'button', { className: 'ok', type: 'button', id: 'instr-send', onclick: function () {
        handlers.send({ mode: draft.mode, text: ta.value, taskId: sel.value || null });
      } }, 'Windows Hello ile GÖNDER')));
    } else {
      card.appendChild(el(doc, 'p', { className: 'muted' }, 'Bu çalıştırma şu an talimat kabul etmiyor (kanal kapalı veya çalıştırma bitti).'));
    }
    var list = el(doc, 'ul', { className: 'list instr-list' });
    (data.instructions || []).forEach(function (i) {
      list.appendChild(el(doc, 'li', null,
        el(doc, 'span', { className: 'status instr-' + String(i.status).replace(/[^A-Z_]/g, '') }, INSTR_STATUS_TR[i.status] || i.status), ' ',
        el(doc, 'strong', null, MODE_TR[i.mode] || i.mode), i.taskId ? ' [' + i.taskId + ']' : '', ' · ' + fmtTime(i.createdAt),
        i.text ? el(doc, 'div', { className: 'summary' }, i.text) : null,
        i.answer ? el(doc, 'div', { className: 'summary answer' }, el(doc, 'strong', null, "Director'ın yanıtı: "), i.answer) : null,
        i.mode === 'ASK' && !i.answer && (i.status === 'PENDING_DELIVERY' || i.status === 'RECEIVED') ? el(doc, 'div', { className: 'muted' }, 'Yanıt bekleniyor… (çalışma durmaz)') : null,
        i.note ? el(doc, 'div', { className: 'muted' }, 'Not: ' + i.note) : null));
    });
    card.appendChild(el(doc, 'h2', null, 'Gönderilen talimatlar (' + (data.instructions || []).length + ')'));
    card.appendChild((data.instructions || []).length ? list : el(doc, 'p', null, 'Henüz talimat yok.'));
    return card;
  }

  function renderReport(doc, runId, rep) {
    var sec = el(doc, 'section', { className: 'card', id: 'run-report' }, el(doc, 'h2', null, 'Tamamlama raporu'));
    if (rep.summary) sec.appendChild(el(doc, 'div', { className: 'summary report-text' }, rep.summary));
    var shots = rep.screenshots || [];
    if (shots.length) {
      var g = el(doc, 'div', { className: 'shots' });
      shots.forEach(function (x) {
        g.appendChild(el(doc, 'figure', { className: 'shot' },
          el(doc, 'img', { src: '/api/ui/runs/' + encodeURIComponent(runId) + '/screenshots/' + encodeURIComponent(x.name), alt: x.caption, loading: 'lazy' }),
          el(doc, 'figcaption', null, x.caption)));
      });
      sec.appendChild(el(doc, 'h2', null, 'Ekran görüntüleri'));
      sec.appendChild(g);
    }
    return sec;
  }

  function renderRunDetail(doc, data, handlers) {
    var run = data.run, s = run.snapshot || {};
    var wrap = el(doc, 'div', { className: 'run-detail' });
    var age = ageSeconds(data.serverTime, run.receivedAt);
    var head = el(doc, 'section', { className: 'card' },
      el(doc, 'h1', null, (run.projectName || run.projectId || run.runId) + ' ', runBadge(doc, run.status)),
      el(doc, 'p', { className: 'muted', id: 'run-age' }, 'Son güncelleme ' + ageText(age) + ' · bilgi amaçlıdır, onay/karar yerine geçmez'),
      isStale(run, data.serverTime) ? el(doc, 'div', { className: 'msg err', id: 'run-stale' }, 'Bağlantı yok / duraklamış olabilir: 2 dakikadan uzun süredir güncelleme gelmedi.') : null,
      run.deletable && handlers && handlers.onDelete ? el(doc, 'p', null, el(doc, 'button', { type: 'button', className: 'danger', id: 'run-delete', onclick: function () { handlers.onDelete(run); } }, 'Bu çalıştırmayı sil')) : null,
      kvTable(doc, [
        ['runId', run.runId], ['Proje', s.projectId || run.projectId], ['Giriş noktası', s.entryPoint], ['Model', s.model],
        ['Başlangıç', s.startedAt ? fmtTime(s.startedAt) : ''], ['Bitiş', s.finishedAt ? fmtTime(s.finishedAt) : ''],
        ['Mevcut görev', s.currentTaskId], ['Durma nedeni', s.stopReason],
      ]),
      el(doc, 'h2', null, 'Bütçe'), budgetBar(doc, s.budget));
    wrap.appendChild(head);
    if (data.report) wrap.appendChild(renderReport(doc, run.runId, data.report));
    var links = el(doc, 'div', null);
    if (s.pendingApprovalId) links.appendChild(el(doc, 'p', null, el(doc, 'a', { href: '#/approvals/' + encodeURIComponent(s.pendingApprovalId) }, 'Bekleyen onaya git →')));
    (s.pendingDecisionIds || []).forEach(function (id) {
      links.appendChild(el(doc, 'p', null, el(doc, 'a', { href: '#/decisions/' + encodeURIComponent(id) }, 'Bekleyen karara git →')));
    });
    if (links.firstChild) wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Senden beklenenler'), links));
    var tasks = s.tasks || [];
    var tt = el(doc, 'table', { className: 'kv tasks' }, el(doc, 'tr', null, el(doc, 'td', { className: 'k' }, 'Görev'), el(doc, 'td', { className: 'k' }, 'Durum'),
      el(doc, 'td', { className: 'k' }, 'Döngü'), el(doc, 'td', { className: 'k' }, 'Son özet')));
    tasks.forEach(function (t) {
      tt.appendChild(el(doc, 'tr', { className: t.taskId === s.currentTaskId ? 'current' : '' },
        el(doc, 'td', null, t.taskId + ' — ' + t.title), el(doc, 'td', null, t.status),
        el(doc, 'td', null, String(t.cycles) + (t.maxAttempts !== null && t.maxAttempts !== undefined ? ' / ' + t.maxAttempts : '')),
        el(doc, 'td', null, t.lastSummary || '')));
    });
    if (data.resume) wrap.appendChild(renderResume(doc, data.resume, handlers));
    if (data.instructionChannel || data.instructions) wrap.appendChild(renderInstructions(doc, data, handlers));
    wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Görevler (' + tasks.length + ')'), tasks.length ? tt : el(doc, 'p', null, 'Görev bilgisi yok.')));
    if (s.lastDirectorAction) {
      var a = s.lastDirectorAction;
      wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Son Director kararı'),
        kvTable(doc, [['Eylem', a.actionType], ['Görev', a.taskId], ['Zaman', fmtTime(a.at)]]),
        el(doc, 'div', { className: 'summary' }, a.rationale)));
    }
    var tl = el(doc, 'ul', { className: 'list timeline' });
    (data.events || []).forEach(function (e) {
      tl.appendChild(el(doc, 'li', { className: 'ev ' + (e.level === 'error' ? 'error' : e.level === 'warn' ? 'warn' : 'info') },
        el(doc, 'span', { className: 'muted' }, fmtTime(e.at) + ' · #' + e.seq + ' · '), el(doc, 'strong', null, e.type),
        e.taskId ? ' [' + e.taskId + ']' : '', ' — ' + e.message));
    });
    wrap.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Zaman çizelgesi (en yeni üstte)'),
      (data.events || []).length ? tl : el(doc, 'p', null, 'Henüz olay yok.')));
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
      return api('GET', '/api/ui/runs?active=1').catch(function () { return { runs: [] }; }).then(function (runs) {
      clear(v);
      v.appendChild(renderPending(doc, data));
      v.appendChild(renderRunsList(doc, runs, { activeOnly: true, onDelete: runsOpts.onDelete }));
      v.appendChild(el(doc, 'section', { className: 'card' }, el(doc, 'h2', null, 'Passkey yönetimi'),
        el(doc, 'button', { type: 'button', id: 'add-passkey', onclick: function () {
          api('POST', '/api/passkeys/options', {})
            .then(function (opts) { return wa().startRegistration({ optionsJSON: opts }); })
            .then(function (resp) { return api('POST', '/api/passkeys/verify', { response: resp }); })
            .then(function () { root.alert('Yeni passkey eklendi.'); }).catch(showError);
        } }, 'Yedek passkey ekle')));
      });
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
        answerAll: function (answers) {
          api('POST', base + '/options', {})
            .then(function (opts) { return wa().startAuthentication({ optionsJSON: opts }); })
            .then(function (assertion) { return api('POST', base + '/answer', { answers: answers, assertion: assertion }); })
            .then(function () { return showDecision(id); }).catch(showError);
        },
      }));
    });
  }

  var pollTimer = null;
  function stopPolling() { if (pollTimer) { root.clearInterval(pollTimer); pollTimer = null; } }
  /** Re-render every 3 s while the tab is visible and the route is unchanged. */
  function startPolling(hash, fn) {
    stopPolling();
    pollTimer = root.setInterval(function () {
      if ((root.location.hash || '#/') !== hash) { stopPolling(); return; }
      if (root.document.visibilityState && root.document.visibilityState !== 'visible') return;
      if (confirmOpen) return;
      fn().catch(function () { /* keep last view; staleness warning covers it */ });
    }, 3000);
  }

  /** In-page confirm dialog (no window.confirm). Polling pauses while it is open. */
  var confirmOpen = false;
  function askConfirm(title, text, yesLabel, onYes) {
    var doc = root.document, v = view();
    var box = el(doc, 'section', { className: 'card confirm', id: 'confirm-box' },
      el(doc, 'h2', null, title), el(doc, 'p', null, text));
    function close() { confirmOpen = false; if (box.parentNode) box.parentNode.removeChild(box); }
    box.appendChild(el(doc, 'p', null,
      el(doc, 'button', { type: 'button', className: 'danger', id: 'confirm-yes', onclick: function () { close(); onYes(); } }, yesLabel),
      el(doc, 'button', { type: 'button', className: 'link', id: 'confirm-no', onclick: close }, 'Vazgeç')));
    confirmOpen = true;
    if (v.firstChild) v.insertBefore(box, v.firstChild); else v.appendChild(box);
    if (root.scrollTo) root.scrollTo(0, 0);
  }
  function deleteRun(run, after) {
    var name = run.projectName || run.projectId || run.runId;
    askConfirm('Çalıştırma silinsin mi?',
      '"' + name + '" (' + run.runId + ') IdP arayüzünden silinecek; olay geçmişi ve talimatları da silinir. Bu işlem geri alınamaz ve çalışmanın kendisini (OtonomMCP) durdurmaz.',
      'Evet, sil', function () { api('DELETE', '/api/ui/runs/' + encodeURIComponent(run.runId)).then(after).catch(showError); });
  }
  var runsOpts = {
    onDelete: function (r) { deleteRun(r, function () { return route(); }); },
    onCleanup: function (n) {
      askConfirm('Temizlik', n + ' bitmiş/bayat çalıştırma IdP arayüzünden silinecek. Bu işlem geri alınamaz.', 'Evet, temizle',
        function () { api('POST', '/api/ui/runs/cleanup', {}).then(function () { return route(); }).catch(showError); });
    },
  };
  function showRuns() {
    var doc = root.document, v = view();
    return api('GET', '/api/ui/runs').then(function (data) { clear(v); v.appendChild(renderRunsList(doc, data, runsOpts)); });
  }
  var instrHandlers = null;
  function showRun(id) {
    var doc = root.document, v = view();
    if (!instrHandlers || instrHandlers.runId !== id) {
      instrHandlers = { runId: id, draft: null, busy: false, send: function (d) {
        if (instrHandlers.busy) return;
        instrHandlers.busy = true;
        var base = '/api/ui/runs/' + encodeURIComponent(id) + '/instructions';
        api('POST', base + '/options', { mode: d.mode, text: d.text, taskId: d.taskId })
          .then(function (r) {
            return wa().startAuthentication({ optionsJSON: r.options }).then(function (assertion) {
              return api('POST', base + '/' + encodeURIComponent(r.instructionId), { assertion: assertion });
            });
          })
          .then(function () { instrHandlers.draft = null; return showRun(id); })
          .catch(showError)
          .then(function () { instrHandlers.busy = false; });
      }, onDelete: function (run) { deleteRun(run, function () { root.location.hash = '#/runs'; }); },
      resume: function () {
        if (instrHandlers.busy) return;
        instrHandlers.busy = true;
        var base = '/api/ui/runs/' + encodeURIComponent(id) + '/resume';
        api('POST', base + '/options', {})
          .then(function (r) {
            return wa().startAuthentication({ optionsJSON: r.options }).then(function (assertion) {
              return api('POST', base + '/' + encodeURIComponent(r.resumeId), { assertion: assertion });
            });
          })
          .catch(showError)
          .then(function () { instrHandlers.busy = false; return showRun(id); });
      } };
    }
    // Don't re-render under the user's cursor while a passkey prompt is open or the textarea has focus.
    if (instrHandlers.busy || (doc.activeElement && doc.activeElement.id && /^instr-/.test(doc.activeElement.id) && v.firstChild)) {
      return Promise.resolve();
    }
    return api('GET', '/api/ui/runs/' + encodeURIComponent(id)).then(function (data) { clear(v); v.appendChild(renderRunDetail(doc, data, instrHandlers)); });
  }

  function route() {
    var h = root.location.hash || '#/';
    var p;
    stopPolling();
    confirmOpen = false;
    if (state.needsSetup) return showSetup();
    if (!state.user) return showLogin();
    if ((p = /^#\/approvals\/([0-9a-fA-F-]{36})$/.exec(h))) return showApproval(p[1]).catch(showError);
    if ((p = /^#\/decisions\/([0-9a-fA-F-]{36})$/.exec(h))) return showDecision(p[1]).catch(showError);
    if (h === '#/runs') { startPolling(h, showRuns); return showRuns().catch(showError); }
    if ((p = /^#\/runs\/([A-Za-z0-9._:%-]{1,400})$/.exec(h))) {
      var rid = decodeURIComponent(p[1]);
      startPolling(h, function () { return showRun(rid); });
      return showRun(rid).catch(showError);
    }
    startPolling(h, showHome);
    return showHome().catch(showError);
  }

  var exported = { el: el, renderApprovalDetail: renderApprovalDetail, renderDecisionDetail: renderDecisionDetail, renderPending: renderPending, remaining: remaining, renderRunsList: renderRunsList, renderRunDetail: renderRunDetail, renderInstructions: renderInstructions, renderResume: renderResume };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;

  if (root.document && !root.__IDP_TEST__) {
    root.addEventListener('hashchange', route);
    root.addEventListener('DOMContentLoaded', function () { loadState().then(route).catch(showError); });
  }
})(typeof window !== 'undefined' ? window : globalThis);
