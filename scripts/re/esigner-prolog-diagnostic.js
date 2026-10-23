/* Passive, in-memory diagnostics. Paste in DevTools on the named GDT portal,
 * then initiate the normal signing action yourself. No requests are generated,
 * changed or retried. No XML, credentials, URLs, filenames or raw errors retained.
 * Export: JSON.stringify(TokenSignerProlog.snapshot(), null, 2)
 * Stop: TokenSignerProlog.restore() (also automatic after five minutes).
 */
(() => {
  'use strict';
  if (location.protocol !== 'https:' || !['dichvucong.gdt.gov.vn', 'thuedientu.gdt.gov.vn'].includes(location.hostname))
    throw new Error('Open the exact GDT portal before installing diagnostics.');
  if (window.TokenSignerProlog) throw new Error('Diagnostics already installed; reload to start again.');
  const MAX_BYTES = 20 << 20, MAX_RECORDS = 48;
  const records = [], pending = new Set(), listeners = [];
  const originalFetch = window.fetch, originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send, originalWS = WebSocket.prototype.send;
  const xhrs = new WeakMap(), sockets = new WeakSet();
  const enc = new TextEncoder(), dec = new TextDecoder('utf-8', {fatal: true});
  const commands = new Set(['CER_001', 'NTDT_CER_001', 'ONLINE_XML_CER_001', 'ONLINE_SUBMIT_SIGNING_001',
    'CHOOSE_FILE', 'OFFLINE_XML_SIGN_002', 'OFFLINE_XML_SIGN_003']);
  const xmlFields = new Set(['dataFile', 'VALUE', 'BASE64_VALUE', 'SIGNED_CONTENT', 'xml', 'xmlData', 'dataXML', 'file', 'fileData', 'content']);
  let active = true, signingSeen = false, nextID = 0, timer;
  function route(value) {
    try {
      const u = new URL(value, location.href);
      if (['127.0.0.1', 'localhost'].includes(u.hostname)) {
        if (u.port === '32001' && u.pathname.toLowerCase() === '/api/hubclient/signxml') return 'ctsign';
        if (['8768', '8769'].includes(u.port) && u.pathname === '/plugin/sign') return 'esigner';
      }
      if (u.origin === location.origin) return 'portal';
    } catch { /* Fixed classification only. */ }
    return null;
  }
  function enqueue(job) {
    const promise = Promise.resolve().then(job).catch(() => {});
    pending.add(promise); promise.finally(() => pending.delete(promise));
  }
  function record(stage, id) {
    if (!active || records.length >= MAX_RECORDS) return null;
    const row = {id, stage}; records.push(row); return row;
  }
  function fromBase64(text) {
    if (text.length > Math.ceil(MAX_BYTES / 3) * 4 || text.length === 0 || text.length % 4 !== 0 ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
    try { return Uint8Array.from(atob(text), c => c.charCodeAt(0)); } catch { return null; }
  }
  async function describe(bytes) {
    if (bytes.byteLength > MAX_BYTES) return {bytes: bytes.byteLength, kind: 'over-limit'};
    const out = {bytes: bytes.byteLength, sha256: Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
      b => b.toString(16).padStart(2, '0')).join('')};
    let text;
    out.bom = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 'utf8' :
      bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf16le' : bytes[0] === 0xfe && bytes[1] === 0xff ? 'utf16be' : 'none';
    try { text = dec.decode(bytes); } catch { return {...out, kind: 'non-utf8'}; }
    const trimmed = text.trimStart();
    if (/^(?:<!doctype\s+html|<html(?:\s|>))/i.test(trimmed)) out.kind = 'html';
    else if (trimmed.startsWith('<')) {
      const doc = new DOMParser().parseFromString(text, 'application/xml');
      out.kind = doc.getElementsByTagName('parsererror').length ? 'invalid-xml' : 'xml';
      if (out.kind === 'xml') {
        out.signatureCount = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature').length;
        out.taxRoot = ['HSoThueDTu', 'TKhai'].includes(doc.documentElement.localName);
      }
    } else if (/^[\[{]/.test(trimmed)) out.kind = 'json';
    else out.kind = fromBase64(trimmed) ? 'base64-text' : 'text';
    // A marker, never raw server text. A response can itself be valid XML/HTML
    // containing this error; it does not identify the document the server parsed.
    out.prologError = /Content is not allowed in prolog\.?/i.test(text);
    return out;
  }
  async function candidate(value, label) {
    const bytes = typeof value === 'string' ? enc.encode(value) : new Uint8Array(await value.arrayBuffer());
    const result = {label, basis: typeof value === 'string' ? 'js-string-utf8' : 'blob-bytes', wire: await describe(bytes)};
    if (typeof value === 'string') {
      const decoded = fromBase64(value);
      if (decoded) result.decodedOnce = await describe(decoded);
    }
    return result;
  }
  async function inspect(body, row, response = false) {
    if (!row || body == null) return;
    if (typeof body === 'object' && body instanceof FormData) {
      row.container = 'multipart'; row.parts = [];
      let i = 0;
      for (const [key, value] of body.entries()) {
        if (row.parts.length >= 8) break;
        if (value instanceof Blob) {
          if (value.size <= MAX_BYTES) row.parts.push(await candidate(value, `file-part-${i}`));
          else row.parts.push({label: `file-part-${i}`, wire: {bytes: value.size, kind: 'over-limit'}});
        } else if (xmlFields.has(key)) row.parts.push(await candidate(value, `xml-field-${i}`));
        i++;
      }
      return;
    }
    if (body instanceof Blob) {
      row.container = 'blob';
      row.payload = body.size > MAX_BYTES ? {wire: {bytes: body.size, kind: 'over-limit'}} : await candidate(body, 'body');
      return;
    }
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
      row.container = 'bytes'; row.payload = {label: 'body', wire: await describe(bytes)}; return;
    }
    if (body instanceof URLSearchParams) body = body.toString();
    if (typeof body !== 'string') { row.container = 'unobserved'; return; }
    if (body.length > MAX_BYTES * 1.4) { row.container = 'over-limit'; return; }
    let obj;
    try { obj = JSON.parse(body); } catch { /* May be XML or URL-encoded form. */ }
    if (obj && typeof obj === 'object') {
      row.container = 'json'; row.parts = [];
      const f = obj.INPUT && typeof obj.INPUT === 'object' ? {...obj, ...obj.INPUT} : obj;
      if (commands.has(f.CODE)) row.command = f.CODE;
      if (typeof f.SUCCESS === 'string') row.success = f.SUCCESS === 'TRUE';
      if (typeof f.status === 'number' && Number.isFinite(f.status)) row.status = f.status;
      for (const key of xmlFields) if (typeof f[key] === 'string') row.parts.push(await candidate(f[key], key));
      if (response && typeof f.data === 'string') row.parts.push(await candidate(f.data, 'data'));
      // Scan errors only to a fixed boolean, without retaining raw values.
      row.prologError = /Content is not allowed in prolog\.?/i.test(body);
      return;
    }
    if (!body.trimStart().startsWith('<') && body.includes('=')) {
      const form = new URLSearchParams(body); row.container = 'urlencoded'; row.parts = [];
      for (const key of xmlFields) if (form.has(key)) row.parts.push(await candidate(form.get(key), key));
      row.prologError = /Content is not allowed in prolog\.?/i.test(body); return;
    }
    row.container = 'text'; row.payload = await candidate(body, 'body');
  }
  function begin(kind, body) {
    if (kind === 'ctsign') signingSeen = true;
    if (kind === 'esigner' && typeof body === 'string') {
      try {
        const f = JSON.parse(body), code = f.INPUT?.CODE ?? f.CODE;
        if (!commands.has(code)) return null;
        signingSeen = true;
      } catch { return null; }
    }
    if (!kind || !active || !signingSeen) return null;
    return ++nextID;
  }
  function listen(target, event, handler) {
    target.addEventListener(event, handler); listeners.push([target, event, handler]);
  }
  function hookedFetch(input, init) {
    const kind = route(typeof input === 'string' || input instanceof URL ? input : input.url);
    const method = String(init?.method ?? input?.method ?? 'GET').toUpperCase();
    const id = method === 'POST' ? begin(kind, init?.body) : null;
    // Forward synchronously; no observer is allowed to prevent or delay send.
    const promise = originalFetch.apply(this, arguments);
    if (id) {
      const row = record(`${kind}-request`, id);
      if (init && Object.hasOwn(init, 'body')) enqueue(() => inspect(init.body, row));
      else if (row && typeof input?.clone === 'function') {
        // Do not read or clone arbitrary streamed Request bodies.
        row.container = 'request-body-unobserved';
      }
      promise.then(response => {
        const reply = record(`${kind}-response`, id);
        if (!reply) return;
        reply.httpStatus = response.status;
        const copy = response.clone();
        enqueue(async () => {
          const reader = copy.body?.getReader();
          if (!reader) return;
          const chunks = []; let size = 0;
          try {
            while (true) {
              const {done, value} = await reader.read();
              if (done) break;
              size += value.byteLength;
              if (size > MAX_BYTES) { reply.container = 'over-limit'; void reader.cancel().catch(() => {}); return; }
              chunks.push(value);
            }
            const bytes = new Uint8Array(size); let offset = 0;
            for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
            reply.bodyBytes = await describe(bytes);
            let text;
            try { text = dec.decode(bytes); } catch { reply.payload = {wire: await describe(bytes)}; return; }
            await inspect(text, reply, true);
          } finally { reader.releaseLock(); }
        });
      }, () => { const reply = record(`${kind}-network-error`, id); if (reply) reply.failed = true; }).catch(() => {});
    }
    return promise;
  }
  function hookedOpen(method, url) {
    xhrs.set(this, {kind: route(url), method: String(method).toUpperCase()});
    return originalOpen.apply(this, arguments);
  }
  function hookedSend(body) {
    const meta = xhrs.get(this), id = meta?.method === 'POST' ? begin(meta.kind, body) : null;
    if (id) {
      const row = record(`${meta.kind}-request`, id); enqueue(() => inspect(body, row));
      meta.id = id;
      if (!row) return originalSend.apply(this, arguments);
      listen(this, 'load', () => {
        if (xhrs.get(this) !== meta || meta.id !== id) return;
        const reply = record(`${meta.kind}-response`, id); if (!reply) return;
        reply.httpStatus = this.status;
        reply.basis = 'browser-response';
        if (this.responseType === '' || this.responseType === 'text') enqueue(() => inspect(this.responseText, reply, true));
        else if (this.responseType === 'json') enqueue(() => inspect(JSON.stringify(this.response), reply, true));
        else if (this.responseType === 'blob' || this.responseType === 'arraybuffer') enqueue(() => inspect(this.response, reply, true));
        else reply.container = 'unobserved';
      });
    }
    return originalSend.apply(this, arguments);
  }
  function hookedWS(data) {
    if (route(this.url) === 'esigner') {
      if (!sockets.has(this)) {
        sockets.add(this);
        listen(this, 'message', event => {
          if (!signingSeen) return;
          const row = record('esigner-response', ++nextID); enqueue(() => inspect(event.data, row, true));
        });
      }
      const id = begin('esigner', data);
      if (id) { const row = record('esigner-request', id); enqueue(() => inspect(data, row)); }
    }
    return originalWS.apply(this, arguments);
  }
  function restore() {
    active = false;
    if (window.fetch === hookedFetch) window.fetch = originalFetch;
    if (XMLHttpRequest.prototype.open === hookedOpen) XMLHttpRequest.prototype.open = originalOpen;
    if (XMLHttpRequest.prototype.send === hookedSend) XMLHttpRequest.prototype.send = originalSend;
    if (WebSocket.prototype.send === hookedWS) WebSocket.prototype.send = originalWS;
    for (const [target, event, handler] of listeners) target.removeEventListener(event, handler);
    listeners.length = 0; clearTimeout(timer);
  }
  window.fetch = hookedFetch; XMLHttpRequest.prototype.open = hookedOpen;
  XMLHttpRequest.prototype.send = hookedSend; WebSocket.prototype.send = hookedWS;
  timer = setTimeout(restore, 5 * 60 * 1000);
  window.TokenSignerProlog = Object.freeze({restore, snapshot: () => JSON.parse(JSON.stringify({version: 1, active, records})),
    settled: async () => { while (pending.size) await Promise.all([...pending]); }});
})();
