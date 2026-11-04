/* One command initiated by the user. Exact tenant origin and fixed upstream.
 * Template placeholders are filled from the private loopback relay descriptor.
 * Never log BrowserInfo, credentials, invoice IDs, or raw callback/error text.
 */
(() => {
let captureStage = "configuration";
void (async () => {
  "use strict";
  const captureAPI = "__CAPTURE_API__";
  const expectedInvoices = Number("__CAPTURE_INVOICE_COUNT__");
  const capturePageOrigin = "__CAPTURE_PAGE_ORIGIN__";
  captureStage = "configuration-or-page-origin";
  if (!Number.isInteger(expectedInvoices) || expectedInvoices < 2 || expectedInvoices > 10000 || !/^http:\/\/127\.0\.0\.1:17080\/capture-[0-9a-f]{32}\/api\/app\/$/.test(captureAPI) ||
      location.protocol !== "https:" || location.origin !== capturePageOrigin)
    throw new Error("Invalid capture configuration or page");
  captureStage = "previous-hook-requires-reload";
  if (window.TokenSignerCapture || window.TokenSignerCapturePending)
    throw new Error("Reload the page before preparing another capture");
  const pending = {};
  window.TokenSignerCapturePending = pending;
  try {
    const healthURL = captureAPI.replace(/api\/app\/$/, "status");
    async function checkRelay() {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        captureStage = "health-fetch";
        const response = await fetch(healthURL, {
          method: "GET", credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal
        });
        captureStage = "health-http-status";
        if (!response.ok) throw new Error("Relay unavailable");
        captureStage = "health-json";
        const health = await response.json();
        captureStage = "health-readiness-or-invoice-count";
        const expires = Date.parse(health.expires_utc);
        if (health.ready !== true || health.expected_invoice_count !== expectedInvoices || !Number.isFinite(expires) || expires <= Date.now() + 60000)
          throw new Error("Relay expired or already used");
        return expires;
      } finally { clearTimeout(timeout); }
    }
    const expires = await checkRelay();
    captureStage = "hook-installation";
    const wsSend = WebSocket.prototype.send;
    const xhrOpen = XMLHttpRequest.prototype.open;
    const xhrSend = XMLHttpRequest.prototype.send;
    const xhrURLs = new WeakMap();
    const abortedXHRs = new WeakSet();
    const observedSockets = new WeakSet();
    const listeners = [];
    let active = true, armed = true, reserved = false, rewritten = 0, callbacks = 0, timer;
    const observe = (target, event, listener) => {
      target.addEventListener(event, listener);
      listeners.push([target, event, listener]);
    };
    const isPlugin = value => {
      try {
        const u = new URL(value, location.href);
        return ["localhost", "127.0.0.1"].includes(u.hostname) && u.port === "16080" &&
          ["http:", "https:", "ws:", "wss:"].includes(u.protocol) && u.pathname.startsWith("/signalr/");
      } catch { return false; }
    };
    const restore = () => {
      active = false; armed = false;
      if (WebSocket.prototype.send === hookedWS) WebSocket.prototype.send = wsSend;
      if (XMLHttpRequest.prototype.open === hookedOpen) XMLHttpRequest.prototype.open = xhrOpen;
      if (XMLHttpRequest.prototype.send === hookedXHR) XMLHttpRequest.prototype.send = xhrSend;
      for (const [target, event, listener] of listeners) target.removeEventListener(event, listener);
      listeners.length = 0;
      clearTimeout(timer);
    };
    const safeCallback = text => {
      try {
        const frame = JSON.parse(text);
        for (const item of Array.isArray(frame.M) ? frame.M : [frame]) {
          if (String(item.H).toLowerCase() !== "handlerhub" || item.M !== "reponseResult" ||
              !Array.isArray(item.A) || typeof item.A[0] !== "string") continue;
          const result = JSON.parse(item.A[0]);
          if (rewritten !== 1 || (result?.data?.command && result.data.command !== "SignInvoices")) continue;
          callbacks++;
          console.info("TokenSigner capture callback", {
            code: typeof result.code === "number" ? result.code : "non-numeric",
            command: result?.data?.command === "SignInvoices" ? "SignInvoices" : "omitted",
            status: typeof result?.data?.status === "boolean" ? result.data.status : "omitted"
          });
          restore();
        }
      } catch { /* Never log raw callback text. */ }
    };
    const reserveFrame = text => {
      if (typeof text !== "string") return null;
      let frame, command;
      try {
        frame = JSON.parse(text);
        if (String(frame.H).toLowerCase() !== "handlerhub" ||
            String(frame.M).toLowerCase() !== "processmessage" ||
            !Array.isArray(frame.A) || frame.A.length !== 1 || typeof frame.A[0] !== "string") return null;
        command = JSON.parse(frame.A[0]);
      } catch { return null; }
      if (command?.PlugCommand?.CommandName !== "SignInvoices") return null;
      if (!active || !armed || reserved) throw new Error("One command already reserved");
      if (command?.BrowserInfo?.LinkApi !== "https://api-hddt.minvoice.com.vn/api/app/" ||
          !Array.isArray(command.PlugCommand.InvoiceIdArray) || command.PlugCommand.InvoiceIdArray.length !== expectedInvoices ||
          command.PlugCommand.InvoiceIdArray.some(id => typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) ||
          new Set(command.PlugCommand.InvoiceIdArray.map(id => id.toLowerCase())).size !== expectedInvoices)
        throw new Error("Unexpected API or invoice count");
      // Reserve synchronously, before the asynchronous readiness check.
      armed = false; reserved = true;
      command.BrowserInfo.LinkApi = captureAPI;
      frame.A[0] = JSON.stringify(command);
      return JSON.stringify(frame);
    };
    const failSend = (transport, kind) => {
      restore();
      console.error("TokenSigner capture: SignInvoices command NOT sent. Reload the page and prepare a fresh capture; do not retry signing automatically.");
      try {
        if (kind === "ws") transport.close(1000, "Capture unavailable");
        else transport.abort();
      } catch { /* Fixed diagnostic above; no raw error. */ }
    };
    async function sendChecked(transport, kind, body) {
      try {
        await checkRelay();
        if (!active || (kind === "ws" && transport.readyState !== WebSocket.OPEN) ||
            (kind === "xhr" && abortedXHRs.has(transport))) throw new Error("Transport no longer available");
        rewritten++;
        if (kind === "ws") wsSend.call(transport, body);
        else xhrSend.call(transport, body);
        console.info("TokenSigner capture: connection verified; one user-initiated batch SignInvoices command routed through loopback.", {invoice_count: expectedInvoices});
      } catch { failSend(transport, kind); }
    }
    function hookedWS(data) {
      if (isPlugin(this.url)) {
        if (!observedSockets.has(this)) {
          observe(this, "message", event => { if (typeof event.data === "string") safeCallback(event.data); });
          observedSockets.add(this);
        }
        try {
          const changed = reserveFrame(data);
          if (changed !== null) { void sendChecked(this, "ws", changed); return; }
        } catch { failSend(this, "ws"); return; }
      }
      return wsSend.call(this, data);
    }
    function hookedOpen(method, url, ...args) {
      xhrURLs.set(this, String(url));
      abortedXHRs.delete(this);
      if (isPlugin(url)) {
        observe(this, "abort", () => abortedXHRs.add(this));
        observe(this, "load", () => {
          if (this.responseType === "" || this.responseType === "text") safeCallback(this.responseText);
        });
      }
      return xhrOpen.call(this, method, url, ...args);
    }
    function hookedXHR(body) {
      if (isPlugin(xhrURLs.get(this)) && typeof body === "string") {
        const form = new URLSearchParams(body);
        if (form.has("data")) {
          try {
            const changed = reserveFrame(form.get("data"));
            if (changed !== null) { form.set("data", changed); void sendChecked(this, "xhr", form.toString()); return; }
          } catch { failSend(this, "xhr"); return; }
        }
      }
      return xhrSend.call(this, body);
    }
    WebSocket.prototype.send = hookedWS;
    XMLHttpRequest.prototype.open = hookedOpen;
    XMLHttpRequest.prototype.send = hookedXHR;
    timer = setTimeout(restore, Math.max(0, expires - Date.now() - 60000));
    window.TokenSignerCapture = Object.freeze({restore, status: () => ({active, armed, reserved, rewritten, callbacks})});
    console.info("TokenSigner capture armed for batch: connection verified.", {invoice_count: expectedInvoices}, "Waiting for a signing action you initiate.");
  } finally {
    if (window.TokenSignerCapturePending === pending) delete window.TokenSignerCapturePending;
  }
})().catch(() => {
  console.error("TokenSigner capture NOT armed. Check the exact tenant page and fresh relay connection, then reload the page before trying again.", {stage: captureStage, page_origin: location.origin});
});

})();
