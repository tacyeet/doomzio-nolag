/*
  Doomz.io WebGL chat sanitizer (minimal)
  - Replaces '<' -> '[' and '>' -> ']' inside incoming chat payload bytes
  - Forces ws.binaryType = "arraybuffer"
  - Intercepts ws.onmessage and addEventListener("message", ...)
  No logging, no overlay.
*/
(() => {
  const SANITIZE_INCOMING_CHAT = true;

  // Signature observed in Doomz packets: 7a 00 01 73 00 [type] [ASCII chat...]
  const SIG = new Uint8Array([0x7a, 0x00, 0x01, 0x73, 0x00]);

  function findSig(u8) {
    for (let i = 0; i <= u8.length - SIG.length; i++) {
      let ok = true;
      for (let j = 0; j < SIG.length; j++) {
        if (u8[i + j] !== SIG[j]) { ok = false; break; }
      }
      if (ok) return i;
    }
    return -1;
  }

  function sanitizeChatInPlace(u8, msgStart) {
    let i = msgStart;
    while (i < u8.length && u8[i] !== 0x00) {
      const b = u8[i];
      if (b === 0x3C) u8[i] = 0x5B;       // '<' -> '['
      else if (b === 0x3E) u8[i] = 0x5D;  // '>' -> ']'
      i++;
    }
  }

  function maybeSanitizeArrayBuffer(buf) {
    if (!SANITIZE_INCOMING_CHAT || !(buf instanceof ArrayBuffer)) return;
    const u8 = new Uint8Array(buf);
    const pos = findSig(u8);
    if (pos === -1) return;
    const typePos = pos + SIG.length;
    const msgStart = typePos + 1;
    if (msgStart >= u8.length) return;

    // Only bother if there is at least one '<' in the message span.
    for (let i = msgStart; i < u8.length && u8[i] !== 0x00; i++) {
      if (u8[i] === 0x3C || u8[i] === 0x3E) {
        sanitizeChatInPlace(u8, msgStart);
        break;
      }
    }
  }

  function wrapMessageHandler(fn) {
    return function(ev) {
      try {
        if (ev && ev.data instanceof ArrayBuffer) {
          maybeSanitizeArrayBuffer(ev.data);
        } else if (ev && ev.data && ev.data instanceof Blob) {
          // If some code forces Blob, convert to ArrayBuffer and forward
          const orig = ev.data;
          orig.arrayBuffer().then((ab) => {
            maybeSanitizeArrayBuffer(ab);
            const newEv = new MessageEvent("message", { data: ab, origin: ev.origin, lastEventId: ev.lastEventId, source: ev.source, ports: ev.ports });
            fn(newEv);
          }).catch(() => fn(ev));
          return;
        }
      } catch {}
      return fn(ev);
    };
  }

  const OriginalWebSocket = window.WebSocket;

  function WrappedWebSocket(url, protocols) {
    const ws = protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
    try { ws.binaryType = "arraybuffer"; } catch {}

    const proxy = new Proxy(ws, {
      set(target, prop, value) {
        try {
          if (prop === "onmessage" && typeof value === "function") {
            target.onmessage = wrapMessageHandler(value);
            return true;
          }
          if (prop === "binaryType") {
            target.binaryType = value;
            return true;
          }
        } catch {}
        target[prop] = value;
        return true;
      },
      get(target, prop) {
        const v = target[prop];
        if (prop === "addEventListener") {
          return function(type, listener, options) {
            if (type === "message" && typeof listener === "function") {
              return target.addEventListener(type, wrapMessageHandler(listener), options);
            }
            return target.addEventListener(type, listener, options);
          };
        }
        return typeof v === "function" ? v.bind(target) : v;
      }
    });

    return proxy;
  }

  WrappedWebSocket.prototype = OriginalWebSocket.prototype;
  ["CONNECTING","OPEN","CLOSING","CLOSED"].forEach(k => {
    try { Object.defineProperty(WrappedWebSocket, k, { value: OriginalWebSocket[k] }); } catch {}
  });

  window.WebSocket = WrappedWebSocket;
})();
