/* Parsing JWT: solo testo. La firma sta in crypto.js. */
const SigilloJwt = (() => {
  const DASH = "\u2014";

  const ALGS = [
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
  ];

  const CLAIMS = [
    ["iss", "Emittente", "text"],
    ["sub", "Soggetto", "text"],
    ["aud", "Destinatario", "text"],
    ["exp", "Scadenza", "time"],
    ["nbf", "Valido dal", "time"],
    ["iat", "Emesso", "time"],
    ["jti", "Id", "id"],
  ];

  function bytesToB64url(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function b64urlToBytes(input) {
    if (!input) return new Uint8Array();
    const cleaned = String(input).replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    if (!/^[A-Za-z0-9+/]*$/.test(cleaned)) {
      const err = new Error("b64");
      err.code = "b64";
      throw err;
    }
    const pad = cleaned.length % 4 === 0 ? "" : "=".repeat(4 - (cleaned.length % 4));
    const bin = atob(cleaned + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function encodeJson(value) {
    return bytesToB64url(new TextEncoder().encode(JSON.stringify(value)));
  }

  function pretty(value) {
    return JSON.stringify(value, null, 2);
  }

  function decodePart(part) {
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(b64urlToBytes(part));
    } catch {
      const err = new Error("part");
      err.code = "part";
      throw err;
    }
    try {
      return { text, value: JSON.parse(text) };
    } catch {
      const err = new Error("json");
      err.code = "json";
      throw err;
    }
  }

  function normalizeToken(raw) {
    let text = String(raw ?? "").trim();
    text = text.replace(/^bearer\s+/i, "");
    if (
      (text.startsWith('"') && text.endsWith('"')) ||
      (text.startsWith("'") && text.endsWith("'"))
    ) {
      text = text.slice(1, -1).trim();
    }
    return text.replace(/\s+/g, "");
  }

  function isSupported(alg) {
    return ALGS.includes(alg);
  }

  function parseToken(raw) {
    const text = normalizeToken(raw);
    if (!text) return { ok: false, empty: true, raw: "" };
    const bits = text.split(".");
    if (bits.length < 2 || bits.length > 3) {
      return {
        ok: false,
        raw: text,
        message: "Un JWT è header.payload.firma, con due punti.",
      };
    }
    const parts = bits.length === 2 ? [bits[0], bits[1], ""] : bits;
    let header;
    let headerText;
    try {
      const decoded = decodePart(parts[0]);
      header = decoded.value;
      headerText = decoded.value !== null && typeof decoded.value === "object"
        ? pretty(decoded.value)
        : decoded.text;
    } catch {
      return { ok: false, raw: text, message: "L'header non è JSON in Base64url." };
    }
    let payload;
    let payloadText;
    try {
      const decoded = decodePart(parts[1]);
      payload = decoded.value;
      payloadText = decoded.value !== null && typeof decoded.value === "object"
        ? pretty(decoded.value)
        : decoded.text;
    } catch {
      return {
        ok: false,
        raw: text,
        parts,
        header,
        headerText,
        message: "Il payload non è JSON in Base64url.",
      };
    }
    const alg = header && typeof header === "object" && !Array.isArray(header)
      ? header.alg
      : undefined;
    return {
      ok: true,
      raw: text,
      parts,
      header,
      payload,
      headerText,
      payloadText,
      alg: alg == null ? "" : String(alg),
    };
  }

  function objectPayload(payload) {
    return payload !== null && typeof payload === "object" && !Array.isArray(payload);
  }

  function unix(value) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
    return null;
  }

  function relative(unixSeconds, nowMs) {
    const deltaSec = unixSeconds - Math.floor(nowMs / 1000);
    const rtf = new Intl.RelativeTimeFormat("it", { numeric: "auto" });
    const abs = Math.abs(deltaSec);
    if (abs < 60) return rtf.format(Math.round(deltaSec), "second");
    if (abs < 3600) return rtf.format(Math.round(deltaSec / 60), "minute");
    if (abs < 86400) return rtf.format(Math.round(deltaSec / 3600), "hour");
    if (abs < 86400 * 30) return rtf.format(Math.round(deltaSec / 86400), "day");
    if (abs < 86400 * 365) return rtf.format(Math.round(deltaSec / (86400 * 30)), "month");
    return rtf.format(Math.round(deltaSec / (86400 * 365)), "year");
  }

  function absolute(unixSeconds) {
    return new Intl.DateTimeFormat("it", {
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(unixSeconds * 1000));
  }

  function displayValue(value) {
    if (value == null) return DASH;
    if (Array.isArray(value)) return value.map((item) => String(item)).join(", ");
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  }

  function claimRows(payload, nowMs) {
    const body = objectPayload(payload) ? payload : null;
    const nowSec = Math.floor(nowMs / 1000);
    return CLAIMS.map(([key, label, kind]) => {
      const present = body != null && Object.prototype.hasOwnProperty.call(body, key);
      if (!present) {
        return { key, label, kind, present: false, reading: DASH, when: "", tone: "missing" };
      }
      const value = body[key];
      if (kind === "time") {
        const stamp = unix(value);
        if (stamp == null) {
          return { key, label, kind, present: true, reading: displayValue(value), when: "", tone: "" };
        }
        let tone = "";
        if (key === "exp" && stamp <= nowSec) tone = "bad";
        else if (key === "nbf" && stamp > nowSec) tone = "warn";
        else if (key === "iat" && stamp > nowSec + 60) tone = "warn";
        return {
          key,
          label,
          kind,
          present: true,
          reading: relative(stamp, nowMs),
          when: absolute(stamp),
          tone,
        };
      }
      return {
        key,
        label,
        kind,
        present: true,
        reading: displayValue(value),
        when: "",
        tone: "",
      };
    });
  }

  /* La frase sotto il titolo. Il tempo vince sulla firma solo quando il token è già scaduto o non è ancora valido. */
  function timeLead(payload, nowMs) {
    if (!objectPayload(payload)) return null;
    const nowSec = Math.floor(nowMs / 1000);
    const exp = unix(payload.exp);
    const nbf = unix(payload.nbf);
    if (exp != null && exp <= nowSec) {
      return { text: `Scaduto, ${relative(exp, nowMs)}`, tone: "bad" };
    }
    if (nbf != null && nbf > nowSec) {
      return { text: `Vale ${relative(nbf, nowMs)}`, tone: "warn" };
    }
    if (exp != null) {
      return { text: `Scade ${relative(exp, nowMs)}`, tone: "" };
    }
    return null;
  }

  function titleFor(payload) {
    if (!objectPayload(payload) || typeof payload.sub !== "string") return "Token";
    const sub = payload.sub.trim();
    if (!sub || sub.length > 48 || /\s{2,}/.test(sub)) return "Token";
    return sub;
  }

  return {
    DASH,
    ALGS,
    CLAIMS,
    bytesToB64url,
    b64urlToBytes,
    encodeJson,
    pretty,
    decodePart,
    normalizeToken,
    isSupported,
    parseToken,
    claimRows,
    timeLead,
    titleFor,
    objectPayload,
  };
})();

globalThis.SigilloJwt = SigilloJwt;
