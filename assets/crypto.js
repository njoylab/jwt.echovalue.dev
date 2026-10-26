/* Firma e verifica con Web Crypto. Nessuna rete. */
const SigilloCrypto = (() => {
  const HASH = {
    HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512",
    RS256: "SHA-256", RS384: "SHA-384", RS512: "SHA-512",
    PS256: "SHA-256", PS384: "SHA-384", PS512: "SHA-512",
    ES256: "SHA-256", ES384: "SHA-384", ES512: "SHA-512",
  };
  const CURVE = { ES256: "P-256", ES384: "P-384", ES512: "P-521" };
  const HASH_BYTES = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };

  function jwt() {
    return globalThis.SigilloJwt;
  }

  function isHmac(alg) {
    return alg === "HS256" || alg === "HS384" || alg === "HS512";
  }

  function isRsa(alg) {
    return alg.startsWith("RS") || alg.startsWith("PS");
  }

  function isEc(alg) {
    return alg === "ES256" || alg === "ES384" || alg === "ES512";
  }

  function isEd(alg) {
    return alg === "EdDSA";
  }

  function hashName(alg) {
    return HASH[alg] || null;
  }

  function hashBytes(alg) {
    const name = hashName(alg);
    return name ? HASH_BYTES[name] : 0;
  }

  function secretBytes(text, isBase64) {
    const raw = String(text ?? "");
    if (!isBase64) return new TextEncoder().encode(raw);
    try {
      return jwt().b64urlToBytes(raw.trim());
    } catch {
      const err = new Error("secret");
      err.code = "secret";
      throw err;
    }
  }

  function pemToDer(pem) {
    const match = String(pem).match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]+?)-----END \1-----/);
    if (!match) {
      const err = new Error("pem");
      err.code = "pem";
      throw err;
    }
    if (/RSA PRIVATE KEY|RSA PUBLIC KEY|EC PRIVATE KEY/.test(match[1])) {
      const err = new Error("pkcs1");
      err.code = "pkcs1";
      throw err;
    }
    const b64 = match[2].replace(/\s/g, "");
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function derToPem(label, buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    const lines = btoa(bin).match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
  }

  function keyError(err) {
    if (err && err.code === "pkcs1") {
      return "Questo PEM è PKCS#1. Serve PKCS#8 (BEGIN PRIVATE KEY) o SPKI (BEGIN PUBLIC KEY).";
    }
    if (err && err.code === "pem") return "Il PEM non si legge.";
    if (err && err.code === "secret") return "Il segreto non è Base64url.";
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      return "Questo browser non espone Web Crypto. Aprilo da localhost.";
    }
    return "La chiave non è valida per questo algoritmo.";
  }

  function importParams(alg) {
    if (isHmac(alg)) return { name: "HMAC", hash: HASH[alg] };
    if (alg.startsWith("RS")) return { name: "RSASSA-PKCS1-v1_5", hash: HASH[alg] };
    if (alg.startsWith("PS")) return { name: "RSA-PSS", hash: HASH[alg] };
    if (isEc(alg)) return { name: "ECDSA", namedCurve: CURVE[alg] };
    if (isEd(alg)) return { name: "Ed25519" };
    return null;
  }

  function opParams(alg) {
    if (isHmac(alg)) return { name: "HMAC" };
    if (alg.startsWith("RS")) return { name: "RSASSA-PKCS1-v1_5" };
    if (alg.startsWith("PS")) return { name: "RSA-PSS", saltLength: hashBytes(alg) };
    if (isEc(alg)) return { name: "ECDSA", hash: HASH[alg] };
    if (isEd(alg)) return { name: "Ed25519" };
    return null;
  }

  async function importHmac(alg, bytes, usages) {
    return crypto.subtle.importKey("raw", bytes, importParams(alg), false, usages);
  }

  async function importPem(alg, pem, format, usages) {
    const der = pemToDer(pem);
    return crypto.subtle.importKey(format, der, importParams(alg), false, usages);
  }

  function dataBytes(signingInput) {
    return new TextEncoder().encode(signingInput);
  }

  async function sign(alg, signingInput, material) {
    try {
      if (!jwt().isSupported(alg)) {
        return { ok: false, reason: "alg", message: "Algoritmo non supportato." };
      }
      let key;
      if (isHmac(alg)) {
        if (!material.secret) return { ok: false, reason: "missing", message: "Manca il segreto." };
        const bytes = secretBytes(material.secret, material.secretIsBase64);
        key = await importHmac(alg, bytes, ["sign"]);
      } else if (!material.privatePem || !material.privatePem.trim()) {
        return { ok: false, reason: "missing", message: "Manca la chiave privata." };
      } else {
        key = await importPem(alg, material.privatePem, "pkcs8", ["sign"]);
      }
      const raw = await crypto.subtle.sign(opParams(alg), key, dataBytes(signingInput));
      return { ok: true, signature: jwt().bytesToB64url(new Uint8Array(raw)) };
    } catch (err) {
      return { ok: false, reason: "key", message: keyError(err) };
    }
  }

  async function verify(alg, signingInput, signaturePart, material) {
    try {
      if (String(alg).toLowerCase() === "none") {
        return { ok: false, reason: "none", message: "alg none non è una firma." };
      }
      if (!jwt().isSupported(alg)) {
        return { ok: false, reason: "alg", message: "Algoritmo non supportato." };
      }
      let signature;
      try {
        signature = jwt().b64urlToBytes(signaturePart);
      } catch {
        return { ok: false, reason: "sig", message: "La firma non è Base64url." };
      }
      let key;
      if (isHmac(alg)) {
        if (!material.secret) return { ok: false, reason: "missing", message: "Manca il segreto." };
        const bytes = secretBytes(material.secret, material.secretIsBase64);
        key = await importHmac(alg, bytes, ["verify"]);
      } else if (material.publicPem && material.publicPem.trim()) {
        key = await importPem(alg, material.publicPem, "spki", ["verify"]);
      } else {
        return { ok: false, reason: "missing", message: "Manca la chiave pubblica." };
      }
      const ok = await crypto.subtle.verify(opParams(alg), key, signature, dataBytes(signingInput));
      return ok
        ? { ok: true, reason: "valid" }
        : { ok: false, reason: "invalid", message: "La firma non torna." };
    } catch (err) {
      return { ok: false, reason: "key", message: keyError(err) };
    }
  }

  async function generate(alg) {
    if (isHmac(alg)) {
      const bytes = crypto.getRandomValues(new Uint8Array(hashBytes(alg)));
      return {
        secret: jwt().bytesToB64url(bytes),
        secretIsBase64: true,
        publicPem: "",
        privatePem: "",
      };
    }
    let key;
    if (isRsa(alg)) {
      const name = alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5";
      key = await crypto.subtle.generateKey(
        { name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: HASH[alg] },
        true,
        ["sign", "verify"],
      );
    } else if (isEc(alg)) {
      key = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: CURVE[alg] },
        true,
        ["sign", "verify"],
      );
    } else if (isEd(alg)) {
      key = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    } else {
      throw new Error("Algoritmo non supportato.");
    }
    const priv = await crypto.subtle.exportKey("pkcs8", key.privateKey);
    const pub = await crypto.subtle.exportKey("spki", key.publicKey);
    return {
      secret: "",
      secretIsBase64: false,
      privatePem: derToPem("PRIVATE KEY", priv),
      publicPem: derToPem("PUBLIC KEY", pub),
    };
  }

  return { isHmac, isRsa, isEc, isEd, hashBytes, secretBytes, sign, verify, generate };
})();

globalThis.SigilloCrypto = SigilloCrypto;
