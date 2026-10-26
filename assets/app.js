/* Banco locale. Lo stato vive nei campi. Non c'è storage e non c'è rete. */
(() => {
  const Jwt = globalThis.SigilloJwt;
  const Crypto = globalThis.SigilloCrypto;

  const tokenEl = document.getElementById("token");
  const tokenPaint = document.getElementById("token-paint");
  const headerEl = document.getElementById("header");
  const headerPaint = document.getElementById("header-paint");
  const payloadEl = document.getElementById("payload");
  const payloadPaint = document.getElementById("payload-paint");
  const titleEl = document.getElementById("screen-title");
  const findingEl = document.getElementById("finding");
  const pillEl = document.getElementById("pill");
  const copyBtn = document.getElementById("copy");
  const algEl = document.getElementById("alg");
  const secretEl = document.getElementById("secret");
  const b64El = document.getElementById("b64");
  const pubEl = document.getElementById("pub");
  const privEl = document.getElementById("priv");
  const hmacBox = document.getElementById("hmac-fields");
  const pemBox = document.getElementById("pem-fields");
  const hintEl = document.getElementById("sign-hint");
  const sizesEl = document.getElementById("sizes");
  const kidEl = document.getElementById("kid");
  const generateBtn = document.getElementById("generate");
  const sharesEl = document.getElementById("shares");
  const sigPreview = document.getElementById("sig-preview");
  const tokenNote = document.getElementById("token-note");
  const headerNote = document.getElementById("header-note");
  const payloadNote = document.getElementById("payload-note");

  let ticket = 0;
  let writing = false;

  function material() {
    return {
      secret: secretEl.value,
      secretIsBase64: b64El.checked,
      publicPem: pubEl.value,
      privatePem: privEl.value,
    };
  }

  function keyMode(alg) {
    if (Crypto.isHmac(alg)) return "hmac";
    if (Jwt.isSupported(alg)) return "pem";
    return "other";
  }

  function syncKeyFields() {
    const mode = keyMode(algEl.value);
    hmacBox.hidden = mode !== "hmac";
    pemBox.hidden = mode !== "pem";
    generateBtn.hidden = mode === "other";
    generateBtn.textContent = mode === "hmac" ? "Genera segreto" : "Genera chiave";
  }

  function syncAlgSelect(alg) {
    let extra = algEl.querySelector("option[data-extra]");
    if (alg && !Jwt.isSupported(alg)) {
      if (!extra) {
        extra = document.createElement("option");
        extra.dataset.extra = "1";
        algEl.prepend(extra);
      }
      extra.value = alg;
      extra.textContent = alg;
      algEl.value = alg;
    } else if (extra) {
      extra.remove();
      if (Jwt.isSupported(alg)) algEl.value = alg;
    } else if (Jwt.isSupported(alg)) {
      algEl.value = alg;
    }
    syncKeyFields();
  }

  function paintToken(value) {
    tokenPaint.replaceChildren();
    if (!value) return;
    const parts = value.split(".");
    parts.forEach((part, index) => {
      if (index) {
        const dot = document.createElement("span");
        dot.className = "seg-dot";
        dot.textContent = ".";
        tokenPaint.append(dot);
      }
      const span = document.createElement("span");
      span.className = index === 1 ? "seg-p" : "seg";
      span.textContent = part;
      tokenPaint.append(span);
    });
  }

  function paintJson(pre, text) {
    pre.replaceChildren();
    if (!text) return;
    const re = /"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b|[{}[\]:,]/g;
    let cursor = 0;
    for (const match of text.matchAll(re)) {
      if (match.index > cursor) pre.append(text.slice(cursor, match.index));
      const span = document.createElement("span");
      const bit = match[0];
      if (bit.startsWith('"')) {
        const after = text.slice(match.index + bit.length);
        span.className = /^\s*:/.test(after) ? "json-key" : "json-str";
      } else if (/^[{}[\]:,]$/.test(bit)) {
        span.className = "json-pun";
      } else {
        span.className = "json-num";
      }
      span.textContent = bit;
      pre.append(span);
      cursor = match.index + bit.length;
    }
    if (cursor < text.length) pre.append(text.slice(cursor));
  }

  function bindScroll(editor, paint) {
    editor.addEventListener("scroll", () => {
      paint.scrollTop = editor.scrollTop;
      paint.scrollLeft = editor.scrollLeft;
    });
  }

  function partIndex(token, caret) {
    const first = token.indexOf(".");
    if (first < 0 || caret <= first) return 0;
    const second = token.indexOf(".", first + 1);
    if (second < 0 || caret <= second) return 1;
    return 2;
  }

  function markPart(index) {
    document.querySelectorAll("[data-part]").forEach((button) => {
      button.setAttribute("aria-selected", button.dataset.part === String(index) ? "true" : "false");
    });
  }

  function renderShares(value) {
    const parts = value ? value.split(".") : ["", "", ""];
    while (parts.length < 3) parts.push("");
    const counts = parts.slice(0, 3).map((part) => part.length);
    document.querySelectorAll("[data-count]").forEach((node, index) => {
      node.textContent = String(counts[index] || 0);
    });
    sharesEl.querySelectorAll("[data-share]").forEach((node, index) => {
      node.style.flexGrow = String(Math.max(counts[index] || 0, 1));
    });
    sigPreview.value = parts.length > 2 ? parts.slice(2).join(".") : "";
  }

  function setSeal(kind) {
    const color = kind === "valid"
      ? "var(--accent)"
      : kind === "invalid"
        ? "var(--negative)"
        : "var(--control)";
    sharesEl.style.setProperty("--seal", color);
  }

  function renderClaims(payload) {
    const rows = Jwt.claimRows(payload, Date.now());
    for (const row of rows) {
      const tr = document.querySelector(`tr[data-claim="${row.key}"]`);
      const reading = tr.querySelector(".reading");
      const when = tr.querySelector(".when");
      reading.className = `reading${row.tone ? ` ${row.tone}` : ""}`;
      if (row.kind === "id" && row.present) {
        reading.replaceChildren();
        const code = document.createElement("code");
        code.textContent = row.reading;
        reading.append(code);
      } else {
        reading.textContent = row.reading;
      }
      when.hidden = !row.when;
      when.textContent = row.when;
    }
  }

  function countPhrase(n, one, many) {
    return `${n} ${n === 1 ? one : many}`;
  }

  function renderSizes(parsed) {
    if (!parsed || !parsed.ok) {
      sizesEl.textContent = "Input 0 caratteri. Firma 0 byte.";
      return;
    }
    const input = parsed.parts[0].length + parsed.parts[1].length + 1;
    let bytes = 0;
    try {
      bytes = Jwt.b64urlToBytes(parsed.parts[2]).length;
    } catch {
      bytes = 0;
    }
    sizesEl.textContent = `Input ${countPhrase(input, "carattere", "caratteri")}. Firma ${countPhrase(bytes, "byte", "byte")}.`;
  }

  function renderKid(parsed) {
    const kid = parsed && parsed.ok && parsed.header && typeof parsed.header === "object"
      ? parsed.header.kid
      : "";
    if (kid) {
      kidEl.hidden = false;
      kidEl.textContent = "";
      const label = document.createElement("span");
      label.textContent = "kid ";
      const code = document.createElement("code");
      code.textContent = String(kid);
      kidEl.append(label, code);
    } else {
      kidEl.hidden = true;
      kidEl.textContent = "";
    }
  }

  function setHint(text) {
    hintEl.hidden = !text;
    hintEl.textContent = text || "";
  }

  function secretHint(alg) {
    if (!Crypto.isHmac(alg) || !secretEl.value) return "";
    try {
      const size = Crypto.secretBytes(secretEl.value, b64El.checked).length;
      const need = Crypto.hashBytes(alg);
      if (size < need) {
        return `Il segreto è di ${size} byte. Per ${alg} ne servono almeno ${need}, altrimenti la firma è più debole.`;
      }
    } catch {
      return "";
    }
    return "";
  }

  function setCopyState() {
    const ready = Boolean(tokenEl.value.trim());
    copyBtn.classList.toggle("primary", ready);
    copyBtn.setAttribute("aria-disabled", ready ? "false" : "true");
  }

  function setPill(text, kind) {
    if (!text) {
      pillEl.hidden = true;
      pillEl.textContent = "";
      pillEl.className = "pill";
      return;
    }
    pillEl.hidden = false;
    pillEl.textContent = text;
    pillEl.className = `pill${kind ? ` ${kind}` : ""}`;
  }

  function setFinding(sentence, word, tone) {
    findingEl.replaceChildren();
    if (!word || !sentence.includes(word)) {
      findingEl.textContent = sentence;
      return;
    }
    const at = sentence.indexOf(word);
    findingEl.append(sentence.slice(0, at));
    const em = document.createElement("span");
    em.className = tone || "";
    em.textContent = word;
    findingEl.append(em, sentence.slice(at + word.length));
  }

  function showFrame(parsed, fromToken) {
    if (fromToken) {
      writing = true;
      if (parsed && parsed.headerText != null) {
        headerEl.value = parsed.headerText;
        paintJson(headerPaint, parsed.headerText);
      }
      if (parsed && parsed.payloadText != null) {
        payloadEl.value = parsed.payloadText;
        paintJson(payloadPaint, parsed.payloadText);
      }
      if (parsed && parsed.ok) syncAlgSelect(parsed.alg);
      writing = false;
    }
    const payload = parsed && parsed.ok ? parsed.payload : null;
    titleEl.textContent = Jwt.titleFor(payload);
    renderClaims(payload);
    renderSizes(parsed);
    renderKid(parsed);
    renderShares(tokenEl.value);
    setCopyState();
  }

  function noteFor(el, text) {
    el.hidden = !text;
    el.textContent = text || "";
  }

  async function verifyCurrent() {
    const my = ++ticket;
    const parsed = Jwt.parseToken(tokenEl.value);
    paintToken(tokenEl.value);
    renderShares(tokenEl.value);
    if (parsed.empty) {
      showFrame(null, false);
      titleEl.textContent = "Token";
      renderClaims(null);
      setPill("", "");
      setSeal("idle");
      setHint("");
      noteFor(tokenNote, "");
      noteFor(headerNote, "");
      noteFor(payloadNote, "");
      setFinding("Incolla un JWT. Il testo resta in questa scheda.", "", "");
      setCopyState();
      return;
    }
    if (!parsed.ok) {
      showFrame(parsed, false);
      if (parsed.headerText) {
        writing = true;
        headerEl.value = parsed.headerText;
        paintJson(headerPaint, parsed.headerText);
        writing = false;
      }
      setPill("Illeggibile", "neg");
      setSeal("invalid");
      setHint("");
      noteFor(tokenNote, parsed.message);
      setFinding(parsed.message, "", "");
      return;
    }
    showFrame(parsed, false);
    noteFor(tokenNote, "");
    const alg = parsed.alg;
    const lead = Jwt.timeLead(parsed.payload, Date.now());
    const weak = secretHint(alg);
    if (String(alg).toLowerCase() === "none") {
      if (my !== ticket) return;
      setPill("Senza firma", "warn");
      setSeal("idle");
      setHint("alg none non firma nulla. Il payload è solo testo.");
      setFinding("alg none. Questo token non ha una firma.", "none", "warn");
      return;
    }
    if (!Jwt.isSupported(alg)) {
      if (my !== ticket) return;
      setPill("Non supportato", "warn");
      setSeal("idle");
      setHint("");
      setFinding(
        alg ? `L'algoritmo ${alg} non è supportato qui.` : "Nell'header manca alg.",
        "",
        "",
      );
      return;
    }
    const mode = keyMode(alg);
    const keys = material();
    if (mode === "hmac" && !keys.secret) {
      if (my !== ticket) return;
      setPill("Non controllata", "");
      setSeal("idle");
      setHint("");
      setFinding(`Manca il segreto. L'algoritmo è ${alg}.`, "segreto", "");
      return;
    }
    if (mode === "pem" && !keys.publicPem.trim()) {
      if (my !== ticket) return;
      setPill("Non controllata", "");
      setSeal("idle");
      setHint(keys.privatePem.trim()
        ? "La chiave privata firma. Per controllare serve anche la pubblica."
        : "");
      setFinding(`Manca la chiave pubblica. L'algoritmo è ${alg}.`, "chiave pubblica", "");
      return;
    }
    const result = await Crypto.verify(
      alg,
      `${parsed.parts[0]}.${parsed.parts[1]}`,
      parsed.parts[2],
      keys,
    );
    if (my !== ticket) return;
    if (result.reason === "key" || result.reason === "sig") {
      setPill("Chiave", "warn");
      setSeal("idle");
      setHint(result.message);
      setFinding(result.message, "", "");
      return;
    }
    if (result.ok) {
      setPill("Valida", "pos");
      setSeal("valid");
      setHint(weak);
      if (lead && lead.tone) {
        setFinding(`${lead.text}. Firma valida con ${alg}.`, lead.text.split(",")[0], lead.tone);
      } else if (lead) {
        setFinding(`Firma valida con ${alg}. ${lead.text}.`, "valida", "ok");
      } else {
        setFinding(`Firma valida con ${alg}.`, "valida", "ok");
      }
      return;
    }
    setPill("Non valida", "neg");
    setSeal("invalid");
    setHint(weak);
    setFinding(`Firma non valida con ${alg}.`, "non valida", "bad");
  }

  function currentSignature() {
    const parts = tokenEl.value.split(".");
    return parts.length >= 3 ? parts.slice(2).join(".") : "";
  }

  async function resign() {
    const my = ++ticket;
    let header;
    let payload;
    try {
      header = JSON.parse(headerEl.value);
      noteFor(headerNote, "");
    } catch {
      noteFor(headerNote, "JSON dell'header non valido. Il token non è stato aggiornato.");
      return;
    }
    try {
      payload = JSON.parse(payloadEl.value);
      noteFor(payloadNote, "");
    } catch {
      noteFor(payloadNote, "JSON del payload non valido. Il token non è stato aggiornato.");
      return;
    }
    if (header === null || typeof header !== "object" || Array.isArray(header)) {
      noteFor(headerNote, "L'header deve essere un oggetto.");
      return;
    }
    const alg = header.alg == null ? algEl.value : String(header.alg);
    syncAlgSelect(alg);
    const input = `${Jwt.encodeJson(header)}.${Jwt.encodeJson(payload)}`;
    const signed = await Crypto.sign(alg, input, material());
    if (my !== ticket) return;
    const signature = signed.ok ? signed.signature : currentSignature();
    writing = true;
    tokenEl.value = `${input}.${signature}`;
    writing = false;
    paintToken(tokenEl.value);
    if (!signed.ok && signed.reason === "missing") {
      const need = Crypto.isHmac(alg) ? "il segreto" : "la chiave privata";
      showFrame(Jwt.parseToken(tokenEl.value), false);
      setPill("Non firmato", "");
      setSeal("idle");
      setHint("");
      setFinding(`Testo aggiornato. Manca ${need} per firmare.`, need, "");
      return;
    }
    if (!signed.ok) {
      setHint(signed.message);
    }
    await verifyCurrent();
  }

  function onToken() {
    if (writing) return;
    const clean = Jwt.normalizeToken(tokenEl.value);
    if (clean !== tokenEl.value) {
      const start = tokenEl.selectionStart || 0;
      const removed = tokenEl.value.length - clean.length;
      writing = true;
      tokenEl.value = clean;
      writing = false;
      const pos = Math.max(0, start - removed);
      tokenEl.setSelectionRange(pos, pos);
    }
    paintToken(tokenEl.value);
    renderShares(tokenEl.value);
    markPart(partIndex(tokenEl.value, tokenEl.selectionStart || 0));
    const parsed = Jwt.parseToken(tokenEl.value);
    if (parsed.empty) {
      writing = true;
      headerEl.value = "";
      payloadEl.value = "";
      writing = false;
      paintJson(headerPaint, "");
      paintJson(payloadPaint, "");
      noteFor(headerNote, "");
      noteFor(payloadNote, "");
      verifyCurrent();
      return;
    }
    if (parsed.headerText != null) {
      writing = true;
      headerEl.value = parsed.headerText;
      writing = false;
      paintJson(headerPaint, parsed.headerText);
      noteFor(headerNote, "");
    }
    if (parsed.payloadText != null) {
      writing = true;
      payloadEl.value = parsed.payloadText;
      writing = false;
      paintJson(payloadPaint, parsed.payloadText);
      noteFor(payloadNote, "");
    } else {
      noteFor(payloadNote, parsed.message || "");
    }
    if (parsed.ok) {
      noteFor(tokenNote, "");
      syncAlgSelect(parsed.alg);
    }
    verifyCurrent();
  }

  function fillAlgOptions() {
    for (const alg of Jwt.ALGS) {
      const option = document.createElement("option");
      option.value = alg;
      option.textContent = alg;
      algEl.append(option);
    }
    algEl.value = "HS256";
    syncKeyFields();
  }

  async function loadExample() {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: "HS256", typ: "JWT" };
    const payload = {
      iss: "sigillo",
      sub: "ada@banco.locale",
      aud: "banco",
      iat: now,
      nbf: now,
      exp: now + 7200,
      jti: randomId(),
      ruolo: "lettura",
    };
    console.assert(payload.exp - payload.iat === 7200);
    console.assert(payload.nbf === payload.iat);
    const gen = await Crypto.generate("HS256");
    writing = true;
    algEl.value = "HS256";
    secretEl.value = gen.secret;
    b64El.checked = true;
    pubEl.value = "";
    privEl.value = "";
    headerEl.value = Jwt.pretty(header);
    payloadEl.value = Jwt.pretty(payload);
    writing = false;
    paintJson(headerPaint, headerEl.value);
    paintJson(payloadPaint, payloadEl.value);
    noteFor(headerNote, "");
    noteFor(payloadNote, "");
    syncKeyFields();
    await resign();
    markPart(0);
  }

  function randomId() {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    return [...bytes].map((byte) => {
      const hex = byte.toString(16);
      return hex.length === 1 ? `0${hex}` : hex;
    }).join("");
  }

  function clearToken() {
    writing = true;
    tokenEl.value = "";
    headerEl.value = "";
    payloadEl.value = "";
    writing = false;
    paintToken("");
    paintJson(headerPaint, "");
    paintJson(payloadPaint, "");
    noteFor(tokenNote, "");
    noteFor(headerNote, "");
    noteFor(payloadNote, "");
    markPart(0);
    verifyCurrent();
    tokenEl.focus();
  }

  function clearKeys() {
    secretEl.value = "";
    b64El.checked = false;
    pubEl.value = "";
    privEl.value = "";
    verifyCurrent();
  }

  async function copyToken() {
    const text = tokenEl.value.trim();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      tokenEl.focus();
      tokenEl.select();
      document.execCommand("copy");
    }
    const previous = copyBtn.textContent;
    copyBtn.textContent = "Copiato";
    window.setTimeout(() => {
      copyBtn.textContent = previous;
    }, 1200);
  }

  function selectPart(index) {
    const token = tokenEl.value;
    const parts = token.split(".");
    let start = 0;
    for (let i = 0; i < index; i += 1) start += (parts[i] || "").length + 1;
    const part = parts[index] || "";
    tokenEl.focus();
    tokenEl.setSelectionRange(start, start + part.length);
    markPart(index);
  }

  async function onGenerate() {
    const alg = algEl.value;
    if (!Jwt.isSupported(alg)) return;
    generateBtn.disabled = true;
    const previous = generateBtn.textContent;
    generateBtn.textContent = Crypto.isHmac(alg) ? "Genero il segreto" : "Genero la chiave";
    try {
      const gen = await Crypto.generate(alg);
      if (gen.secret) {
        secretEl.value = gen.secret;
        b64El.checked = true;
      }
      if (gen.publicPem) pubEl.value = gen.publicPem;
      if (gen.privatePem) privEl.value = gen.privatePem;
      if (headerEl.value.trim() && payloadEl.value.trim()) await resign();
      else await verifyCurrent();
    } catch (err) {
      setHint(err && err.message ? err.message : "Non riesco a generare la chiave in questo browser.");
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = previous;
    }
  }

  fillAlgOptions();
  bindScroll(tokenEl, tokenPaint);
  bindScroll(headerEl, headerPaint);
  bindScroll(payloadEl, payloadPaint);

  tokenEl.addEventListener("input", onToken);
  tokenEl.addEventListener("keyup", () => markPart(partIndex(tokenEl.value, tokenEl.selectionStart || 0)));
  tokenEl.addEventListener("click", () => markPart(partIndex(tokenEl.value, tokenEl.selectionStart || 0)));
  headerEl.addEventListener("input", () => {
    if (writing) return;
    paintJson(headerPaint, headerEl.value);
    resign();
  });
  payloadEl.addEventListener("input", () => {
    if (writing) return;
    paintJson(payloadPaint, payloadEl.value);
    resign();
  });
  algEl.addEventListener("change", () => {
    syncKeyFields();
    if (!headerEl.value.trim()) {
      verifyCurrent();
      return;
    }
    try {
      const header = JSON.parse(headerEl.value);
      if (header && typeof header === "object" && !Array.isArray(header)) {
        header.alg = algEl.value;
        writing = true;
        headerEl.value = Jwt.pretty(header);
        writing = false;
        paintJson(headerPaint, headerEl.value);
      }
    } catch {
      noteFor(headerNote, "JSON dell'header non valido. Il token non è stato aggiornato.");
      return;
    }
    resign();
  });
  secretEl.addEventListener("input", () => verifyCurrent());
  b64El.addEventListener("change", () => verifyCurrent());
  pubEl.addEventListener("input", () => verifyCurrent());
  privEl.addEventListener("input", () => verifyCurrent());
  document.getElementById("example").addEventListener("click", () => loadExample());
  document.getElementById("clear").addEventListener("click", clearToken);
  document.getElementById("clear-keys").addEventListener("click", clearKeys);
  copyBtn.addEventListener("click", () => copyToken());
  generateBtn.addEventListener("click", () => onGenerate());
  document.querySelectorAll("[data-part]").forEach((button) => {
    button.addEventListener("click", () => selectPart(Number(button.dataset.part)));
  });

  const menu = document.getElementById("menu");
  const rail = document.getElementById("rail");
  const inspect = document.getElementById("inspect");
  if (menu && rail) {
    menu.addEventListener("click", () => {
      const open = rail.classList.toggle("open");
      menu.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }
  if (inspect) {
    inspect.addEventListener("click", () => {
      tokenEl.focus();
      if (rail) rail.classList.remove("open");
      if (menu) menu.setAttribute("aria-expanded", "false");
    });
  }

  loadExample().catch(() => {
    setFinding("Web Crypto non è disponibile in questa pagina.", "", "");
    setHint("Apri Sigillo da localhost. Su alcuni browser file:// nasconde la firma.");
  });
})();
