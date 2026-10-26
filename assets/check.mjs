import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

const code = readFileSync(new URL("./jwt.js", import.meta.url), "utf8")
  + "\n"
  + readFileSync(new URL("./crypto.js", import.meta.url), "utf8");
const { jwt, crypto: box } = new Function(`${code}\nreturn { jwt: globalThis.SigilloJwt, crypto: globalThis.SigilloCrypto };`)();

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

const input = "aaa.bbb";
const secret = "segretto-di-prova";
const mac = createHmac("sha256", secret).update(input).digest();
const expected = jwt.bytesToB64url(new Uint8Array(mac));
const signed = await box.sign("HS256", input, { secret, secretIsBase64: false, publicPem: "", privatePem: "" });
assert(signed.ok && signed.signature === expected, "HS256 non coincide con createHmac");
const checked = await box.verify("HS256", input, signed.signature, { secret, secretIsBase64: false, publicPem: "", privatePem: "" });
assert(checked.ok, "HS256 verify");
const tampered = await box.verify("HS256", "aaa.bbc", signed.signature, { secret, secretIsBase64: false, publicPem: "", privatePem: "" });
assert(!tampered.ok && tampered.reason === "invalid", "un payload alterato deve fallire");

const none = await box.verify("none", input, "", { secret: "", secretIsBase64: false, publicPem: "", privatePem: "" });
assert(!none.ok && none.reason === "none", "alg none non è una firma");

const round = jwt.decodePart(jwt.encodeJson({ luogo: "città" }));
assert(round.value.luogo === "città", "Base64url non tiene l'utf-8");

const bearer = jwt.parseToken('Bearer "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZGEifQ.x"');
assert(bearer.ok && bearer.payload.sub === "ada", "Bearer e virgolette");

const now = Date.UTC(2026, 9, 26, 8, 0, 0);
const rows = jwt.claimRows({ exp: Math.floor(now / 1000) - 7200, iss: "sigillo" }, now);
assert(rows.find((row) => row.key === "exp").tone === "bad", "exp passato è in ritardo");
assert(rows.find((row) => row.key === "sub").reading === "\u2014", "claim assente è un trattino");
assert(jwt.timeLead({ exp: Math.floor(now / 1000) + 7200, iat: Math.floor(now / 1000) }, now).text.startsWith("Scade"), "exp futuro");

for (const alg of ["HS384", "HS512", "RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"]) {
  const gen = await box.generate(alg);
  const material = {
    secret: gen.secret,
    secretIsBase64: gen.secretIsBase64,
    publicPem: gen.publicPem,
    privatePem: gen.privatePem,
  };
  const made = await box.sign(alg, input, material);
  assert(made.ok, `${alg} sign: ${made.message || ""}`);
  const verdict = await box.verify(alg, input, made.signature, material);
  assert(verdict.ok, `${alg} verify: ${verdict.message || verdict.reason}`);
  const broken = await box.verify(alg, "aaa.zzz", made.signature, material);
  assert(!broken.ok, `${alg} deve rifiutare un input diverso`);
}

console.log("ok");
