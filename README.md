# Sigillo

Banco per leggere e firmare JWT nel browser. Il token resta in questa scheda: la pagina non fa richieste di rete e non scrive nulla in archivio.

## Aprire

Va servita da localhost. Su `file://` alcuni browser non espongono Web Crypto e la firma non si può controllare.

```sh
python3 -m http.server 8765
```

Poi apri http://127.0.0.1:8765/

All'avvio c'è un token di esempio, firmato con un segreto generato in quella scheda. Va sostituito con il token proprio.

## Uso

Incolla un JWT. Header, payload e claim registrati si leggono subito. La firma si controlla con un segreto HMAC oppure con un PEM pubblico SPKI (`BEGIN PUBLIC KEY`). Per rifirmare serve il segreto, oppure un PEM privato PKCS#8 (`BEGIN PRIVATE KEY`).

Modificare header o payload rifirma il token se il materiale c'è. Cambiare algoritmo aggiorna `alg` nell'header e rifirma. `alg: none` non è mai una firma valida.

Algoritmi: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA (Ed25519). Ed25519 chiede un browser recente.

Un PEM `BEGIN RSA PRIVATE KEY`, `BEGIN RSA PUBLIC KEY` o `BEGIN EC PRIVATE KEY` viene rifiutato.

## Controllo

```sh
node assets/check.mjs
```

Confronta HMAC con Node e fa un giro di firma, verifica e token alterato per gli altri algoritmi.

## Font

I file in `fonts/` sono i subset latin di Fontsource 5.2.5. Le licenze valgono solo per i font.

- Inter, per l'interfaccia. SIL Open Font License 1.1. Testo in `fonts/inter-LICENSE.txt`.
- JetBrains Mono, per token, JSON e chiavi. SIL Open Font License 1.1. Testo in `fonts/jetbrains-mono-LICENSE.txt`.
