# OtonomMCP External IdP

OtonomMCP için **yerel, passkey (WebAuthn / Windows Hello) tabanlı kimlik sağlayıcı**.
OtonomMCP bir insan onayı (ör. `aidm_autonomous_start`) ya da Director'ın sorduğu bir karar
gerektiğinde bu sunucuya istek açar; sen tarayıcıda isteği görür, **Windows Hello ile** onaylar/cevaplarsın;
IdP, OtonomMCP'nin `OidcIdentityProviderAdapter`'ının kabul ettiği **ES256 imzalı** bir token üretir.

- HTTP sunucu: `node:http`, varsayılan `http://127.0.0.1:7443` (yalnızca loopback)
- Kalıcılık: Node 22'nin yerleşik `node:sqlite` modülü (native derleme yok, Windows'ta sorunsuz)
- WebAuthn: `@simplewebauthn/server` + `@simplewebauthn/browser` (tarayıcı paketi yerelden sunulur, CDN yok)
- İmza: kalıcı ES256 (P-256) anahtar, `kid` = RFC 7638 JWK thumbprint
- Parola yok: giriş ve her onay **passkey + kullanıcı doğrulaması (UV)** ister

## Gereksinimler (Windows)

1. **Node.js 22** (22.5 veya üstü): <https://nodejs.org> → "22.x LTS" Windows Installer. Kontrol: `node -v`
2. Windows Hello (PIN, parmak izi veya yüz) açık olmalı: *Ayarlar → Hesaplar → Oturum açma seçenekleri*.
3. Chrome veya Edge (güncel).

```powershell
cd "D:\ÇALIŞMALAR-D\OtonomMCP-External-IdP"
npm ci
npm test            # tüm testler
npm start           # derler ve çalıştırır
```

Geliştirme için `npm run dev` (değişiklikte otomatik derleme + yeniden başlatma).

## İlk çalıştırma

`npm start` ilk açılışta konsola şunları yazar:

```
[idp] Generated new ES256 signing key (kid …).
[idp] Generated OtonomMCP client token. Copy it into AIDM_IDP_CLIENT_TOKEN from: D:\…\data\client-token.txt
[idp] First run: one-time setup code = 1A2B3C-4D5E6F-7A8B9C  (open http://localhost:7443/ …)
[idp] OtonomMCP pin: AIDM_IDP_PUBLIC_KEY_FILE=D:\…\data\public-key.pem
```

`data\` klasörü (git'e girmez) şunları içerir:

| Dosya | İçerik |
|---|---|
| `idp.sqlite` | kullanıcılar, passkey'ler, istekler, kararlar, audit log, anahtar kaydı |
| `signing-key.pem` | **özel imza anahtarı** – kimseyle paylaşma, loglanmaz |
| `public-key.pem` | OtonomMCP'nin sabitleyeceği (pin) açık anahtar |
| `client-token.txt` | OtonomMCP'nin API çağrılarında kullanacağı bearer token |

> Windows'ta dosya izinleri kullanıcı profilinin ACL'ini miras alır; `data\` klasörünü yalnızca senin
> erişebildiğin bir yerde tut (ör. kendi kullanıcı klasörün veya D: altındaki kişisel klasörün).

### Passkey kaydı (Windows Hello) – insan adımı

1. Tarayıcıda **http://localhost:7443/** aç (127.0.0.1 değil, `localhost` – passkey RP ID'si `localhost`).
2. "İlk kurulum" ekranında konsoldaki **kurulum kodunu**, kullanıcı adını ve görünen adını gir.
3. "Passkey oluştur (Windows Hello)" → Windows Hello penceresinde PIN/parmak izi ile onayla.
4. Hesap `PRODUCT_OWNER` rolüyle oluşur, kurulum kodu geçersizleşir. İstersen ana sayfadan
   "Yedek passkey ekle" ile ikinci bir passkey (ör. telefon veya güvenlik anahtarı) ekle.

Kurulum kodunu sabitlemek istersen başlatmadan önce `$env:IDP_SETUP_CODE = "en-az-8-karakter"`.
Kurulum bitmeden sunucuyu yeniden başlatırsan yeni bir kod üretilir.

## OtonomMCP ayarları

OtonomMCP'yi çalıştırdığın PowerShell penceresinde (veya MCP config'in `env` bölümünde):

```powershell
$env:AIDM_IDP_URL = "http://127.0.0.1:7443"
$env:AIDM_IDP_CLIENT_TOKEN = (Get-Content "D:\ÇALIŞMALAR-D\OtonomMCP-External-IdP\data\client-token.txt").Trim()
$env:AIDM_IDP_ISSUER = "otonommcp-external-idp"
$env:AIDM_IDP_AUDIENCE = "otonommcp"
$env:AIDM_IDP_PUBLIC_KEY_FILE = "D:\ÇALIŞMALAR-D\OtonomMCP-External-IdP\data\public-key.pem"
```

`IDP_ISSUER` / `IDP_AUDIENCE` değiştirirsen OtonomMCP tarafındaki `AIDM_IDP_ISSUER` / `AIDM_IDP_AUDIENCE` aynı olmalı.
Anahtarı JWKS üzerinden almak yerine **dosyayla sabitlemek (pin)** önerilir.

## Bir isteği onaylama

1. OtonomMCP onay ya da karar istediğinde `approvalUrl` / `decisionUrl` döner (ör. `http://localhost:7443/#/approvals/<id>`).
2. Linki aç → passkey ile giriş yap.
3. Detay sayfasında **özet** ve token'a imzalanacak **tüm bağlam alanlarını** (projectId, packageId, revision,
   contextFingerprint, specFingerprint, operation, directorSessionId, taskId, nonce, son geçerlilik) kontrol et.
4. **"Windows Hello ile ONAYLA"** → Windows Hello. Bu, **yalnızca o requestId'ye bağlı** taze bir passkey doğrulamasıdır.
   Reddetmek için gerekçe yazıp "Reddet".
5. Karar isteklerinde seçeneklerden birini seç (önerilen işaretli), istersen serbest metin yaz, "Windows Hello ile GÖNDER".

Her istek **bir kez** karara bağlanabilir; süresi dolan (en fazla 15 dk) istekler onaylanamaz.
Token ömrü en fazla 5 dakikadır; OtonomMCP `GET /api/approval-requests/:id` ile token'ı alır.

## API (OtonomMCP ⇄ IdP sözleşmesi)

Tüm `/api/*` makine uçları `Authorization: Bearer <AIDM_IDP_CLIENT_TOKEN>` ister.

| Uç | Açıklama |
|---|---|
| `POST /api/approval-requests` | `{ requestId(uuid), projectId, packageId, revision, contextFingerprint, specFingerprint, directorSessionId?, taskId?, operation, nonce(>=16), summary, requestedAt, expiresAt(<=15dk) }` → `201 { requestId, status:'PENDING', approvalUrl, expiresAt }` |
| `GET /api/approval-requests/:id` | `{ requestId, status: PENDING\|APPROVED\|REJECTED\|EXPIRED, token? (yalnız APPROVED), reason? }` |
| `POST /api/decision-requests` | `{ decisionId(uuid), projectId, runId, taskId, packageId, revision, operation:'AUTONOMOUS_DECISION', contextFingerprint, question, options[2..6]{id,label,description?}, allowFreeText, recommendedOptionId?, nonce, summary?, requestedAt, expiresAt }` → `201 { decisionId, status:'PENDING', decisionUrl, expiresAt }` |
| `GET /api/decision-requests/:id` | `{ decisionId, status: PENDING\|ANSWERED\|EXPIRED, token? }` |
| `GET /api/status` | heartbeat: sürüm, uptime, kid, issuer/audience, bekleyen sayıları |
| `GET /healthz` | (auth yok) sağlık kontrolü |
| `GET /.well-known/jwks.json`, `GET /api/public-key.pem` | (auth yok) ES256 açık anahtar + `kid` |

Doğrulama sıkıdır: bilinmeyen alan → 400, tekrar eden `requestId`/`decisionId`/`nonce` → 409, gövde > 64 KB → 413.

**Onay token'ı** (JWS ES256, başlık `{alg:'ES256', typ:'JWT', kid}`, imza raw R‖S):
`iss, aud, sub, preferred_username, actorRole:'PRODUCT_OWNER', nonce (istekteki), jti, iat, nbf, exp (≤ iat+300),
requestId, decision:'APPROVED', amr:['webauthn'], uv:true, projectId, packageId, revision, contextFingerprint,
specFingerprint, operation, directorSessionId?, taskId?`

**Karar token'ı**: `iss, aud, sub, preferred_username, actorRole, nonce, jti, iat, nbf, exp, decisionId, selectedOptionId?, freeText?,
projectId, runId, taskId, packageId, revision, operation:'AUTONOMOUS_DECISION', contextFingerprint, amr:['webauthn'], uv:true`
(sözleşme v1.1: OtonomMCP doğrulayıcısı packageId/revision olmayan token'ı reddettiği için bu alanlar zorunludur).

## Ortam değişkenleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `IDP_HOST` | `127.0.0.1` | dinlenen adres (loopback dışı önerilmez) |
| `IDP_PORT` | `7443` | port |
| `IDP_DATA_DIR` | `./data` | SQLite + anahtarlar |
| `IDP_ISSUER` | `otonommcp-external-idp` | token `iss` |
| `IDP_AUDIENCE` | `otonommcp` | token `aud` |
| `IDP_RP_ID` | `localhost` | WebAuthn RP ID |
| `IDP_ORIGIN` | `http://localhost:<port>` | WebAuthn origin + UI linkleri |
| `IDP_CLIENT_TOKEN` | (üretilir) | OtonomMCP bearer token (≥ 32 karakter) |
| `IDP_SETUP_CODE` | (üretilir) | ilk kurulum kodu (≥ 8 karakter) |
| `IDP_TOKEN_TTL_SECONDS` | `300` | token ömrü (30–300) |
| `IDP_SESSION_TTL_SECONDS` | `28800` | tarayıcı oturumu |
| `IDP_AUTH_RATE_LIMIT` | `20` | giriş/WebAuthn uçları, dakika başına IP başına |
| `IDP_API_RATE_LIMIT` | `300` | makine API, dakika başına |

## Güvenlik özeti

- Passkey-only; `userVerification: 'required'`; origin, RP ID, imza, UP/UV bayrakları ve **sayaç gerilemesi** kontrol edilir.
- Challenge'lar sunucuda saklanır, tek kullanımlıktır (başarısız denemede de yanar), 5 dk geçerlidir ve
  tarayıcı oturumuna, kullanıcıya ve onaylarda **ilgili requestId/decisionId'ye** bağlıdır.
- Çerezler `HttpOnly; SameSite=Strict`; değiştiren tüm UI çağrıları aynı `Origin` + `X-CSRF-Token` ister.
- CSP `script-src 'self'` (inline script yok), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`;
  Host başlığı kontrolü (DNS rebinding), JSON gövde sınırı, giriş uçlarında rate limit.
- UI tüm sunucu verisini `textContent` ile basar (innerHTML yok).
- Tüm durum geçişleri SQLite `BEGIN IMMEDIATE` işlemleriyle atomik; her istek bir kez karara bağlanır; audit log tutulur.

## Testler ve sözleşme kontrolü

```powershell
npm test                 # jest: DB/migration, anahtar, JWKS, API, doğrulama, durum makinesi, WebAuthn (yazılım authenticator), UI XSS
npm run contract-check   # gerçek token'ı OtonomMCP'nin OidcIdentityProviderAdapter'ı ile doğrular
```

`contract-check`, OtonomMCP'yi varsayılan olarak kardeş klasörde (`..\OtonomMCP`) arar ve
`packages\core\dist` derlenmiş olmalıdır (IdP bağlantısını içeren dal, ör. `feat/external-idp-approval`):

```powershell
cd "D:\ÇALIŞMALAR-D\OtonomMCP"; npm run build
cd "D:\ÇALIŞMALAR-D\OtonomMCP-External-IdP"
$env:OTONOMMCP_DIR = "D:\ÇALIŞMALAR-D\OtonomMCP"; npm run contract-check
```

`contract-check` hem **onay** token'ını (adapter + `verifyIdpToken`) hem de **karar** token'ını
(OtonomMCP'nin `buildDecisionRecord` + `IdpDecisionResolver.verify` yolu) doğrular.

Uçtan uca (gerçek IdP süreci ⇄ gerçek OtonomMCP, LLM ve AGY mock):

```powershell
$env:OTONOMMCP_CORE = "D:\ÇALIŞMALAR-D\OtonomMCP\packages\core"; npm run e2e
```

Bu, IdP'yi ayrı süreç olarak başlatır; OtonomMCP `aidm_autonomous_start` ile onay isteği açar, yazılım
authenticator passkey ile onaylar, `aidm_autonomous_resume` token'ı doğrulayıp çalıştırmayı yürütür, Director'ın
sorduğu karar IdP'de passkey ile cevaplanır ve çalıştırma tamamlanır; ret yolu da denenir.

Yazılım authenticator (`src/testing/soft-authenticator.ts`) gerçek WebAuthn biçiminde cevap üretir
(CBOR `attestationObject` fmt `none`, UP+UV bayraklı authenticatorData, origin/challenge'lı clientDataJSON),
böylece `@simplewebauthn/server`'ın gerçek doğrulaması test edilir. Sunucu çalışırken kullanılmaz.

## Sorun giderme

- **"Unexpected Host header" (421)**: tarayıcıda `http://localhost:7443` kullan; farklı bir host gerekiyorsa `IDP_ORIGIN` ayarla.
- **Windows Hello penceresi açılmıyor**: adres `localhost` olmalı (IP değil); Windows Hello PIN'i tanımlı olmalı.
- **localhost açılmıyor**: bazı sistemlerde `localhost` önce `::1`'e çözülür; `IDP_HOST=localhost` ile başlatmayı dene.
- **Token OtonomMCP'de SIGNATURE_INVALID**: OtonomMCP dalı ES256 raw R‖S düzeltmesini içermeli ve yeniden derlenmeli;
  `AIDM_IDP_PUBLIC_KEY_FILE` güncel `data\public-key.pem`'i göstermeli.
