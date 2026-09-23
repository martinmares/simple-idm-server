# Plán implementace Passkeys

## Stav dokumentu

- Stav: etapa 1 dokončena; etapa 2 implementována částečně, automatizované browser E2E chybí
- Datum rozhodnutí: 23. 9. 2026
- Pokračování: po upgradu Codex CLI zahájeno 23. 9. 2026
- Rozsah: `simple-idm-server`, primárně lokálně spravované identity

## Cíl

Doplnit do Simple IDM přihlášení pomocí Passkeys postavené na WebAuthn.
Passkey nebude pouze další kód ve stávajícím TOTP kroku, ale plnohodnotná
phishing-resistant alternativa k přihlášení heslem a TOTP.

Pro lokální účet mají být podporovány dvě cesty:

```text
heslo + TOTP
nebo
Passkey s povinným ověřením uživatele
```

Po úspěšném přihlášení pomocí Passkey se již nemá vyžadovat TOTP. Passkey s
WebAuthn `user verification` sama představuje vícefaktorový kryptografický
autentikátor.

## Hranice řešení

Simple IDM bude spravovat Passkeys pouze pro identity s `auth_mode = local`.

- `local`: Passkeys registruje, ověřuje a spravuje Simple IDM.
- `federated`: Passkeys a MFA zůstávají odpovědností upstream IdP.
- `ad`: autentizační politika zůstává odpovědností AD nebo navazující identity
  infrastruktury.

Federovaní ani AD uživatelé nesmí dostávat druhou, nesouvisející WebAuthn výzvu
od Simple IDM.

## Schválená produktová rozhodnutí

1. Passkeys budou uložené v samostatné tabulce, nikoliv v existující tabulce
   `user_authenticators` určené pro TOTP.
2. Jeden uživatel může mít více Passkeys.
3. Registrace Passkey je možná pouze z přihlášené session a po čerstvém ověření
   uživatele.
4. WebAuthn musí vždy vyžadovat `user verification`.
5. První verze použije username-first přihlášení. Conditional UI a
   usernameless přihlášení přijdou později.
6. Heslo + TOTP zůstane během adopce jako fallback.
7. Produkční RP ID a povolené origins budou explicitní konfigurace. Nesmí se
   slepě odvozovat z HTTP `Host` ani z nedůvěryhodných proxy hlaviček.
8. Krátkodobý stav registrační a autentizační ceremony bude uložen na serveru,
   bude jednorázový a bude mít krátké TTL.
9. Pro více instancí serveru se stav uloží v PostgreSQL, nikoliv pouze v paměti
   procesu.
10. Výchozí attestation bude `none`. Enterprise attestation bude případné
    pozdější, volitelné rozšíření.

## Datový model

### Passkeys

Navrhovaná samostatná tabulka:

```text
user_passkeys
├── id                    UUID PRIMARY KEY
├── tenant_id             UUID NOT NULL
├── user_id               UUID NOT NULL
├── credential_id         BYTEA NOT NULL UNIQUE
├── passkey_data          JSONB NOT NULL
├── label                 TEXT NOT NULL
├── transports            JSONB
├── backup_eligible       BOOLEAN
├── backup_state          BOOLEAN
├── created_at            TIMESTAMPTZ NOT NULL
├── updated_at            TIMESTAMPTZ NOT NULL
├── last_used_at          TIMESTAMPTZ
└── revoked_at            TIMESTAMPTZ
```

Požadavky:

- `credential_id` musí být unikátní napříč všemi účty, nejen v rámci jednoho
  uživatele.
- Credential se nikdy nesmí přiřadit více identitám.
- Privátní klíč se v Simple IDM neukládá; server uchovává veřejný credential a
  metadata potřebná k ověření.
- Po úspěšné autentizaci se musí atomicky aktualizovat stav credentialu,
  zejména počítadlo a backup flags poskytované knihovnou.
- Revokace bude logická a auditovaná; fyzické mazání se může řídit existující
  delete policy.

### WebAuthn transakce

Navrhované tabulky:

```text
webauthn_registration_transactions
webauthn_authentication_transactions
```

Každá transakce musí obsahovat alespoň:

- hash náhodného opaque tokenu předaného browseru,
- serverový WebAuthn ceremony state,
- tenant a uživatele, pokud jsou v dané fázi známí,
- původní OAuth/OIDC authorization parametry,
- počet neúspěšných pokusů,
- čas vytvoření a expirace,
- typ operace a požadovanou úroveň ověření.

Transakce musí být po úspěšném dokončení atomicky spotřebována. Expirace bude
řádově v minutách a staré záznamy se budou průběžně uklízet.

## Konfigurace

Navrhované proměnné:

```text
WEBAUTHN_RP_ID=idm.example.com
WEBAUTHN_RP_NAME=Simple IDM
WEBAUTHN_ORIGINS=https://idm.example.com
```

Pravidla:

- Produkční origin musí používat HTTPS.
- Lokální vývoj může podporovat bezpečnou výjimku pro `localhost`.
- RP ID musí být stabilní. Změna RP ID zneplatní dříve registrované Passkeys.
- Seznam origins se musí validovat explicitně a přesnou shodou.
- `JWT_ISSUER` může sloužit jako kontrolovaný výchozí údaj, ale produkční
  konfigurace WebAuthn musí být viditelná a ověřitelná samostatně.
- Nasazení za proxy se nesmí spoléhat na libovolné klientské
  `X-Forwarded-Host` nebo `X-Forwarded-Proto`.

## Backendové flow

### Registrace Passkey

1. Uživatel otevře `My account -> Security` v platné session.
2. Server vyžádá recent authentication.
3. Uživatel se ověří existující Passkey nebo heslem a případně TOTP podle
   aktuální politiky.
4. Server vytvoří registration challenge, předá všechny uživatelovy existující
   credential IDs v `excludeCredentials` a uloží ceremony state na serveru.
5. Browser zavolá `navigator.credentials.create()`.
6. Server ověří odpověď bezpečným high-level API knihovny.
7. Server znovu ověří globální unikátnost credential ID a uloží Passkey.
8. Transakce se jednorázově spotřebuje a vznikne auditní událost.

Admin nesmí Passkey uživateli vytvořit ani nahrát. Může pouze zobrazit stav,
credential revokovat nebo zahájit recovery/reset proces.

### Přihlášení pomocí Passkey

První verze bude username-first:

1. Uživatel zadá e-mail nebo login.
2. Zvolí `Continue with passkey`.
3. Server načte aktivní Passkeys uživatele, vytvoří authentication challenge a
   uloží ceremony state společně s pending OAuth/OIDC authorization daty.
4. Browser zavolá `navigator.credentials.get()`.
5. Server atomicky spotřebuje transakci, ověří assertion a aktualizuje stav
   credentialu.
6. Existující dokončení authorization flow vydá code/session s odpovídajícím
   `amr` a `acr`.

Odpovědi start endpointu, časování a throttling nesmí zbytečně umožnit
enumeraci účtů.

### Autentizační kontext

Navrhované úrovně:

```text
urn:simple-idm:acr:password
urn:simple-idm:acr:mfa
urn:simple-idm:acr:phishing-resistant
```

Konkrétní `amr` hodnoty je nutné před implementací sjednotit s existujícím
OIDC modelem. Server nesmí tvrdit, že zná konkrétní biometrickou metodu; z
WebAuthn bezpečně vyhodnocuje pouze ověřené protocol flags, zejména UP a UV.

## Uživatelské rozhraní

### Login

První návrh:

```text
Email
[ Continue with passkey ]

---------- or ----------

Password
MFA or recovery code
[ Sign in ]
```

Conditional UI a `autocomplete="username webauthn"` nejsou součástí první
etapy.

### My account -> Security

Uživatel musí vidět:

- seznam aktivních Passkeys,
- uživatelský label,
- datum registrace,
- poslední použití,
- dostupnou informaci o možnosti zálohování nebo synchronizaci,
- akci pro přejmenování,
- akci pro revokaci,
- tlačítko `Add another passkey`.

UI nesmí z AAGUID nebo transportu bez dostatečných důkazů tvrdit, že jde o
konkrétní fyzické zařízení.

### Admin UI

Admin u uživatele uvidí počet a stav Passkeys a může provést:

- revokaci konkrétní Passkey,
- reset všech Passkeys,
- reset všech lokálních autentikátorů včetně TOTP a recovery kódů.

`Reset MFA` a `Reset Passkeys` mají být odlišné operace. Každá destruktivní
operace musí vyžadovat potvrzení, být auditovaná a ukončit relevantní aktivní
session a rozpracované autentizační transakce.

## Tenant policy

Stávající `mfa_policy` se v první etapě nebude přejmenovávat ani přetěžovat.
Vedle něj vznikne samostatná politika:

```text
passkey_policy = disabled | allowed | required
```

První vydání implementuje pouze:

- `disabled`
- `allowed`

Režim `required` se smí zpřístupnit až po dokončení a otestování:

- více Passkeys na uživatele,
- ochrany proti odstranění posledního použitelného autentikátoru,
- admin recovery,
- recovery pro ztracené zařízení,
- dostatečných auditních událostí,
- migračního a rollback postupu.

TOTP nebo recovery fallback snižuje phishing resistance výsledného účtu. Je to
přijatelný migrační kompromis, ale login a audit musí rozlišovat Passkey,
heslo + TOTP a recovery code.

## Knihovna a kryptografické hranice

Preferovaná knihovna je `webauthn-rs` a její bezpečné high-level API. Vlastní
implementace WebAuthn validace se vytvářet nebude.

Před implementací je nutné znovu ověřit:

- aktuální podporovanou verzi knihovny,
- bezpečnostní advisories,
- kompatibilitu s aktuálním Rust toolchainem,
- způsob bezpečného serverového uložení ceremony state,
- podporované algoritmy a jejich bezpečné defaults.

Nepoužívat starší verzi se známou chybou validace origin/subdomain. Nezapínat
`danger-*` features bez zdokumentovaného důvodu a cíleného bezpečnostního
review.

## Recovery a provozní pravidla

- Doporučit uživateli registraci alespoň dvou Passkeys.
- Recovery codes zůstávají jednorázové a hashované.
- Přidání první Passkey nesmí automaticky odstranit heslo ani TOTP.
- Odstranění poslední Passkey je možné pouze tehdy, pokud účtu zůstane jiná
  povolená autentizační cesta.
- Passkey-only režim nebude součástí první verze.
- Změna hesla, reset MFA nebo zásah administrátora musí mít jasně definovaný
  dopad na Passkeys; výchozí návrh je samostatná revokace, nikoliv tiché
  odstranění všech Passkeys při běžné změně hesla.
- Každá registrace, úspěšné a neúspěšné použití, revokace a recovery operace
  budou auditované bez ukládání citlivého ceremony payloadu.

## Testovací strategie

### Unit a integrační testy

- registration start/finish,
- authentication start/finish,
- expirovaná, opakovaně použitá a cizí transakce,
- chybný challenge, origin a RP ID,
- chybějící UP nebo UV,
- credential patřící jinému účtu nebo tenantovi,
- globální duplicita credential ID,
- aktualizace counteru a backup flags,
- deaktivovaný nebo smazaný uživatel,
- revokovaná Passkey,
- tenant policy `disabled` a `allowed`,
- zachování OAuth/OIDC parametrů, PKCE, nonce a state,
- správné `amr` a `acr`,
- race při dvojím dokončení stejné ceremony,
- throttling a auditní události.

### Browser E2E

- Chromium virtual authenticator přes WebDriver/Playwright,
- registrace první a druhé Passkey,
- login a následný OIDC redirect,
- odebrání Passkey,
- heslo + TOTP fallback,
- nasazení za reverzní proxy se správnou veřejnou origin,
- negativní test neautorizované origin.

### Manuální kompatibilita

- Windows Hello,
- macOS/iOS Passkeys,
- Android Passkeys,
- externí FIDO2 bezpečnostní klíč,
- aktuální Chromium, Firefox a Safari podle podporované platformy.

## Etapy implementace

### Etapa 1: WebAuthn základ

- závislost a centrální WebAuthn konfigurace,
- validační pravidla RP ID a origins,
- databázové migrace,
- serverové ceremony transakce,
- registration a authentication service,
- unit a integrační testy.

Průběžný stav: migrace `042_add_passkeys.sql`, explicitní konfigurace RP,
serverový `PasskeyService` a základní validační testy jsou implementované.
HTTP endpointy a uživatelské UI pro registraci, přihlášení a správu Passkeys
jsou dostupné pro lokální účty s politikou `allowed`. Admin UI nabízí počet
aktivních klíčů a samostatný reset všech Passkeys. Metadata `transports` se
zatím nesbírají a backup flags se doplní při prvním úspěšném přihlášení;
samotný WebAuthn credential je uchován v `passkey_data`. Browser flow bylo
ověřeno ručně v Chromium s virtuálními autentikátory; automatizovaný E2E test
a testy fyzických zařízení zůstávají otevřené.

### Etapa 2: Uživatelský produkt

- username-first Passkey login,
- `My account -> Security`,
- více Passkeys a jejich labely,
- revoke/reset,
- audit,
- admin stav a bezpečné recovery operace,
- browser E2E testy.

### Etapa 3: Rozšířené politiky

- conditional UI a usernameless přihlášení,
- `passkey_policy = required`,
- Passkey-only účty,
- enterprise attestation a spravované typy autentikátorů,
- pokročilé step-up a klientské ACR požadavky.

## Kritéria dokončení první verze

První verze je hotová, pokud:

1. lokální uživatel bezpečně zaregistruje alespoň dvě Passkeys;
2. pomocí Passkey dokončí běžný OAuth2/OIDC authorization flow bez hesla a
   TOTP;
3. server vyžaduje UV a striktně validuje RP ID, origin, challenge a
   jednorázový stav;
4. credential nelze použít pro jiného uživatele nebo tenant;
5. funguje heslo + TOTP fallback;
6. uživatel i admin mohou Passkey bezpečně revokovat;
7. relevantní session, reset a recovery scénáře jsou otestované;
8. operace jsou auditované a dokumentované;
9. restart nebo více instancí serveru nerozbije rozpracovanou ceremony;
10. současné federované a AD login flow zůstane beze změny.

## Referenční materiály

- W3C Web Authentication Level 3: <https://www.w3.org/TR/webauthn/>
- `webauthn-rs`: <https://github.com/kanidm/webauthn-rs>
- `webauthn-rs` high-level API:
  <https://docs.rs/webauthn-rs/latest/webauthn_rs/struct.Webauthn.html>
- NIST SP 800-63B: <https://pages.nist.gov/800-63-4/sp800-63b.html>
