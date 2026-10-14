# Simple IDM

Všech 13 crates sdílí jednu verzi přes `version.workspace = true`.
Další vydání připravíš pomocí `just release-version 0.12.2`;
[postup vydávání](docs/RELEASING.md) popisuje GitHub i GitLab pipeline.

Simple IDM je OAuth2/OIDC identity stack napsaný v Rustu. Cíl projektu je provozovat vlastní SSO, řídit groups/claims efektivněji než běžné cloudové IdP a přitom podporovat legacy aplikace, SSH certifikáty i delegované ověření přes Google/OIDC nebo AD/LDAP.

Export uživatelů z Google Workspace a následný CLI import s náhledem popisuje
[návod pro Directory API](docs/GOOGLE_WORKSPACE_EXPORT.cs.md). Export nemění Google ani IDM;
import zapisuje až s explicitním `--apply`.

## Komponenty

- `simple-idm-server` - OAuth2/OIDC server, Admin API a Admin Web UI
- `simple-idm-ctl` - CLI a TUI klient pro správu
- `simple-idm-oauth2-proxy` - OIDC proxy pro legacy aplikace a nginx `auth_request`
- `simple-idm-ssh-login` - klient pro SSH login přes certifikát
- `simple-idm-ssh-signer` - služba podepisující SSH certifikáty
- `simple-idm-core` - sdílená serverová knihovna
- `simple-idm-ad-auth` - ověření hesla a stažení profilu/rolí z AD/LDAP
- `simple-idm-ldap-sync` - mapování externích rolí na lokální groups

## Hlavní Funkce

- OAuth2 Authorization Code Flow s PKCE
- OAuth2 Device Flow
- OAuth2 Client Credentials Flow pro M2M klienty
- OIDC discovery a JWKS endpoint
- refresh tokeny a SSO sessions
- lokální hesla uložená jako Argon2 hash
- TOTP MFA podle tenanta, jednorázové recovery kódy a auditovaný admin reset pro lokálně spravované účty
- federované přihlášení přes Google/OIDC
- delegované ověření hesla přes AD/LDAP provider
- sync AD/LDAP rolí a mapování na interní groups
- nested groups a effective groups
- virtual groups
- per-client claim maps
- Admin Web UI v Tabler stylu
- CLI klient pro login, sessions a automatizaci
- soft delete model pro admin-managed entity

## Požadavky

- Rust stable
- PostgreSQL 14+
- `sqlx-cli`
- RSA klíče pro podepisování JWT
- `IDP_SECRETS_MASTER_KEY` pokud se ukládají identity provider secrets

Instalace `sqlx-cli`:

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

## Bootstrap for dummies

První instalaci na Linux proveď v tomto pořadí. Podrobný
[Linux bootstrap návod](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md) obsahuje příkazy,
ukázkový `.env` i systemd unit; začni u něj, pokud ještě nemáš server připravený.

1. **Připrav PostgreSQL**: vytvoř databázovou roli, její heslo a databázi.
   [Postup a přehled tajemství](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#čím-nahradit-původní-redacted-hodnoty).
2. **Připrav Linux**: založ účet `simple-idm`, nainstaluj binárku a vytvoř adresáře.
   [Účet služby](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#1-vytvoř-linuxového-uživatele)
   a [instalace binárky](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#2-nainstaluj-binárku-a-připrav-adresáře).
3. **Vygeneruj klíče**: vytvoř JWT RSA pár a master key pro šifrování secrets.
   [Generování klíčů](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#3-vygeneruj-jwt-klíče).
4. **Vyplň konfiguraci**: nastav DB připojení, veřejný issuer a cesty ke klíčům.
   [Ukázka `.env`](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#4-připrav-env).
5. **Spusť službu**: vytvoř unit, povol linger a zapni automatický start.
   [Systemd unit](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#5-vytvoř-systemd-user-unit),
   [linger](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#6-povol-linger-a-spusť-user-manager)
   a [start služby](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#7-povol-a-spusť-službu).
6. **Nastav admin přístup**: přes dočasný bootstrap token vytvoř administrátora
   a ověř jeho oprávnění před odstraněním tokenu.
   [První administrátor](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#první-admin-přístup).
7. **Ověř provoz**: zkontroluj health, veřejné HTTPS, discovery a login.
   [Kontrola instalace](docs/LINUX_SYSTEMD_BOOTSTRAP.cs.md#ověření-veřejné-instalace).

## Rychlý Start

Vytvoření databáze:

```bash
createdb simple_idm
```

Vygenerování klíčů:

```bash
./scripts/generate_keys.sh
```

Konfigurace:

```bash
cp .env.example .env
```

Migrace:

```bash
cargo sqlx migrate run
```

Start serveru:

```bash
cargo run -p simple-idm-server --bin simple-idm-server
```

Admin Web UI:

```text
http://localhost:8080/admin/ui
```

## Konfigurace

Důležité proměnné:

```env
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
DATABASE_URL=postgres://postgres:postgres@localhost/simple_idm

JWT_ISSUER=http://localhost:8080
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
JWT_KEY_ID=default-key-2025
ACCESS_TOKEN_EXPIRY_SECONDS=3600
REFRESH_TOKEN_EXPIRY_SECONDS=2592000

ADMIN_ROOT_TOKEN=

AUTH_ALLOW_USERNAME_LOGIN=true
ALLOWED_EMAIL_DOMAINS=

ONBOARDING_TOKEN_TTL_SECONDS=86400
ONBOARDING_TOKEN_CLEANUP_INTERVAL_SECONDS=3600
IDP_SECRETS_MASTER_KEY=

UI_BRAND_NAME=Cloud App
UI_BRAND_DOMAIN=
UI_PAGE_TITLE=Simple IDM
```

UI customizace je záměrně omezená jen na tyto textové popisky. Barvy, layout,
dark/light chování a assety zůstávají konzistentní napříč Simple službami přes
embedované Tabler Admin UI assety.

`JWT_ISSUER` musí odpovídat veřejné URL serveru. Používá se jako issuer v tokenech a jako základ pro generované callback URL.

Produkční příklad:

```env
JWT_ISSUER=https://sso.example.com
```

## Šifrování Secretů

Secrets identity providerů a autentikátorů se ukládají do DB šifrovaně:

- OIDC client secret
- Google client secret
- AD/LDAP bind password
- pending a aktivní TOTP seed

Nastav:

```env
IDP_SECRETS_MASTER_KEY=<base64_32B_key>
```

Vygenerování:

```bash
openssl rand -base64 32
```

Formát uloženého secretu:

```text
EncSimple[@api=2.0:@box=<base64(nonce||ciphertext||tag)>]
```

Bez re-encryptu existujících dat neměň `IDP_SECRETS_MASTER_KEY`.

## Callback URL

### Simple IDM jako OAuth2/OIDC Provider

U běžných OAuth2 klientů je callback URL hodnota z `redirect_uris` v `Clients`.

Příklady:

```text
https://app.example.com/auth/callback
http://127.0.0.1:55236/callback
```

Server validuje `redirect_uri` z `/oauth2/authorize` proti registrovanému klientovi.

### Federated Onboarding Callback

Používá se při invitation flow, kdy admin propojí lokálního uživatele s upstream providerem.

Formát:

```text
{JWT_ISSUER}/federated/onboarding/{provider_slug}/callback
```

Příklad:

```text
https://sso.example.com/federated/onboarding/google/callback
```

Tuhle URL je potřeba registrovat v upstream provideru, například v Google OAuth Client settings.

### Federated Login Callback

Používá se při normálním interaktivním loginu, pokud Simple IDM přesměruje uživatele na upstream OIDC provider.

Formát:

```text
{JWT_ISSUER}/oauth2/federated/{provider_slug}/callback
```

Příklad:

```text
https://sso.example.com/oauth2/federated/google/callback
```

Pokud provider používáš pro běžný login, musí být tato URL také registrovaná v upstream IdP.

### AD/LDAP

AD/LDAP nemá OAuth callback URL. Ověření probíhá přímým LDAPS/StartTLS bindem ze Simple IDM serveru na LDAP server.

AD onboarding stránka:

```text
{origin}/ad/onboarding?token=...
```

Uživatel zadá AD login/heslo, Simple IDM ověří heslo přes vybraný `ad_ldap` provider, stáhne profil a role a uloží sync stav.

### Device Flow

Device flow nemá callback URL.

Endpointy:

```text
POST /oauth2/device/authorize
GET  /device
POST /oauth2/device/verify
POST /oauth2/device/token
```

Ověřovací URL:

```text
{JWT_ISSUER}/device
{JWT_ISSUER}/device?user_code=XXXX-XXXX
```

## Identity Providers

Konfigurace je v Admin Web UI:

```text
Admin UI -> Identity providers
```

Podporované typy:

- `google`
- `oidc`
- `ad_ldap`

### Google / OIDC

Používají OAuth2/OIDC redirect flow.

Typické položky:

- slug
- issuer
- client ID
- client secret
- scopes
- optional hosted domain
- optional authorization/token/JWKS URL

Google:

```text
issuer: https://accounts.google.com
scopes: openid profile email
```

Authorization URL, Token URL a JWKS URL obvykle nech prázdné. Načtou se přes discovery.

### AD/LDAP Provider

AD/LDAP se konfiguruje jako identity provider:

```text
provider_type: ad_ldap
```

Typické položky:

- host
- port
- base DN
- user filter
- TLS mode: `ldaps` nebo `starttls`
- timeout
- allow insecure TLS pro test
- bind DN/login
- bind password
- domény
- nastavení role sync

Příklad filtru:

```text
(|(mail={login})(sAMAccountName={login})(userPrincipalName={login}))
```

Uživatel musí mít:

```text
auth_mode = ad
auth_provider_id = <ad_ldap provider id>
```

Role z AD/LDAP se ukládají per-provider a mapují se na lokální groups přes AD role mappings.

## Auth Módy Uživatelů

- `local` - heslo je uložené lokálně jako Argon2 hash
- `federated` - identita se ověřuje přes Google/OIDC provider
- `ad` - heslo se ověřuje přes vybraný AD/LDAP provider

U `federated` probíhá propojení přes invitation a admin approval. Finální vazba je přes upstream `issuer + subject`, ne jen přes email.

Při běžném browser přihlášení použij na OAuth2 login stránce tlačítko
`Continue with Google` (nebo název svého OIDC providera). Nabízejí se pouze
aktivní Google/OIDC providery v tenantu OAuth klienta. Heslový formulář je
určen pro lokální a AD/LDAP účty; Google heslo do něj nezadávej. Invitation
slouží k prvotnímu propojení identity, nikoliv k běžnému přihlášení.

U `ad` rozhoduje `auth_provider_id`, přes který AD/LDAP provider se ověřuje heslo, onboarding a role sync.

## MFA Pro Spravované Tenanty

Simple IDM aplikuje vlastní MFA politiku pouze na účty s módem `local`. Účty s
autentizací `federated` nebo `ad` nadále přebírají MFA od upstream identity
providera nebo AD. Uživatel tak neprochází dvěma nesouvisejícími MFA výzvami a
hranice důvěry zůstává jednoznačná.

Každý tenant má jednu z těchto politik, nastavitelnou v **Admin UI → Tenants**:

Migrace `044_add_domain_auth_policies.sql` přidává přepsání podle e-mailové domény
v **Tenants / domains → Edit domain**. MFA nabízí `inherit`, `disabled`, `optional`
a `required`; passkeys nabízí `inherit`, `disabled` a `allowed`. `inherit` převezme
politiku tenantu, zatímco explicitní `disabled` přepíše i zapnutou politiku tenantu.
Existující domény mají výchozí hodnotu `inherit`. Rozhoduje aktuální e-mail uživatele
a pouze aktivní, nesmazaná doména ve stejném tenantu. Neregistrované domény dědí
politiku tenantu. Federované a AD účty nadále používají upstream autentizaci;
tato nastavení sama nevynucují lokální typ účtu pro danou doménu.

Pro smíšené prostředí ponech MFA a passkeys tenantu vypnuté, u `example.org`
nastav MFA `required` a passkeys `allowed`; `example.com` ponech na `inherit`.
Nastavení je nezávislé na veřejné adrese SSO i WebAuthn RP ID. MFA vyžaduje
`IDP_SECRETS_MASTER_KEY`, passkeys navíc konfiguraci WebAuthn.
Starší browser session a refresh token pouze s heslem neobejdou nově povinné MFA.
Session vytvořená přes passkey přestane vyhovovat po vypnutí passkeys. Již vydané
access tokeny zůstávají platné do svého obvyklého vypršení.

CLI podporuje politiky u `tenants domains create/update` pomocí `--mfa-policy`
a `--passkey-policy`; hodnotou `inherit` přepsání odstraníš.

Migrace `045_add_domain_authentication_rules.sql` přidává samostatnou
**Authentication policy**: `Unrestricted` (výchozí), `Local only`, `Federated only`
nebo `AD/LDAP only`. Poslední dvě možnosti vyžadují aktivního providera odpovídajícího
typu ve stejném tenantu. Například nastav `example.com` na `Federated only`
s Googlem a `example.org` na `Local only`.
Jde o vynucované pravidlo, ne automatickou konverzi nebo propojení účtů.
Platí při zakládání/importu, změně e-mailu, typu či providera a obnově smazaného
uživatele. Přísnější doménové pravidlo nelze uložit, pokud mu odporují existující
nesmazané účty, včetně neaktivních. Neaktivní nebo smazaná doména pravidlo nevynucuje.
Vypnutí předepsaného providera zablokuje přihlášení, dokud neopravíš providera nebo
pravidlo. Federované propojení stále vyžaduje ověřené `issuer + sub`, nikoliv jen e-mail.
Existující domény zůstanou po migraci `Unrestricted`. CLI nabízí přepínače
`--authentication-policy unrestricted|local|federated|ad` a `--auth-provider-id`.

| Politika | Lokální účet bez TOTP | Lokální účet s aktivním TOTP | Federovaný / AD účet |
|---|---|---|---|
| `disabled` | pouze heslo | pouze heslo | upstream autentizace |
| `optional` | pouze heslo | heslo + TOTP nebo recovery kód | upstream autentizace |
| `required` | povinná registrace přes browser | heslo + TOTP nebo recovery kód | upstream autentizace |

`optional` nevynucuje novou registraci. Hodí se pro postupný rollout nebo pro
zachování MFA u účtů, které už TOTP aktivovaly. Pokud se mají všechny lokální
účty zaregistrovat při nejbližším browser loginu, nastav tenant na `required`.

Registrace používá standardní TOTP a funguje s Microsoft Authenticator, Google
Authenticator a kompatibilními aplikacemi. Po potvrzení prvního kódu uživatel
dostane deset jednorázových recovery kódů. V databázi jsou pouze jejich Argon2
hashe a kódy už nelze znovu zobrazit.

Administrátor může u lokálního uživatele použít **Reset MFA**. Operace revokuje
autentikátor i recovery kódy, odstraní rozpracované MFA transakce, ukončí SSO
sessions uživatele a zapíše auditní událost. Při politice `required` začne další
browser login novou registraci. TOTP seed se v Admin UI nikdy nezobrazuje.

Authorization Code Flow zapisuje způsob přihlášení do `amr` a úroveň záruky do
`acr`. Úspěšné MFA vytvoří `amr` s `pwd` a `otp` (nebo `recovery`) a
`acr=urn:simple-idm:acr:mfa`; hodnoty se zachovávají v authorization code i při
refreshi tokenu. Device Flow přijme existující TOTP nebo recovery kód, ale
záměrně neumí registrovat nový autentikátor: uživatel bez něj musí nejprve
dokončit browser login.

Provozní požadavky:

- před nasazením nové binárky spusť migraci `041_add_managed_tenant_mfa.sql`;
- nastav `IDP_SECRETS_MASTER_KEY`, který šifruje také TOTP seedy;
- udržuj synchronizovaný čas serveru, protože TOTP je časově závislé;
- zálohy databáze a šifrovací klíč chraň odděleně;
- začni politikou `disabled`, ověř browser a recovery flow a potom u vybraného
  spravovaného tenanta přepni na `required`.

### Připravovaná podpora Passkeys

Základ WebAuthn je zatím interní: registrace ani přihlášení přes HTTP a UI ještě
nejsou dostupné. Konfigurace se aktivuje jen při nastavení `WEBAUTHN_RP_ID` a
`WEBAUTHN_ORIGINS` (volitelně `WEBAUTHN_RP_NAME`). Produkční origin musí být
HTTPS, například `WEBAUTHN_RP_ID=idm.example.com` a
`WEBAUTHN_ORIGINS=https://idm.example.com`. Hodnota RP ID musí zůstat stabilní;
její změna zneplatní již registrované Passkeys. Tenant má po migraci politiku
`passkey_policy=disabled`. Podrobnosti jsou v
`docs/PASSKEY_IMPLEMENTATION_PLAN.cs.md`.

## OAuth2 Endpointy

Discovery:

```text
GET /.well-known/openid-configuration
GET /.well-known/jwks.json
```

Authorization Code Flow:

```text
GET  /oauth2/authorize
POST /oauth2/login
POST /oauth2/token
```

Client Credentials:

```text
POST /oauth2/client_credentials/token
```

Device Flow:

```text
POST /oauth2/device/authorize
GET  /device
POST /oauth2/device/verify
POST /oauth2/device/token
```

UserInfo:

```text
GET /oauth2/userinfo
```

Introspection/revocation:

```text
POST /oauth2/introspect
POST /oauth2/revoke
```

## Admin Web UI

Admin UI:

```text
/admin/ui
```

Sekce:

- Dashboard
- Users
- Groups
- Memberships
- Clients
- Identity providers
- Client claims
- Group claims

Pro vývoj lze použít `ADMIN_ROOT_TOKEN`.

## Admin CLI

Instalace všech osmi nativních binárek workspace do `~/.cargo/bin`:

```bash
just install
```

Příkaz nahradí dříve nainstalované verze a sdílí build cache v adresáři
`target`. Kořen workspace má virtuální manifest, proto `cargo install --path .`
nefunguje; job instaluje každý binárkový balíček zvlášť.

Build:

```bash
cargo build -p simple-idm-ctl
```

Login přes browser:

```bash
simple-idm-ctl login --url https://sso.example.com
```

Nepovinná nápověda pro browser přihlášení:

```bash
simple-idm-ctl login --url https://sso.example.com --user user@example.com
```

`--user` posílá OIDC `login_hint`, nikoliv přihlašovací údaj. Aktivní federovaný
účet se schválenou identitou v tenantu klienta se přesměruje na svého providera;
jinak se předvyplní přihlašovací formulář. Existující SSO session má stále
přednost. Volbu nelze kombinovat s `--device`.

Login přes device flow:

```bash
simple-idm-ctl login --url https://sso.example.com --device
```

Session příkazy:

```bash
simple-idm-ctl status
simple-idm-ctl sessions list
simple-idm-ctl sessions use production
simple-idm-ctl logout
```

## OAuth2 Proxy

`simple-idm-oauth2-proxy` chrání legacy aplikace bez OAuth2/OIDC podpory.

Architektura:

```text
browser -> nginx -> simple-idm-oauth2-proxy -> legacy app
```

Praktický produkční režim může být i:

```text
browser -> nginx TLS edge -> simple-idm-oauth2-proxy -> aplikace
```

V tomto režimu nginx řeší certifikáty a edge nastavení, zatímco
`simple-idm-oauth2-proxy` řeší SSO login, logout, session cookie, důvěryhodné
identity hlavičky a HTTP/1.1/WebSocket proxy na jednu upstream aplikaci.

Typické hlavičky:

```text
X-Auth-User
X-Auth-Email
X-Auth-Groups
```

Dokumentace:

```text
docs/OAUTH2_PROXY.md
docs/multi-oauth/
```

## SSH Certifikáty

### Interaktivní přístup přes bastion

`simple-idm-bastion` nabízí katalog povolených hostů, SSH terminál a trvalý
audit relací. Přihlášení probíhá přes SSO; SSH klíče a certifikáty spravuje
bastion pomocí existujícího signeru. Otevřený terminál pokračuje i po expiraci
certifikátu.

```sh
simple-idm-ssh-login bastion.datalite.cz
# Explicitní forma:
simple-idm-ssh-login bastion bastion.datalite.cz
```

Konfiguraci klienta, oprávnění, nasazení a audit popisuje
[dokumentace bastionu](docs/BASTION.cs.md). Průběžný stav realizace je v
[implementačním plánu](docs/BASTION_IMPLEMENTATION_PLAN.cs.md).

### Přímé SSH certifikáty

SSH stack:

- `simple-idm-ssh-login`
- `simple-idm-ssh-signer`

Flow:

```text
simple-idm-ssh-login -> Simple IDM OIDC login -> SSH signer -> OpenSSH certificate
```

Příklad `sshd_config`:

```text
TrustedUserCAKeys /etc/ssh/simple-idm-ssh-signer.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

Příklady groups/principals:

```text
ssh:principal:user
ssh:role:linux-admin
```

## Groups A Claims

Groups mohou být zanořené. Token může obsahovat direct nebo effective groups.

Client settings:

- `groups_claim_mode = none`
- `groups_claim_mode = direct`
- `groups_claim_mode = effective`
- `ignore_virtual_groups = true|false`

Claim maps umožňují per-client překlad groups na vlastní claims:

- single value
- array value
- group-specific claim mapping

To pomáhá zmenšit JWT a přizpůsobit claims konkrétní aplikaci.

## Group Patterns

Group patterns automaticky přiřazují groups uživatelům.

Příklady:

```text
ssh:*
*:admin
ssh:*:admin
exact-match
```

Priorita:

- nižší číslo = vyšší priorita
- pravidla se aplikují podle priority

Config:

```env
GROUP_PATTERNS_SYNC_INTERVAL_SECONDS=300
```

## Soft Delete

Admin operace používají soft delete, kde to dává smysl. Záznamy se označí jako smazané a běžné UI/API je neukazuje.

Volitelný purge:

```env
SOFT_DELETE_PURGE_ENABLED=false
SOFT_DELETE_PURGE_INTERVAL_SECONDS=3600
SOFT_DELETE_RETENTION_DAYS=30
```

## SQLx Offline Mode

Po změně SQL dotazů nebo migrací:

```bash
cargo sqlx migrate run
cargo sqlx prepare --workspace
git add .sqlx migrations
```

Build bez databáze:

```bash
SQLX_OFFLINE=true cargo build --workspace
```

## Vývoj

Při nasazení bezpečnostních oprav projdi [změny nasazení](docs/SECURITY_UPGRADE.md)
a [bezpečnostní audit](docs/security_best_practices_report.md).

Před pushem nebo vydáním spusť stejný kontrolní skript jako GitHub CI:

```bash
just ci-check
# Nebo: bash scripts/ci-check.sh
```

Nejdřív nainstaluj stejnou verzi auditního nástroje:
`cargo install cargo-audit --locked --version 0.22.2`.
Skript kontroluje verze, testy release/audit politiky, formátování, celý workspace
se všemi targets a závislosti proti aktuální databázi RustSec. Používá Rust toolchain
repozitáře a SQLx offline metadata; při chybě skončí. GitHub spouští stejný skript
na Linuxu, lokálně se platformové testy řídí tvým OS. Nový bezpečnostní nález může
přibýt i po úspěšné lokální kontrole.

PostgreSQL integrační testy se spouštějí **lokálně u vývojáře** pomocí Docker
Compose. CI používá uložená SQLx offline metadata a nepotřebuje přístup k externí
databázi. Databázové testy označené `#[ignore]` spusť samostatně:

```bash
# Vyžaduje Docker s Compose a sqlx-cli (viz požadavky).
bash scripts/test-postgres.sh
# Nebo: just test-postgres
```

Skript vytvoří samostatný Compose projekt podle `docker-compose.test.yml`, počká
na PostgreSQL, aplikuje migrace a spustí databázové testy v `simple-idm-core`.
Databáze poslouchá pouze na loopbacku na automaticky přiděleném portu. Data jsou
v dočasném souborovém systému kontejneru a odstraní se při ukončení skriptu,
i při selhání testu. Vývojové databáze ani volume z `docker-compose.yml` se
nedotýká. Přihlašovací údaje jsou lokální testovací hodnoty. Historické soubory
v kořenovém `tests/` nejsou Cargo test targets tohoto virtuálního workspace;
tento příkaz je nespouští.

Start serveru:

```bash
cargo run -p simple-idm-server --bin simple-idm-server
```

## Licence

MIT

## Komerční Podpora

Software je poskytován pod licencí MIT, bez záruky a bez bezplatné komunitní
podpory. Používání softwaru nevyžaduje zakoupení podpory.

Profesionální podporu nabízí **[DataLite](https://datalite.cz)**, například:

- technickou pomoc a řešení problémů,
- ověřené releasy a aktualizace,
- opravy chyb,
- pomoc s nasazením,
- dlouhodobou údržbu.

Možnosti komerční podpory projednej s [DataLite](https://datalite.cz).
Veřejná hlášení ani externí pull requesty nezakládají povinnost odpovědět,
provést review, přijmout příspěvek nebo implementovat změnu. SLA ani pravidelný
harmonogram releasů nejsou slíbeny, pokud nejsou samostatně dohodnuty.

## Autor

Martin Mareš
