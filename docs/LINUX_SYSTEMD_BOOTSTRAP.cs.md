# Simple IDM na Linuxu: instalace a systemd user service

Tento návod spouští `simple-idm-server` pod samostatným linuxovým uživatelem
`simple-idm`. Služba startuje při bootu a běží i bez přihlášeného uživatele.
Příkazy se `sudo` spouštěj ze svého administrátorského účtu.

Potřebuješ Linux se systemd, dostupnou PostgreSQL databázi, OpenSSL a linuxovou
binárku `simple-idm-server` pro architekturu serveru. PostgreSQL účet musí mít
práva pro migrace ve své databázi: server je provádí automaticky při startu.
Veřejné HTTPS v tomto příkladu zajišťuje reverzní proxy.

## 1. Vytvoř linuxového uživatele

```bash
sudo useradd --create-home --user-group --shell /bin/bash simple-idm
id simple-idm
getent passwd simple-idm
```

Domovský adresář bude `/home/simple-idm`. Tento linuxový účet je účet služby,
nikoliv uživatel v databázi IDM. Nepotřebuje heslo ani členství v `sudo`.
Pokud účet už existuje, příkaz `useradd` neopakuj; ověř jeho home přes `getent`.

## 2. Nainstaluj binárku a připrav adresáře

Příklad předpokládá rozbalenou release binárku v aktuálním adresáři:

```bash
sudo install -o root -g root -m 0755 ./simple-idm-server /usr/local/bin/simple-idm-server
sudo install -d -o simple-idm -g simple-idm -m 0700 \
  /home/simple-idm/.config \
  /home/simple-idm/.config/simple-idm-server \
  /home/simple-idm/.config/simple-idm-server/keys \
  /home/simple-idm/.config/systemd \
  /home/simple-idm/.config/systemd/user
```

Binárku spravuje root. Konfiguraci a klíče vlastní `simple-idm`.

Každý adresář uvádíme výslovně: rodiče vytvořené automaticky pomocí
`install -d` nemusí získat stejného vlastníka a práva jako cílový adresář.
Pokud jsi postupoval podle starší verze návodu a adresáře vlastní `root`,
oprav existující konfiguraci ze svého administrátorského účtu:

```bash
sudo chown simple-idm:simple-idm /home/simple-idm/.config
sudo chown -R simple-idm:simple-idm \
  /home/simple-idm/.config/simple-idm-server \
  /home/simple-idm/.config/systemd
sudo find /home/simple-idm/.config/simple-idm-server /home/simple-idm/.config/systemd \
  -type d -exec chmod 0700 {} +
sudo chmod 0700 /home/simple-idm/.config
sudo find /home/simple-idm/.config/simple-idm-server /home/simple-idm/.config/systemd \
  -type f -exec chmod 0600 {} +
```

Poslední příkaz předpokládá, že tyto dva stromy obsahují pouze konfiguraci,
klíče a systemd unit soubory, nikoliv spustitelné skripty. Klíče ani master
key kvůli opravě práv negeneruj znovu.

Ověř vlastníka a režim všech adresářů:

```bash
ls -ld /home/simple-idm/.config \
  /home/simple-idm/.config/simple-idm-server \
  /home/simple-idm/.config/simple-idm-server/keys \
  /home/simple-idm/.config/systemd \
  /home/simple-idm/.config/systemd/user
```

Očekávaný vlastník je `simple-idm simple-idm` a režim `drwx------`.

## 3. Vygeneruj JWT klíče

Pro novou instalaci:

```bash
sudo -u simple-idm sh -c '
  set -eu
  umask 077
  cd /home/simple-idm/.config/simple-idm-server/keys
  test ! -e private.pem && test ! -e public.pem
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem
  openssl pkey -in private.pem -pubout -out public.pem
'
```

Příkaz záměrně odmítne přepsat existující klíče. Při přesunu existujícího IDM
přenes jeho původní klíče; nové klíče by změnily podpisy vydávaných tokenů.

Vygeneruj také master key pro šifrování provider secrets a TOTP seedů:

```bash
openssl rand -base64 32
```

Výsledek vlož do `IDP_SECRETS_MASTER_KEY` níže. Tento klíč uchovej a zálohuj;
při restartu nebo aktualizaci jej negeneruj znovu.

## 4. Připrav `.env`

### Čím nahradit původní `<redacted>` hodnoty

Každá hodnota má jiný účel. Nepoužívej stejné tajemství pro více položek:

| Položka | Jak ji získat |
| --- | --- |
| Heslo v `DATABASE_URL` | Heslo PostgreSQL role `simple_idm_admin`; pro novou roli můžeš vygenerovat `openssl rand -hex 24` |
| `IDP_SECRETS_MASTER_KEY` | `openssl rand -base64 32`; při přesunu existující instalace zachovej původní hodnotu |
| `ADMIN_ROOT_TOKEN` | Pro dočasný bootstrap `openssl rand -hex 32`; v produkci celý řádek vynech |
| `keys/private.pem` a `keys/public.pem` | Vygeneruj podle kroku 3; jde o RSA klíče, nikoliv hodnoty v `.env` |

Vygenerované databázové heslo musíš také nastavit v PostgreSQL. Samotné vložení
hesla do `.env` nezmění heslo databázové role. Pokud databázi spravuje někdo
jiný, vyžádej si přihlašovací údaje od jejího správce.

Na PostgreSQL serveru může administrátor pro novou instalaci použít:

```bash
sudo -u postgres psql
```

V interaktivním `psql`:

```sql
CREATE ROLE simple_idm_admin LOGIN;
\password simple_idm_admin
CREATE DATABASE simple_idm OWNER simple_idm_admin;
\quit
```

Příkaz `\password` se zeptá na heslo a jeho potvrzení. Vlož tam vygenerované
databázové heslo a stejnou hodnotu použij v `DATABASE_URL`. Pokud role nebo
databáze už existují, příslušný `CREATE` neopakuj. PostgreSQL musí zároveň
povolovat připojení z IDM serveru přes svou konfiguraci a firewall.

```bash
sudo -u simple-idm touch /home/simple-idm/.config/simple-idm-server/.env
sudo chmod 0600 /home/simple-idm/.config/simple-idm-server/.env
sudo -u simple-idm vim /home/simple-idm/.config/simple-idm-server/.env
```

Vlož a uprav následující konfiguraci. Nahraď obě hodnoty `REPLACE_ME`:

```env
APP_ENV=production
SERVER_HOST=127.0.0.1
SERVER_PORT=3003
DATABASE_URL=postgres://simple_idm_admin:REPLACE_ME@pg.cluster/simple_idm

JWT_ISSUER=https://sso.example.com
JWT_KEY_ID=sso-key-1
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
ACCESS_TOKEN_EXPIRY_SECONDS=3600
REFRESH_TOKEN_EXPIRY_SECONDS=2592000
REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS=3600

RUST_LOG=simple_idm_server=info,tower_http=info
RATE_LIMIT_REQUESTS_PER_SECOND=5
RATE_LIMIT_BURST_SIZE=10
AUTH_MAX_FAILURES=5
AUTH_FAILURE_WINDOW_SECONDS=900
AUTH_LOCKOUT_SECONDS=900

IDP_SECRETS_MASTER_KEY=REPLACE_ME
WEBAUTHN_RP_ID=sso.example.com
WEBAUTHN_ORIGINS=https://sso.example.com

UI_BRAND_NAME=Cloud App
UI_BRAND_DOMAIN=sso.example.com
UI_PAGE_TITLE=Simple IDM
FORCE_SECURE_COOKIES=true
TRUST_PROXY_HEADERS=false
ONBOARDING_TOKEN_CLEANUP_INTERVAL_SECONDS=3600
```

`SERVER_HOST=127.0.0.1` je vhodné pro proxy na stejném serveru. Pokud proxy běží
jinde, nastav dostupnou adresu nebo `0.0.0.0` a omez přístup firewallem.
`JWT_ISSUER` je veřejná HTTPS URL, nikoliv interní adresa listeneru.
`TRUST_PROXY_HEADERS=true` nastav pouze tehdy, když se na listener dostane jen
důvěryhodná proxy a přepisuje klientské forwarded hlavičky.

Heslo v `DATABASE_URL` musí být URL-encoded, pokud obsahuje například `@`, `:`,
`/`, `#` nebo `%`. Soubor `.env` používá zápis `KEY=value`, bez `export`.
Hodnoty s mezerami uzavři do dvojitých uvozovek.

V produkční konfiguraci **vynech celý řádek `ADMIN_ROOT_TOKEN`**. Server jej
v produkci odmítá, i když má prázdnou hodnotu. Pro dočasný bootstrap existuje
vývojový/recovery režim: `APP_ENV=development` s náhodným `ADMIN_ROOT_TOKEN`
(`openssl rand -hex 32`). Používej jej jen v omezeném prostředí pro nastavení
admin přístupu; před produkčním provozem token odstraň a vrať `APP_ENV=production`.
Založení admin identity a oprávnění v IDM je samostatný krok, linuxový účet je
nevytváří. Viz [Admin Web UI](../README.cs.md#admin-web-ui).

## 5. Vytvoř systemd user unit

```bash
sudo -u simple-idm vim /home/simple-idm/.config/systemd/user/simple-idm-server.service
```

Obsah:

```ini
[Unit]
Description=Simple IDM Server (user service)

[Service]
Type=simple
WorkingDirectory=%h/.config/simple-idm-server
EnvironmentFile=%h/.config/simple-idm-server/.env
ExecStart=/usr/local/bin/simple-idm-server
Restart=on-failure
RestartSec=2
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=default.target
```

`%h` znamená home uživatele služby, tedy `/home/simple-idm`. Working directory
je důležitý kvůli relativním cestám `./keys/...`. `EnvironmentFile` načte
proměnné při každém startu procesu; změna `.env` proto vyžaduje restart služby.

Základní unit záměrně nepotřebuje filesystem namespaces. Volby `PrivateTmp`,
`ProtectSystem`, `ProtectHome` a `ReadWritePaths` z původního příkladu mohou
v user službě vyžadovat `PrivateUsers=yes` a povolené unprivileged user
namespaces. Bez podpory v distribuci mohou způsobit chybu při startu.
Přidávej je až po ověření základní služby a podpory daného systému.

User manager také nesdílí systémový `network-online.target`; uvedení tohoto
targetu v user unit nezajistí čekání na dostupnou síť. Pokud při bootu ještě
není dostupná DB nebo DNS, služba díky `Restart=on-failure` pokus opakuje.

## 6. Povol linger a spusť user manager

```bash
sudo loginctl enable-linger simple-idm
loginctl show-user simple-idm -p Linger
sudo systemctl start "user@$(id -u simple-idm).service"
```

Výsledek musí obsahovat `Linger=yes`. Linger udržuje user manager i bez
přihlášení a umožňuje jeho spuštění při bootu. Samotný linger ještě nepovoluje
automatický start konkrétní služby; to provede `enable` v dalším kroku.

## 7. Povol a spusť službu

Z administrátorského účtu spustíš příkazy pod `simple-idm` takto:

```bash
SIMPLE_IDM_UID=$(id -u simple-idm)
sudo -u simple-idm env \
  XDG_RUNTIME_DIR="/run/user/$SIMPLE_IDM_UID" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$SIMPLE_IDM_UID/bus" \
  systemctl --user daemon-reload

sudo -u simple-idm env \
  XDG_RUNTIME_DIR="/run/user/$SIMPLE_IDM_UID" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$SIMPLE_IDM_UID/bus" \
  systemctl --user enable --now simple-idm-server.service
```

Pro další správu je pohodlnější otevřít shell účtu služby:

```bash
sudo -iu simple-idm
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
systemctl --user status simple-idm-server.service --no-pager
journalctl --user -u simple-idm-server.service -n 100 --no-pager
curl --fail http://127.0.0.1:3003/health
```

Health endpoint má vrátit `OK`. Pro živé logy:

```bash
journalctl --user -u simple-idm-server.service -f
```

Shell opustíš příkazem `exit`. Služba zůstane spuštěná.

## První admin přístup

Pokud už máš administrátora v IDM, použij jeho přístup. Pro prázdnou instalaci:

1. V `.env` dočasně nastav `APP_ENV=development` a přidej
   `ADMIN_ROOT_TOKEN` vygenerovaný přes `openssl rand -hex 32`. Restartuj službu.
   Po dobu bootstrapu omez dostupnost serveru na důvěryhodné správce.
2. Otevři `https://sso.example.com/admin/ui` a do přihlašovacího formuláře
   vlož tento token. HTTPS proxy musí být v provozu; ukázková konfigurace
   vynucuje Secure cookies.
3. V **Users** vytvoř svého lokálního administrátora se silným heslem.
   V **Groups** vytvoř skupinu `simple-idm:role:admin`, pokud ještě neexistuje.
   V **Memberships** do ní administrátora přidej.
4. V **Clients** ověř klienta `cli-tools`: musí být aktivní a public,
   povolovat `authorization_code` a `refresh_token`, mít scopes
   `openid profile email groups` a `groups_claim_mode=effective` nebo `direct`.
   Virtuální skupinu s admin rolí nesmí odfiltrovat nastavení klienta.
   Pro výchozí CLI login povol redirect URI `http://localhost:8888/callback`.
5. Ze svého počítače ověř přihlášení administrátora:

   ```bash
   simple-idm-ctl login --url https://sso.example.com
   ```

   CLI vypíše cestu k `sessions.json`. S nainstalovaným `jq` získáš access
   token aktivní session takto (na počítači, kde proběhl login):

   ```bash
   # Linux; při vlastním XDG_CONFIG_HOME použij cestu vypsanou CLI.
   jq -r '.servers[.active].access_token' "$HOME/.config/simple-idm-ctl/sessions.json"

   # macOS
   jq -r '.servers[.active].access_token' "$HOME/Library/Application Support/simple-idm-ctl/sessions.json"
   ```

   Token i soubor session jsou tajné údaje: neposílej je do logů, screenshotů
   ani Gitu. Access token má omezenou platnost; pro další přístup použij
   aktuální token.

   Úspěšný login ověří autentizaci. Pro Admin Web UI potřebuješ access token
   vydaný pro aktivního klienta, který obsahuje group `simple-idm:role:admin`;
   ten vlož do tokenového formuláře UI a ověř přístup v samostatné browser
   session. Samotný linuxový účet ani skupina nazvaná pouze `admin` tato
   oprávnění nenahrazují.
6. Až máš ověřený běžný admin přístup, odstraň celý řádek `ADMIN_ROOT_TOKEN`,
   vrať `APP_ENV=production` a restartuj službu. Pro další správu používej
   admin access token, nikoliv původní bootstrap token.

## Ověření veřejné instalace

Ze svého počítače:

```bash
curl --fail https://sso.example.com/health
curl --fail https://sso.example.com/.well-known/openid-configuration
curl --fail https://sso.example.com/.well-known/jwks.json
```

Health má vrátit `OK`, discovery má obsahovat nastavený veřejný issuer a JWKS
veřejný podpisový klíč. Otevři také `/admin/ui` a vyzkoušej skutečný login.
URL v příkladech nahraď vlastní doménou; proxy a HTTPS certifikát nakonfiguruj
před testováním browser loginu.

## 8. Restart a aktualizace

V shellu `simple-idm` s nastavenými proměnnými z předchozího kroku:

```bash
systemctl --user restart simple-idm-server
systemctl --user status simple-idm-server --no-pager
```

Název služby je `simple-idm-server`, nikoliv `simple-idm`. Pokud chceš používat
přesně `systemctl --user restart simple-idm`, přidej do sekce `[Install]`:

```ini
Alias=simple-idm.service
```

Potom spusť `systemctl --user daemon-reload` a
`systemctl --user reenable simple-idm-server.service`. Tím vznikne alias.

Po změně unit souboru vždy proveď `daemon-reload` a restart. Po změně samotného
`.env` stačí restart. Před výměnou binárky službu zastav, novou binárku
nainstaluj příkazem `install` z kroku 2 a službu znovu spusť. Před aktualizací
zálohuj databázi: nová verze může při startu provést migrace.

## Když něco nefunguje

- `Failed to connect to bus`: ověř `Linger=yes`, běžící `user@UID.service`
  a `/run/user/UID/bus`. Pouhé `sudo -u simple-idm systemctl --user ...`
  nemusí mít správné prostředí; použij příkazy z kroku 7.
- `Private key: No such file or directory`: zkontroluj working directory,
  soubory `keys/private.pem`, `keys/public.pem` a vlastnictví `simple-idm`.
- `Permission denied`: ověř přístup uživatele ke konfiguraci, klíčům a binárce.
- `ADMIN_ROOT_TOKEN is forbidden in production`: odstraň celý řádek tokenu
  z `.env` a případný token uložený v prostředí user manageru.
- `Too many open files` nebo chyba při nastavování limitu: ověř
  `systemctl --user show simple-idm-server -p LimitNOFILE`. User manager nemůže
  překročit svůj hard limit; jeho zvýšení musí nastavit administrátor systému.
- Databáze/DNS není dostupná: ověř spojení ze serveru a čti journal. Stav
  `active` znamená běžící proces; `/health` je základní kontrola HTTP listeneru,
  nikoliv kompletní kontrola všech závislostí.

Zálohuj PostgreSQL a `/home/simple-idm/.config/simple-idm-server`, především
JWT private key a `IDP_SECRETS_MASTER_KEY`. Zálohy obsahují tajné údaje a musí
být chráněné stejně jako původní soubory.
