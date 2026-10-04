# Bastion V1

V1 poskytuje SSO v prohlížeči, lokální výběr hostu, interaktivní SSH terminál
a trvalý audit přístupů. Klient komunikuje přes HTTPS/WSS; dočasný SSH klíč
pro každou relaci vytváří bastion. Privátní klíč CA zůstává pouze u signeru.
Podporované jsou klienty Linux/macOS a unixový bastion s OpenSSH. Přenos
souborů, forwarding, záznam obsahu terminálu a obnovení odpojené relace
nejsou součástí V1.

## Klient

[Příklad profilů](../examples/config.example.bastions.toml) patří do
`~/Library/Application Support/simple-idm-ssh-login/bastions.toml` na macOS;
na Linuxu `$XDG_CONFIG_HOME/simple-idm-ssh-login/bastions.toml`
(výchozí `~/.config/simple-idm-ssh-login/bastions.toml`). Je oddělený
od stávajícího `config.toml` pro přímé SSH. Nastavte `url`, `issuer`, `client_id`,
volitelný slug tenantu a scopes podle svého nasazení.

```sh
simple-idm-ssh-login bastion.example.com
simple-idm-ssh-login bastion bastion.example.com
```

Druhá forma řeší kolizi hostname s názvem subcommandu. Přihlášení využívá
OIDC, PKCE a MFA politiku IDM. Fokus začíná v seznamu. `/` aktivuje filtr,
Enter jej potvrdí a vrátí do seznamu. Šipky vybírají, Enter v seznamu
připojí, Esc ukončí výběr. Esc ve filtru zruší úpravu a obnoví původní
filtr; Ctrl-U filtr vymaže. Více povolených účtů otevře výběr účtu. `exit`
vrací do seznamu, Ctrl-C v shellu patří vzdálenému programu a změna velikosti
okna se přenáší. Při chybě autentizace lze před novým připojením obnovit SSO.
Bastion režim nepotřebuje lokální SSH klíč/certifikát. Přímé SSH příkazy zůstávají.

Klient 0.11.0 používá Ratatui: ohraničený filtr, tabulku hostů se zvýrazněním,
počtem řádků a scrollbarem pouze při přesahu. PageUp/PageDown a Home/End listují.
Záhlaví obsahuje serverem ověřenou identitu, tenant, identifikátor bastionu,
endpoint a IP připojeného TLS endpointu (tedy nginx při ukončení TLS v proxy).
Daemon 0.1.1 přidává identitu a adresy hostů; DNS se zjišťuje pouze pro povolené
hosty s timeoutem jedné sekundy. Starší daemon je kompatibilní, ale metadata
nemá. Mouse capture je vypnutý, aby fungoval nativní výběr textu. Obrazovka se
aktualizuje při vstupu/resize, nikoli neustálým překreslováním.

## Přidání hostu z CLI (0.2.0)

Na bastionu pod uživatelem vlastnícím konfiguraci spusťte průvodce:

```sh
~/.local/bin/simple-idm-bastion \
  --config ~/.config/simple-idm-bastion/config.toml add-host
```

Průvodce se zeptá na ID, zobrazované jméno, hostname/IP, port, prostředí,
popis, povolené IDM skupiny, Linux účty a volitelné principals. Ukáže nový
TOML blok a uloží jej až po potvrzení. Zachová komentáře i oprávnění souboru,
zálohu uloží vedle konfigurace jako `.bak-UUID`. Celá konfigurace musí projít
validací; duplicitní ID odmítne. `--dry-run` pouze ukazuje náhled, `--yes`
povolí uložení bez dotazu při zadání všech povinných argumentů.

```sh
~/.local/bin/simple-idm-bastion \
  --config ~/.config/simple-idm-bastion/config.toml add-host \
  --id intel-nuc1 --name 'Intel NUC1' --address intel-nuc1.cluster \
  --environment infra --group ssh:principal:mares --login mares \
  --principal mares --dry-run
```

Volitelně vložte nezávisle ověřený ED25519 fingerprint; průvodce stáhne
host key a uloží ho do `known_hosts` pouze při shodě. V neinteraktivním režimu
slouží `--host-key-fingerprint SHA256:...`. Fingerprint zjistěte na **cílovém**
serveru příkazem `sudo ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub`.
Bez fingerprintu se `known_hosts` nemění. Cílové účty a důvěra v user CA musí
být nastavené samostatně. Zápisy jsou atomické po jednotlivých souborech;
known_hosts se ukládá první, takže při následné chybě configu může přidaný
ověřený klíč zůstat. Každý změněný soubor má vlastní zálohu.

Restart provádíte ručně: `systemctl --user restart simple-idm-bastion.service`.
Ukončí otevřené relace. Poté znovu otevřete klienta, aby načetl nový katalog.

## Identita a signer

V IDM zaregistrujte veřejného klienta `simple-idm-bastion` s PKCE, browser
loopback callbackem a scope `bastion:connect`. Audience access tokenu musí
souhlasit s daemonem i signerem. API přijímá **access token**, nikoli ID token.
Token musí obsahovat autoritativní `tenant_id` UUID a `bastion:connect`.
Na serverech připněte skutečné UUID tenantu; klientský slug je pouze nápověda
při přihlášení. Katalog se filtruje podle ověřených skupin a oprávnění se
kontroluje znovu před každou relací.

Do konfigurace signeru doplňte:

```toml
[bastion]
expected_audience = "simple-idm-bastion"
tenant_id = "11111111-1111-4111-8111-111111111111" # skutečné UUID
service_key_env = "BASTION_SERVICE_KEY"
required_scope = "bastion:connect"
```

Obě služby musí mít v prostředí stejné náhodné servisní tajemství o alespoň
32 bytech. Soubory prostředí chraňte a rotujte obě služby společně. Tajemství
nepatří do klienta, repozitáře ani URL.

Delegace používá `POST /ssh/sign/bastion`, bearer **uživatelský access token**,
hlavičku `X-Bastion-Key` a JSON `public_key`, volitelné `requested_principals`,
`ttl_seconds` a `session_id` UUID. Signer vrací `certificate`, `valid_after`,
`valid_before`, `principals`. Požadované principals mohou pouze zúžit oprávnění
odvozená z ověřené identity/skupin. Certifikát má key ID
`simple-idm-cert:bastion:<session_uuid>` a pouze extension `permit-pty`.
Dosavadní `/ssh/sign` zůstává pro přímé SSH. Samotné oprávnění ke katalogu
nezaručuje principal u signeru.
Skupina katalogu `infra-admins` je odlišná od skupiny signeru
`ssh:role:infra-admins`; při povoleném mapování rolí signer vydává principal
`role:infra-admins`. Ten musí povolit i cílový Linux účet.

## Nasazení daemona a cílového SSH

Použijte [konfiguraci daemona](../examples/config.example.bastion.toml).
`signer_url` je **celý endpoint** včetně `/ssh/sign/bastion`. V1 naslouchá
pouze na loopback HTTP za TLS proxy; URL issueru/signeru vyžadují HTTPS
s výjimkou explicitních loopback fixtures. Neznámá pole se odmítají.
Host má `allowed_groups` a seznam `logins`.
`{username}` se dosazuje z ověřeného a validovaného `preferred_username`.
U pevného účtu `postgres` audit stále zachovává skutečnou IDM identitu.
Volitelné `principals` zužuje oprávnění certifikátu.

Vytvořte servisní účet `simple-idm-bastion`, instalujte binárku do
`/usr/local/bin/simple-idm-bastion`. Ukázku konfigurace zkopírujte do
`/etc/simple-idm-bastion/config.toml`, podle explicitního `--config` v unitu
(výchozí cesta binárky je `bastion.toml`). Ověřené host keys patří do stejného
adresáře. Soubory vlastní správce, služba je smí číst.
Rootem vlastněný soubor `/etc/simple-idm-bastion/bastion.env` s právy 0600
obsahuje `BASTION_SERVICE_KEY=<nahodne-tajemstvi-alespon-32-bytu>`.

[Systemd unit](../examples/systemd/simple-idm-bastion.service) poskytuje
privátní state/runtime adresáře, umask 0077, restart a ukončení celé skupiny
procesů. Příkaz končí povinným subcommandem `serve`. Před aktivací spusťte
`simple-idm-bastion --config /etc/simple-idm-bastion/config.toml check-config`;
poté proveďte `systemctl daemon-reload` a aktivaci služby. Služba potřebuje
PTY (`/dev/ptmx`), DNS a síťový přístup k IDM, signeru a cílovým hostům.
Nespouštějte ji jako root. Smoke harness nic nenasazuje.

Na cílech vytvořte Linux účty a instalujte pouze **veřejný** klíč CA.
[Ukázka sshd](../examples/systemd/bastion-target-sshd.conf) používá
`AuthorizedPrincipalsFile /etc/ssh/simple-idm-principals/%u`. Soubory vlastní
root a obsahují povolené principals, jeden na řádek: např. `alice` pro účet
alice; pro sdílený účet použijte explicitně oprávněný principal dle politiky.
Před reloadem ověřte celé nastavení pomocí `sshd -t` a
`sshd -T -C user=postgres,host=target,addr=<bastion-ip>`. Při zavádění zachovejte
samostatně posouzený nouzový přístup. SSH ingress lze omezit na bastion.

`known_hosts` musí obsahovat nezávisle ověřené veřejné klíče cílových hostů.
Pro nestandardní port použijte `[hostname]:port ssh-ed25519 ...`.
Samotný `ssh-keyscan` identitu neověřuje. Neznámý nebo změněný klíč musí
připojení odmítnout; rotaci ověřte a opravte spravovaný soubor. Nevypínejte
strict host-key checking.

## nginx a protokol

[Ukázka nginx](../examples/nginx/bastion.conf) patří do kontextu `http {}`.
Změňte DNS/TLS cesty a ověřte `nginx -t`. Proxy předává WebSocket upgrade
a Authorization, vypíná buffering a nastavuje dlouhé transportní timeouty.
Keepalive udržuje zdravý tichý terminál; timeout proxy není TTL relace.
`trusted_proxies` nastavte pouze na skutečné proxy IP. nginx přepisuje zdrojovou
IP hlavičku místo důvěřování hodnotě dodané klientem.

Klient používá `/api/v1/hosts` a `/api/v1/terminal`. Terminál má parametry
`host_id`, `login`, `cols`, `rows`, `term`; token je v hlavičce, nikdy v URL.
Binární WebSocket rámce obsahují terminálová data. JSON řídicí zprávy jsou
`ready` s verzí/session ID, `resize` s verzí 1/cols/rows, `error` s message
a `exit` s povinným celočíselným `status`. V1 nemá reconnect ticket.

## Expirace a odvolání přístupu

TTL certifikátu, typicky 3600 sekund s omezením dle signeru, určuje dobu,
ve které lze **zahájit** SSH autentizaci. Již otevřený shell po expiraci
pokračuje. Nová autentizace se stejným prošlým certifikátem selže. Ani
expirace access tokenu sama neukončuje již autorizovaný terminál. V1 nemá
hodinové odpojení, časové uzamčení ani limit neaktivity.

Nová relace znovu ověřuje token i host/účet. Změna skupin se projeví po vydání
tokenu s novými claims, s ohledem na platnost tokenu a validační toleranci.
Nelze slibovat okamžité odvolání ani ukončení otevřeného shellu. Keepalive
detekuje ztracený transport, neměří neaktivitu. Odpojení SSH negarantuje
ukončení programů spuštěných přes `tmux`, `nohup` apod.

## Audit a provoz

SQLite audit dovoluje jedinou aktivní instanci pro databázi. Zachovává session
a bastion ID, issuer/subject/tenant, username, cíl a port, Linux účet, klientskou
IP, UTC časy, identifikátor certifikátu, výsledek/důvod konce a exit status.
`duration_ms` měří připojení monotónně. Audit se uloží před zpřístupněním
shellu; nefunkční úložiště odmítá nové relace. Zápis konce je idempotentní
a opakuje se. Restart označí neuzavřené relace jako `interrupted` /
`restart_unknown_end`, uloží reconciliation čas a neznámý konec/délku ponechá
null. Audit není záznam obsahu terminálu. Tokeny a privátní klíče se neukládají.

Retenci určuje `retention_days` (ukázka 90). Pruning vyžaduje zastavený daemon
a příkaz `simple-idm-bastion --config /etc/simple-idm-bastion/config.toml retain`.
Jde o explicitní údržbu, nikoli automatický plánovač. Chraňte DB, WAL, exporty a zálohy.
Za běhu použijte online backup SQLite; prostou kopii provádějte až po zastavení
služby a se souvisejícími soubory. Obnovu ověřte izolovaně. Sledujte místo
na disku, chyby signeru/JWKS a zápisu ukončení auditu. Přesnou syntaxi výpisu
a JSON/CSV exportu zjistíte pomocí `audit --help` sestaveného daemona.
Filtry používají subject, username, host, result a `since`/`until` jako UTC
Unix epoch milisekundy. Exporty chraňte stejně jako databázi.

```sh
simple-idm-bastion --config /etc/simple-idm-bastion/config.toml audit --username alice --format json
simple-idm-bastion --config /etc/simple-idm-bastion/config.toml audit --host grafana --format csv
```

## Izolované ověření

Z kořene repozitáře:

```sh
docker build -t simple-idm-bastion-smoke:local -f scripts/bastion-smoke.Dockerfile scripts
python3 scripts/bastion-smoke.py
cargo build -p simple-idm-ssh-signer
python3 scripts/bastion-smoke.py --signer-bin target/debug/simple-idm-ssh-signer
cargo build -p simple-idm-bastion
python3 scripts/bastion-smoke.py --signer-bin target/debug/simple-idm-ssh-signer --bastion-bin target/debug/simple-idm-bastion
```

Harness používá standardní Python, OpenSSL a OpenSSH. Vytváří vlastní sshd
v Dockeru na náhodném loopback portu, dočasnou CA, host/user/RSA klíče a HTTP
discovery/JWKS mock. Vypíná okolní HTTP proxy, SSH agent i multiplexing.
Do cílového kontejneru připojuje pouze jeho host key/config a veřejnou CA.
Nepoužívá produkční hosty, účty ani existující SSH konfiguraci. Image musí být
předem sestavený; harness jej sám nestahuje ani nesestavuje.

Režim skutečného signeru kontroluje přímý i delegovaný podpis, odmítnutí
tokenu/tenantu/scope a servisního tajemství, principals a PTY-only extensions.
Oba režimy prokazují pokračování PTY po expiraci a odmítnutí nové autentizace
stejným prošlým certifikátem, odmítnutí účtu/host key a exit status.
Plný režim `--bastion-bin` doplňuje autorizaci katalogu/terminálu, skutečné SSH
přes WSS s privátní TLS fixture proxy a ověřením důvěry certifikátu, binární
UTF-8, resize/Ctrl-C, pokračování shellu po expiraci a audit před shell/exit/délku.
Kontroluje souběžné identity na sdíleném Linux účtu, odpojení, změněný host key,
nefunkční audit writer, restart s neznámým časem konce, filtry/CSV export
a úklid klíčů. TLS fixture není nginx; konfiguraci nasazení ověřte samostatně.
Cleanup maže pouze vlastní procesy/kontejner/temp soubory. `--keep` ponechá
privátní artefakty pro diagnostiku; poté je bezpečně odstraňte. Úspěch platí
pouze pro zvolený režim, nikoli neprovedené browser SSO/TUI ověření.

V izolovaném testovacím tenantu ručně ověřte SSO/MFA, filtrování, výběr účtu,
`vim`/`top`, UTF-8, resize, Ctrl-C/EOF, návrat po `exit`, obnovu lokálního
terminálu při chybě a audit identity/cíle/délky. Dále odmítnutí hostu/účtu,
změnu host key, dva různé uživatele, odpojení, restart a výpadek úložiště.
JWKS mock záměrně neposkytuje browser login UI. Testy nepatří na živou
infrastrukturu.

Ověřeno 3. 10. 2026 na Docker Desktop s OpenSSH 10.3 klientem a Alpine
OpenSSH 10.0 cílem: prošly samostatný režim, skutečný signer i plný režim
daemon/WSS/audit. Plný režim použil skutečné binárky `simple-idm-bastion`
a `simple-idm-ssh-signer`. Browser SSO/TUI a aktivace Linux systemd nebyly
součástí automatického běhu.
Obě TOML ukázky se parsují, daemon ukázka prošla `check-config` a nginx ukázka
prošla `nginx -t` s dosazenými fixture TLS cestami.

### Automatické hledání konfigurace (0.2.1)

`--config <FILE>` má přednost. Bez něj se hledají `config.toml` a potom
`bastion.toml` v OS konfiguračním adresáři uživatele pod `simple-idm-bastion`,
potom `/etc/simple-idm-bastion/config.toml` a `/etc/simple-idm-bastion/bastion.toml`.
Linux respektuje `$XDG_CONFIG_HOME` nebo `~/.config`; macOS používá
`~/Library/Application Support`. Při nenalezení Clap vypíše hledané cesty.
Neplatná explicitní cesta nikdy nepřepne na jiný config. Help, version a examples
fungují bez konfigurace. V nynějším user-service nasazení stačí
`simple-idm-bastion add-host`.

Pole `environment` je pouze zobrazované označení a údaj pro filtrování hostů.
Nemění SSH připojení ani oprávnění. Pro infrastrukturní NUC servery použijte
`infra`; další možné vlastní hodnoty jsou například `production`, `staging`, `dev`.
