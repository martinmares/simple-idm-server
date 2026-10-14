# Nasazení bezpečnostních oprav

Opravy navazují na [bezpečnostní audit](security_best_practices_report.md).
Historické migrace 001–045 se nemění. Nové migrace 046–049 přidávají scope
administračního CLI, revokační triggery, zákaz rezervovaných claim map a verzi
přihlašovacích údajů. Před nasazením zálohuj databázi; migrace aplikuje server
při startu stejně jako dosud.

## Změny vyžadující pozornost

- **Default tenant UUID zůstává `11111111-1111-1111-1111-111111111111`.**
  Žádnou změnu tohoto UUID v konfiguraci domácího bastionu není potřeba dělat.
  Identifikátor není tajemství a opravy kontrolují skutečnou autorizaci.
- Po upgradu se znovu přihlas pomocí aktualizovaného `simple-idm-ctl`.
  Admin API/UI přijímají access token s typem `at+jwt`, scopem `admin:*` a
  explicitně povoleným audience. Výchozí audience je `cli-tools`; další
  administrační klienty nastav přes `ADMIN_OAUTH_CLIENT_IDS` (čárkou oddělená
  client ID). Musí patřit default tenantu a mít registrovaný scope `admin:*`.
  U uživatelů se role ověřuje z aktuálních skupin default tenantu v databázi.
  M2M klient musí být confidential a mít povolený grant `client_credentials`.
  Libovolný custom claim s textem `admin` už přístup neuděluje.
- Public klienti musí používat S256 PKCE. Confidential klient musí poslat
  client secret i při použití PKCE. Všechny požadované scopes musí být
  registrované na klientovi; zkontroluj zejména `groups` a scopes pro SSH.
  Dříve neomezené požadavky budou nyní odmítnuty.
- OAuth Basic client ID/secret se před ověřením dekódují z form encodingu
  podle RFC 6749. To je důležité pro secrets obsahující `+`, `/`, `:` nebo `%`.
  PKCE nenahrazuje confidential secret. Chyby authorization-code/refresh
  endpointu vracejí HTTP 400/401/500 místo HTTP 200, aby je OIDC klient správně
  rozpoznal a neúspěšné ověření se započítalo do throttlingu.
- Změna hesla, tenantu či způsobu přihlášení, deaktivace účtu nebo revokace MFA/passkey
  ruší relace, kódy, refresh tokeny a rozpracovaná ověření. Nové přihlášení
  nelze dokončit se starou verzí přihlašovacích údajů. Samostatně ověřované
  JWT u externích konzumentů dál podléhají své době platnosti; pro okamžitou
  revokaci musí konzument používat online kontrolu.
- Webová administrace vyžaduje u mutací přesný `Origin` odpovídající
  `JWT_ISSUER`. Používej její kanonickou URL. Admin API s Bearer tokenem je
  určeno pro CLI a automatizaci; formulářové POST bez Origin se odmítají.
- `TRUST_PROXY_HEADERS=true` nyní přijímá hlavičky jen od důvěryhodných peerů.
  `TRUSTED_PROXY_IPS` je seznam přesných IP adres oddělených čárkou, výchozí
  `127.0.0.1,::1`. Za vzdáleným ingress/proxy nastav jeho skutečné peer IP.
  Proxy musí přepisovat klientem dodané forwarded hlavičky. CIDR zápis není
  podporovaný. U ostatních peerů se používá adresa TCP spojení.
- Identity URL vyžadují HTTPS mimo loopback. Lokální HTTP zůstává použitelné.
  Federovaný OIDC provider musí nabízet discovery, ID token, nonce a S256;
  ověřuje se podpis, issuer, audience a shoda subjectu s UserInfo. Pro tuto
  cestu se nepřisuzuje lokální MFA assurance z neověřených upstream claimů.
- Reverse proxy chrání `/` i při vynechání `protected_prefixes`; prázdný
  seznam je chyba konfigurace. Public výjimky odpovídají celým segmentům.
  Cesta se dekóduje, kontroluje a stejná reprezentace se pošle upstreamu;
  nejednoznačné cesty se odmítají. Odstraňují se i vlastní identity hlavičky.
- OAuth proxy obnovuje skupiny a profil přes UserInfo nejpozději po pěti
  minutách. Provider musí mít UserInfo endpoint. `session_max_age` je pevná
  maximální životnost relace, obnovování ji neprodlužuje.
- Přímé SSH certifikáty mají explicitně povolené jen nakonfigurované
  extensions; výchozí je PTY. Pokud potřebuješ forwarding či user RC,
  nastav příslušné `permit_*` volby. Bastion certifikát zůstává pouze s PTY.
- Nová či měněná lokální hesla mají 12–1024 bajtů. Existující kratší hesla
  stále fungují při přihlášení. Hashování a ověřování běží v omezeném
  blocking poolu. AD proxy omezuje souběžné pokusy podle normalizovaného
  účtu: pět pokusů za pět minut; tato ochrana je v paměti procesu.
- CLI ukládá tokeny atomicky; na Unixu má soubor od vytvoření 0600 a adresář
  0700. Výstupní adresář token proxy je na Unixu soukromý a publishing
  používá otevřené directory descriptors bez následování symlinků. Rodič
  výstupního adresáře musí být důvěryhodný. Na Windows se použijí ACL
  uživatelského profilu/adresáře; jejich nastavení je nutné ověřit při
  nasazení, Unix oprávnění se na Windows nevztahují.

## Závislost `rsa`: konkrétní výjimka

`cargo audit` 0.22.2 nad aktuální databází stále hlásí
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
pro `rsa 0.9.10`; opravená verze není k dispozici. Přímé produkční použití
v `auth/jwt.rs` parsuje veřejný klíč pro JWKS. OIDC RP používá veřejné klíče
pro ověřování, JWT podpis vytváří `jsonwebtoken` s backendem AWS-LC.
Generování privátních RSA klíčů přes `rsa` je v testech. Dotčené privátní RSA
operace nebyly nalezeny v produkčních request cestách.

Výjimka platí pouze pro tuto advisory a verzi, při zachování uvedeného
použití. Není to oprava upstream knihovny. Nové použití privátního RSA přes
`rsa` nebo `openidconnect` vyžaduje její opětovnou revizi. CI spouští
`scripts/audit-dependencies.py`, který odmítá jiné advisory, změnu verze nebo
warnings. Samotný `cargo audit` se nijak nekonfiguruje k potlačení nálezu a
nadále vrací exit code 1. Výjimku odstranit při dostupnosti opravené závislosti.

## Vlastní scopes v administraci OAuth klientů

Formulář vytvoření a editace klienta nyní používá textové pole se scopes
oddělenými mezerou. Původní checkboxy při uložení zahazovaly vlastní scopes,
například `bastion:connect` nebo `admin:*`. Existující hodnoty se zobrazí celé;
chybějící scope je nutné doplnit u konkrétního klienta. Upgrade ho automaticky
nepřiděluje. Bastion vyžaduje `openid profile email groups bastion:connect`
pro uvedený klientský profil. Oprava formuláře prošla cargo check serveru
včetně kompilace šablon; ověření nasazeného UI následuje po nové výměně serveru.

## Ověření nasazení 2026-10-05

Uživatel ověřil nasazený server (Passkey login do Grafany a admin token),
SSH signer (HTTPS health endpoint), OAuth2 proxy (registry login/logout a
zachování relace po více než pěti minutách) a bastion. Bastion bez tokenu
vrací 401; browser SSO, katalog hostů, vydání certifikátu, připojení jako
`mares` na `intel-nuc1` a návrat po `exit` byly funkčně ověřeny.
Admin UI po opravě uložilo a zobrazilo vlastní scope `bastion:connect`.
Nginx access logy SSO a registry v dodaných výpisech neobsahují query string.

Tím je základní audit a uvedené funkční ověření uzavřeno. Výjimka závislosti
`rsa`, dočasný development režim s admin tokenem a podmíněná doporučení
pro síťové omezení backendů, PostgreSQL TLS a systemd sandbox zůstávají
zdokumentované; toto ověření samo nepotvrzuje jejich realizaci.
UUID default tenantu zůstává na výslovné přání uživatele beze změny.

## Ověření u vývojáře

Před pushem/vydáním spusť `just ci-check`. GitHub CI používá tentýž
`scripts/ci-check.sh` (verze, testy release/audit politiky, fmt, workspace se
všemi targets a RustSec audit). Skript vyžaduje cargo-audit 0.22.2 a Python
3.11+; na macOS vybírá dostupný novější Python stejně jako release.sh.
Databázové integrační testy zůstávají zvlášť, stejně jako dosud.

Kontrola 2026-10-14 odhalila čtyři nové advisory pro `rustls 0.23.45`:
RUSTSEC-2026-0346, 0347, 0348 a 0349. Cargo.lock byl aktualizován na opravený
`rustls 0.23.46`. Pro tyto nálezy se nepřidává žádná výjimka; stávající
konkrétní výjimka rsa 0.9.10 / RUSTSEC-2023-0071 zůstává beze změny.

```bash
just ci-check
bash scripts/test-postgres.sh
```

PostgreSQL testy běží pouze lokálně přes oddělený Docker Compose projekt,
nikoli přes databázi přístupnou z CI. Skript po testech odstraní dočasné
kontejnery a data. Postup je také v README. Živý AD/OIDC provider, WebAuthn
browser ceremony a Windows ACL vyžadují integrační ověření v konkrétním
prostředí; lokální testy je nenahrazují.
