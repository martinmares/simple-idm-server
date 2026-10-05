# Bezpečnostní audit Simple IDM

Datum: 2026-10-04. Verze: 0.12.1. Revize: `cadb5b77e9c74d960a91c549e72a3dfecb842a79`.

## Shrnutí

Největší riziko představují hranice autorizace: ověření OAuth klienta, povolené scopes, izolace tenantů a přijímání tokenů administračním API. Další důležité problémy jsou nedostatečná revokace přihlašovacích oprávnění a ignorované volby SSH certifikátů. Doporučuji tyto chyby opravit před nasazením do prostředí s nedůvěryhodnými klienty nebo více tenanty.

Audit neprokázal napadení aplikace ani zveřejnění skutečných produkčních tajemství. Změna viditelnosti Git repozitáře sama neopravuje chyby nasazené aplikace. Závažnost níže zohledňuje předpoklady použití; žádný nález zde není označen jako bezpodmínečně kritický.

Jde o obrannou revizi kódu, nikoli certifikaci bezpečnosti. Report neobsahuje útočné postupy, payloady ani hodnoty tajemství. Nálezy a řádky níže popisují původní auditovanou revizi; následné opravy jsou uvedené v další části.

## Následné opravy

Podrobnosti nasazení a změn konfigurace: [SECURITY_UPGRADE.md](SECURITY_UPGRADE.md).
Report byl přesunut do `docs/`. Default tenant UUID se podle rozhodnutí
provozovatele nemění. Databázové testy se spouštějí lokálně přes Docker Compose.

| Nález | Provedená náprava |
|---|---|
| 01 | Confidential secret se ověřuje nezávisle na PKCE; public klient vyžaduje S256. |
| 02 | Scopes se kontrolují proti registraci klienta při vydání i obnově grantů. |
| 03 | Společná kontrola aktivního uživatele, klienta a stejného tenantu včetně SSO. |
| 04 | Explicitní admin audience, scope `admin:*`, access-token typ a aktuální databázová role default tenantu. |
| 05 | Podmíněné jednorázové spotřebování a uložení refresh tokenu v transakci; kontrola počtu spotřebovaných řádků. |
| 06 | Jednotná revokace grantů a rozpracovaných ověření; verze přihlašovacích údajů a serializace dokončení s revokací. |
| 07 | `-O clear` pro všechny certifikáty a explicitní nakonfigurované extensions. |
| 08 | Bezpečný serde default `/`, validace konfigurace a společná normalizace kontrolované/forwardované cesty. |
| 09 | UserInfo při obnově, shoda subjectu, nové skupiny/profil, pevná maximální délka relace. |
| 10 | Chyby načtení autorizačních dat ukončí vydání tokenu. |
| 11 | Hlavičky jen od důvěryhodných peerů, atomický PostgreSQL čítač a account throttling AD proxy. |
| 12 | Centrální kontrola přesného Origin pro všechny mutace webové administrace, včetně loginu. |
| 13 | Log celého token response odstraněn. |
| 14 | TTL cache, nahrazení celé sady, single-flight a cooldown pro neznámé klíče. |
| 15 | Atomický zápis CLI session souboru, na Unixu soukromý adresář a 0600 od vytvoření. Windows ACL viz nasazení. |
| 16 | Společná kontrola HTTPS mimo loopback a HTTP klienti bez redirectů s timeoutem v opravovaných identity cestách. |
| 17 | Odstraňuje se také nakonfigurovaná groups hlavička pro HTTP i WebSocket. |
| 18 | Unix publishing přes directory descriptors a no-follow; soukromý output/staging. Windows viz nasazení. |
| 19 | Advisory zůstává upstream neopravená; konkrétní výjimka pro veřejné RSA operace a kontrola nových nálezů v CI. |

Při opravách se navíc sjednotila kontrola Device Flow client ID/secret,
jednorázové spotřebování device code, upstream OIDC nonce/S256/ID token,
zákaz rezervovaných JWT claims, limity hesel a omezený blocking pool Argon2.
SSH key record má strukturovanou kontrolu, limit velikosti a signing timeout.
OIDC flow state je jednorázový v proxy; federovaný state serveru je šifrovaný
a časově omezený.

Regresní testy pokrývají odmítnutí confidential klienta bez secret při přítomném
verifieru, souběžné spotřebování kódu, revokaci po změně hesla/MFA, tenant
hranice, PKCE/scopes/granty, odmítnutí ID tokenu na access-token verifieru,
obnovu proxy claims, SSH extensions, public-prefix hranice a symlink parent.
Závěrečné ověření oprav dne 2026-10-05:

- `SQLX_OFFLINE=true cargo test --locked --workspace --all-targets`: **147 passed, 9 ignored, 0 failed**. Běh mimo sandbox umožnil lokální sockety používané testy bastionu.
- `bash scripts/test-postgres.sh`: **8 passed, 0 failed**; všechny migrace 001–049 prošly na dočasném lokálním PostgreSQL přes Compose. Container a jeho data byly po testu odstraněny.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: **26 passed**.
- Workspace `cargo check --locked --workspace --all-targets`, `cargo fmt --all -- --check`, `git diff --check` a kontrola sdílené verze prošly.
- Surový `cargo audit` nadále hlásí **RUSTSEC-2023-0071 / rsa 0.9.10**. Kontrola `scripts/audit-dependencies.py` prošla s přesně vymezenou výjimkou pro tuto advisory a verzi; nové nálezy či warnings selžou. Upstream problém není opravený.

Databázový regresní test navíc ověřuje, že registrace TOTP se starou verzí
přihlašovacích údajů po revokaci neaktivuje nový faktor. Browser WebAuthn,
živý AD/OIDC provider a Windows ACL vyžadují samostatné ověření v cílovém prostředí.

### Následné ověření při nasazení OAuth proxy

Dne 2026-10-05 byl opraven starší parser OAuth Basic credentials: před
ověřením nyní dekóduje form encoding client ID/secret. Confidential secret
obsahující `+`/`/` se tím ověřuje správně i s PKCE. Authorization-code a
refresh chyby nyní vracejí odpovídající HTTP status; původní HTTP 200 zakrývalo
skutečný OAuth error a způsobovalo chybné vyhodnocení selhání v throttlingu.

Workspace: **149 passed, 9 ignored, 0 failed**. Lokální PostgreSQL:
**8 passed**, včetně endpoint testu encoded Basic + S256 a odmítnutí
chybějícího secretu s HTTP 401. Workspace check, format a diff kontrola prošly;
Linux MUSL release serveru byl znovu sestaven. Nasazenou opravu je ještě
potřeba ověřit novým přihlášením; žádný secret ani PKCE pravidlo se neoslabuje.

Při následné kontrole proxy byl odstraněn opomenutý výpis session ID při
logoutu a raw state při nenalezeném flow. State cookie má na HTTPS Secure.
Dva cílené proxy testy a cargo check prošly; Linux release proxy sestaven.

Při integračním ověření logoutu access log potvrdil, že chráněný favicon
spouštěl nový login přes dosud aktivní SSO. Přesná lokální `/favicon.ico`
route nyní vrací 204 bez OAuth toku. Ostatní cesty a state kontrola zůstávají
chráněné. Cílené proxy testy/check prošly, Linux release proxy byl sestaven.

## Rozsah a ověření

Prozkoumány byly server/core, Admin API a UI, OAuth/OIDC toky, MFA, Passkeys, AD/LDAP knihovny a proxy, OAuth proxy, token proxy, metadata proxy, SSH signer/login, bastion, CLI, migrace, konfigurační příklady a CI.

- `SQLX_OFFLINE=true cargo test --workspace --locked`: **139 úspěšných testů, 6 ignored, žádný neúspěšný**. První běh uvnitř sandboxu narazil na zákaz lokálních socketů; opakování s povolením prošlo.
- `SQLX_OFFLINE=true cargo build --locked -p simple-idm-server`: úspěšný build aktuální revize.
- `cargo audit` 0.22.2: **1 vulnerability, 0 warnings**, 581 závislostí. Databáze RustSec: 1290 advisorií, revize `ef6173cbc5c50ec8166f9a5b28f07834144373ee`, poslední aktualizace 2026-10-03. Exit code 1 zde znamená nalezenou advisory. Původní verze 0.21.2 nedokázala zpracovat CVSS 4.0; její neúspěšný výstup není použit jako výsledek auditu.
- `gitleaks git --redact=100 --log-opts='--all'`: 227 prohledaných commitů, přibližně 5,29 MB, 4 kandidáti; po kontrole testovací data nebo falešné pozitivní výsledky. Kontrola se týká historie dostupné v lokálním klonu, nikoli neexistujících lokálních refs nebo všech objektů vzdáleného serveru.
- Kontrola `unsafe`, SQL dotazů, procesů, cest, oprávnění souborů a TLS nastavení byla statická.
- Nálezy 01–03 byly během počáteční části auditu také potvrzeny na izolované dočasné lokální instanci. Po upřesnění rozsahu už nebyly vyvíjeny ani spouštěny další reprodukční scénáře; reprodukční skript není součástí výsledku.

Přeskočené testy zahrnují databázové kontroly importu, doménových politik, Device SSO a Passkeys a test vyžadující skutečné PTY. Testy v kořenovém `tests/` nejsou automaticky zapojené jako integrační testy, protože kořenový Cargo manifest je virtuální workspace. Úspěšný běh workspace tedy nepotvrzuje tyto starší E2E scénáře. Nebyl proveden produkční penetrační test, fuzzing, Miri, ověření živého AD ani browser test WebAuthn.

## Vysoká závažnost

### 01 — Ověření confidential OAuth klienta závisí na vstupu požadavku

**Kód:** `crates/simple-idm-core/src/oauth2/authorization_code.rs:2431`, `:2467`.

**Vysvětlení:** Kontrola client secret je přeskočena podle přítomnosti `code_verifier` v požadavku místo typu registrovaného klienta. Pokud uložený kód nemá PKCE challenge, následná větev verifier ani neověří. PKCE a autentizace confidential klienta jsou dvě nezávislé kontroly. Platný authorization code tak není dostatečně chráněn tajemstvím klienta. Samotný nález nepřekonává potřebu získat platný kód; v kombinaci s dalšími chybami zde výrazně oslabuje ochranu.

**Náprava:** Ověřovat tajemství každého confidential klienta bez ohledu na PKCE. Public klienty identifikovat pouze podle registrace. Public Authorization Code Flow vyžadovat se S256 PKCE; odmítat nekonzistentní challenge/verifier. Sjednotit pravidla mezi jednotlivými granty.

**Validace opravy:** Negativní test confidential klienta s platným PKCE a chybějícím či chybným tajemstvím; public klienta bez challenge; verifier bez původní challenge.

### 02 — Vydávání scopes bez omezení registrací klienta

**Kód:** `crates/simple-idm-core/src/oauth2/authorization_code.rs:320`, `:1388`, `:1126`; `crates/simple-idm-core/src/oauth2/client_credentials.rs:240`; `crates/simple-idm-core/src/oauth2/device_flow.rs:301`.

**Vysvětlení:** Požadovaný scope se převezme přímo a podepíše do tokenu. Není vynucena podmnožina povolených scopes klienta. Scope tak nepředstavuje spolehlivou autorizační hranici, pokud na něj downstream služba spoléhá. Bastion již rozlišuje `bastion:connect` a `bastion:admin`; ostatní kontroly skupin/tenantu nadále platí, takže samotné přidání scope není automaticky plný přístup.

**Náprava:** Zavést společnou validaci scopes proti registraci klienta a případným oprávněním uživatele. Nepovolené scopes odmítnout s `invalid_scope`. Při refreshi znovu respektovat aktuální oprávnění klienta; rozsah nesmí narůstat. Do kontroly zahrnout SSO, federaci, Passkeys, Device Flow i M2M.

**Validace opravy:** Pro každý grant ověřit odmítnutí nepovoleného scope a správné chování po odebrání scope klientovi.

### 03 — Authorization Code Flow nekontroluje shodu tenantu uživatele a klienta

**Kód:** `crates/simple-idm-core/src/oauth2/authorization_code.rs:300`, `:348`, `:1222`, `:1350`, `:1384`, `:2511`; `crates/simple-idm-core/src/oauth2/passkey_routes.rs:181`.

**Vysvětlení:** SSO vybere uživatele ze session a klienta nezávisle. U heslového loginu se tenant uživatele určuje z emailu/defaultu a klient se řeší zvlášť. Před vydáním běžného authorization code chybí kontrola, že klient a uživatel patří do stejného tenantu. Kontrola auth policy při výměně kódu se týká uživatele, nikoli vztahu uživatel–klient. Token pak může obsahovat audience klienta jiného tenantu a skupiny původního uživatele. Device Flow naopak explicitní vztah tenantů kontroluje.

**Náprava:** Centrálně vynucovat vztah uživatele a klienta při zahájení, dokončení a výměně autorizačního toku. Výjimky pro sdílené klienty případně modelovat explicitní ACL, ne implicitním přístupem. Pokud má být cross-tenant SSO záměrnou funkcí, zdokumentovat a testovat tuto hranici včetně izolace skupin a claims.

**Validace opravy:** Testovat odlišné tenanty pro SSO, heslo, Passkeys, federaci a exchange; ověřit, že se claims cizího tenantu nevydávají.

### 04 — Admin API a UI přijímají tokeny libovolného aktivního OAuth klienta

**Kód:** `crates/simple-idm-core/src/admin/middleware.rs:88`, `:108`, `:113`; `crates/simple-idm-server/src/web_admin.rs:2948`, `:2968`; `crates/simple-idm-core/src/auth/jwt.rs:157`, `:220`.

**Vysvětlení:** Očekávané audiences tvoří všechny aktivní klientské identifikátory. Následná autorizace stojí na názvu skupiny, bez vyhrazené admin audience, scope a jasného rozlišení access/ID tokenu. ID token obsahuje stejnou skupinu a používá stejný podpis; verifier s prázdným seznamem required scopes ho může přijmout. Aplikace, do níž se přihlásí správce, tak dostává token potenciálně použitelný i pro správu IDM. Neznamená to, že libovolný běžný uživatel získá admin roli. Navíc skupiny jsou tenantově unikátní, ale admin oprávnění je podle middleware globální, bez ověření původu privilegované skupiny.

**Náprava:** Vyhradit admin resource/audience, explicitní scopes a tokenový typ. ID tokeny pro API odmítat. Oddělit globální správce od správců tenantů a validovat původ role. Stejné rozhodování sdílet mezi UI a API. Opravit také nesoulad komentáře o M2M `admin:*` se skutečnou implementací, která tyto scopes nekontroluje.

**Validace opravy:** ID token, access token běžného klienta a stejně pojmenovaná role z jiného tenantu musí být odmítnuty.

### 05 — Authorization code není spotřebován atomicky

**Kód:** `crates/simple-idm-core/src/oauth2/authorization_code.rs:2326`, `:2698`, `:2725`.

**Vysvětlení:** Kód se nejdřív načte, vytvoří se tokeny a uloží refresh token a až pak se kód smaže. Vydávání není chráněno transakcí se zámkem ani atomickým spotřebováním kódu. Dva souběžné požadavky mohou oba projít stejnou validací. Výsledek mazání je navíc ignorován. To porušuje jednorázovost authorization code; předpokladem jsou údaje nutné k jinak platné výměně.

**Náprava:** V jedné transakci zamknout a ověřit kód, spotřebovat jej právě jednou a uložit navazující oprávnění. Kontrolovat počet změněných řádků; nevydat token při selhání spotřebování. Opakované použití zaznamenat a zvážit revokaci příslušné tokenové rodiny.

**Validace opravy:** Souběžná výměna musí mít právě jeden úspěšný výsledek; rollback nesmí zanechat použitelný refresh token.

### 06 — Reset hesla, MFA a Passkeys neodvolává všechny navazující přihlašovací údaje

**Kód:** `crates/simple-idm-core/src/password_reset.rs:109`, `:144`; `crates/simple-idm-core/src/mfa.rs:398`; `crates/simple-idm-core/src/passkeys.rs:180`, `:406`; `crates/simple-idm-core/src/oauth2/authorization_code.rs:2912`.

**Vysvětlení:** Password reset mění hash hesla a reset tokeny, ale ponechává SSO sessions, authorization codes a refresh tokens. MFA a Passkey reset ruší autentikátory a browser sessions, nikoli dříve vydané refresh tokeny a authorization codes. Refresh kontroluje uložené `amr` vůči politice, ale nikoli, zda byl příslušný autentikátor mezitím odvolán. Oprávnění vzniklé před bezpečnostním resetem tak může dál vydávat nové access tokeny. To je podstatně delší pokračování přístupu než dokumentovaná platnost již vydaného access tokenu do expirace.

**Náprava:** Bezpečnostní reset provádět transakčně s revokací browser sessions, kódů, refresh tokenových rodin a pending login/registration transakcí. Zavést uživatelské `credentials_version` nebo `revoked_before`, kontrolované při exchange a refreshi. Definovat rozdíl mezi běžným odstraněním jedné Passkey a incidentním resetem všech metod.

**Validace opravy:** Po každém druhu resetu musí starý refresh token, autorizační kód a stará login transakce přestat fungovat; nové přihlášení musí uspět podle aktuální politiky.

### 07 — Přímý SSH signer ignoruje nastavení zakazující forwarding

**Kód:** `crates/simple-idm-core/src/ssh_signer/config.rs:61`; `crates/simple-idm-ssh-signer/src/main.rs:121`; `crates/simple-idm-core/src/ssh_signer/cert_signer.rs:122`, `:134`.

**Vysvětlení:** Konfigurace definuje `permit_port_forwarding`, `permit_agent_forwarding`, `permit_x11_forwarding` a `permit_user_rc`, standardně false. Tyto hodnoty se ale nepředávají do `CertSigner`. Pouze bastionová větev vymaže výchozí extensions a povolí PTY; přímá větev ponechává výchozí oprávnění OpenSSH certifikátu. Správce tak může věřit omezením, která certifikát ve skutečnosti neobsahuje. Výsledné možnosti stále omezuje konfigurace cílového sshd. [Dokumentace ssh-keygen](https://man.openbsd.org/ssh-keygen#O).

**Náprava:** Pro všechny certifikáty začít prázdným seznamem extensions a přidat pouze explicitně povolené vlastnosti. Předávat config do signeru a testovat obsah skutečně vydaných certifikátů. Bastionovou větev zachovat omezenou na její účel.

**Validace opravy:** Pro každou kombinaci voleb kontrolovat extensions certifikátu; zejména všechny forwarding volby false.

### 08 — Reverse proxy může při chybějící konfiguraci nechránit žádnou cestu

**Kód:** `crates/simple-idm-core/src/proxy/config.rs:17`, `:166`; `crates/simple-idm-oauth2-proxy/src/main.rs:146`, `:532`, `:551`.

**Vysvětlení:** Při deserializaci TOML chybějící `protected_prefixes` dostane prázdný vektor. Toto se liší od `Config::default()` s ochranou `/`. Validace reverse_proxy režimu prázdný seznam nezakazuje a `is_protected_path` pak nechrání žádnou cestu. S veřejnými výjimkami navíc rozhoduje raw prefix před normalizací upstream URL, což vytváří riziko rozdílného posouzení cest proxy a upstreamem. První problém vyplývá přímo z kódu; dopad normalizace závisí na konkrétním upstreamu a konfiguraci výjimek a nebyl samostatně dynamicky ověřen.

**Náprava:** Výchozí chování reverse proxy musí vyžadovat autentizaci. Vyžadovat explicitní konfiguraci veřejných výjimek; odmítnout prázdné ochranné nastavení, pokud není záměrně povolen veřejný režim. Autorizaci i forwarding opřít o stejnou kanonickou cestu a segmentové porovnání prefixů; nejednoznačné cesty odmítat.

**Validace opravy:** Chybějící nastavení nesmí vytvořit veřejný upstream; normalizované cesty a hranice segmentů musí mít stejné autorizační rozhodnutí.

## Střední závažnost

### 09 — OAuth proxy uchovává staré skupiny i po obnově tokenu

**Kód:** `crates/simple-idm-core/src/proxy/oidc.rs:182`, `:203`; `crates/simple-idm-core/src/proxy/session.rs:154`, `:357`; `crates/simple-idm-oauth2-proxy/src/main.rs:434`.

**Vysvětlení:** Refresh vrátí pouze refresh token. Session prodlouží expiraci, ale username/email/groups ponechá z původního loginu. Odebraná role proto může pokračovat v autentizačních hlavičkách přes více obnov session. Tato chyba se uplatní, pokud upstream autorizuje podle těchto skupin. Při defaultní hodinové session existuje i bez refreshů hodinové okno; refresh ho může prodlužovat.

**Náprava:** Po refreshi získat a validovat aktuální claims, např. přes UserInfo nebo nově vydaný ověřený ID token, a atomicky aktualizovat session. Zajistit shodu subjectu. Stanovit maximální stáří autorizačních dat a nepřekročitelnou životnost session.

### 10 — Chyba DB při načítání group filtrů rozšíří výstup tokenu

**Kód:** `crates/simple-idm-core/src/oauth2/authorization_code.rs:2596`, `:2970`.

**Vysvětlení:** Při chybě načtení klientských filtrů se vrátí nefiltrované skupiny a token se přesto vydá. Selhání autorizačního omezení tedy vede k širšímu přístupu nebo zveřejnění skupin, pokud filtr slouží jako bezpečnostní hranice.

**Náprava:** Při chybě odmítnout vydání tokenu nebo použít bezpečnou poslední validovanou konfiguraci. Všechny granty musí sdílet stejné chování; chybu auditovat bez obsahu tokenu.

### 11 — Důvěra v proxy hlavičky a souběh oslabují throttling

**Kód:** `crates/simple-idm-server/src/main.rs:480`, `:488`; `crates/simple-idm-core/src/oauth2/throttle.rs:7`, `:20`, `:67`; `crates/simple-idm-ad-proxy/src/main.rs:306`.

**Vysvětlení:** `SmartIpKeyExtractor` používá forwarded IP hlavičky bez vazby na `TRUST_PROXY_HEADERS` a bez ověření síťového peeru. `extract_client_ip` navíc čte `x-real-ip` i s vypnutou důvěrou. To oslabuje síťové limity, pokud ingress hlavičky nepřepisuje nebo je služba dostupná přímo. Per-identity čítač používá SELECT a následný UPSERT s předpočítanou hodnotou, takže souběžná selhání mohou ztratit přírůstky. Standalone AD proxy nemá vlastní throttling a může neomezeně zatěžovat autentizační backend. Per-identity ochrana serveru dál představuje částečnou obranu; nález neznamená, že ji pouhá změna IP zcela překoná.

**Náprava:** Bez trusted proxy používat skutečného peeru; forwarded hlavičky přijímat jen od seznamu trusted peerů a jednotně pro všechny limity. Čítače měnit atomicky v DB. Standalone AD proxy doplnit vlastní omezení nebo vynutit a zdokumentovat ingress throttling.

### 12 — Admin formuláře nemají explicitní CSRF ochranu

**Kód:** `crates/simple-idm-server/src/web_admin.rs:2989`, `:3203`, `:5313`; administrační POST routy `:1277`.

**Vysvětlení:** Mutace ověřují session cookie, ale ne CSRF token nebo Origin. Cookie `SameSite=Lax` omezuje běžné cross-site POST, nikoli všechny situace mezi různými origins stejného site. Významné je prostředí s méně důvěryhodnými aplikacemi na sousedních subdoménách. Login formulář také postrádá vazbu na původ požadavku. MFA reset je příkladem citlivé mutace bez této ochrany.

**Náprava:** Na všechny cookie-authenticated mutace zavést session-bound CSRF token a kontrolu přesného Origin vůči konfiguraci. SameSite ponechat jako další ochranu. Cookie pro administraci zvážit s prefixem `__Host-`, pokud je kompatibilní s deploymentem.

### 13 — Token response obsahující refresh token může skončit v logu

**Kód:** `crates/simple-idm-core/src/oauth2/authorization_code.rs:2752`; `.env.example:97` (nastavení logování).

**Vysvětlení:** Debug log serializuje celý `TokenResponseWithRefresh`, který obsahuje access, ID a refresh token. Při zapnutí debug logování pro core vzniká další dlouhodobé úložiště přihlašovacích údajů. Ukázkový log filter zapíná debug serveru; sám o sobě nemusí zapnout target core, proto nález závisí na skutečném filtru.

**Náprava:** Odstranit logování token response a používat metadata události. Pro secret-bearing struktury nepoužívat neomezený Debug. Pokud core debug běžel v produkci, ověřit logy a odvolat dotčené refresh tokeny; nepublikovat jejich hodnoty při kontrole.

### 14 — JWKS cache signeru a bastionu nemá expiraci

**Kód:** `crates/simple-idm-core/src/ssh_signer/jwt_validator.rs:159`, `:200`, `:210`; používající služby signer/bastion.

**Vysvětlení:** Klíč známého `kid` se vrací z cache bez limitu stáří. Funkce `refresh_jwks` nemá v produkčním kódu volajícího. Klíč odebraný kvůli kompromitaci proto může zůstat důvěryhodný až do restartu. Neznámé `kid` naopak pokaždé vyvolává HTTP fetch bez negativní cache a koordinace souběhu, což vytváří zátěž na IdP.

**Náprava:** Přidat omezené stáří cache, atomickou výměnu celé sady klíčů a definovanou revokační latenci. Zavést single-flight refresh a krátkou negativní cache neznámých identifikátorů. Záměrný overlap rotace explicitně konfigurovat.

### 15 — CLI zapisuje session credentials před nastavením restriktivních oprávnění

**Kód:** `crates/simple-idm-ctl/src/main.rs:74`, `:81`, `:88`.

**Vysvětlení:** `sessions.json` obsahuje přihlašovací tokeny. Je vytvořen/zapsán přes `fs::write` a teprve potom přepnut na 0600. Při běžném umask může být první vytvoření krátce čitelné ostatním lokálním uživatelům; soubor se také zapisuje neatomicky. Adresář není explicitně zajištěn jako 0700. Dopad je lokální, zejména na sdílených systémech; oprávnění již existujícího souboru mohou riziko zmenšit.

**Náprava:** Soukromý adresář 0700, vytvoření nového dočasného souboru s 0600 od začátku, atomický rename a odpovídající ochrana před symlinky. Na Windows aplikovat uživatelské ACL nebo systémové credential storage.

### 16 — TLS pravidla nejsou jednotná mezi komponentami

**Kód:** `crates/simple-idm-core/src/proxy/config.rs:176`; `crates/simple-idm-core/src/ssh_signer/jwt_validator.rs:86`; `crates/simple-idm-core/src/ssh_login/signer_client.rs:28`; `crates/simple-idm-core/src/oauth2/authorization_code.rs:973`.

**Vysvětlení:** OAuth proxy výslovně přijme HTTP issuer i pro vzdálený host. Přímý SSH signer a jeho klient nemají obdobné omezení issuer/signer URL, jaké má bastion. Tyto kanály přenášejí tokeny nebo důvěryhodné klíče. Fed token/UserInfo požadavky používají obecný reqwest klient s výchozí redirect policy a bez explicitního timeoutu; metadata nemají jednotnou validaci schématu. Veřejná HTTPS terminace před lokálním HTTP backendem je legitimní a není sama o sobě nálezem. Explicitní insecure TLS volby token/metadata proxy jsou záměrné a nesmí být zaměňovány za default.

**Náprava:** Sdílená validace URL: HTTPS pro vzdálené auth/metadata/signing endpointy, HTTP jen pro explicitní loopback nebo zdokumentovanou důvěryhodnou interní síť. Pro credential-bearing HTTP klienty nastavit timeout, limity response a redirect policy `none`. Insecure režimy výrazně logovat a pro produkční profil odmítat.

## Nízká závažnost a závislosti

### 17 — Vlastní auth header není zahrnut v sanitizaci proxy

**Závažnost:** nízká; podmíněná důvěrou upstreamu v hlavičku a konfigurací veřejných cest.

**Kód:** `crates/simple-idm-oauth2-proxy/src/main.rs:572`, `:604`, `:705`; `crates/simple-idm-core/src/proxy/config.rs:50`.

**Vysvětlení:** Sanitizace odstraní pouze pevné názvy `x-auth-*`, ale `groups_header_name` je konfigurovatelný. Na chráněné autentizované cestě jej injekce obvykle přepíše. Na veřejné cestě bez session však může klientem poslaná vlastní skupinová hlavička zůstat zachována. Relevantní je upstream používající tuto hlavičku i na veřejných cestách.

**Náprava:** Před forwardingem odstranit všechny konfigurované identity headers bez ohledu na výsledek autentizace a teprve pak vložit ověřená data. Ověřit HTTP i WebSocket cestu.

### 18 — Token-proxy fetch nechrání cílovou cestu proti lokálním symlinkům

**Závažnost:** nízká; zvýšená na střední, pokud může jiný uživatel měnit výstupní adresář privilegovaného procesu.

**Kód:** `crates/simple-idm-token-proxy/src/main.rs:408`, `:544`, `:552`.

**Vysvětlení:** Lexikální kontrola relativního cíle je správná, ale pozdější spojení s output_dir a `create_dir_all`/rename neřeší symlinky v nadřazených segmentech. V nedůvěryhodném výstupním adresáři tak chybí ochrana proti přesměrování zápisu mimo zamýšlený strom. Nejde o prokázanou vzdálenou path traversal v HTTP endpointu.

**Náprava:** Používat soukromý output_dir s ověřeným vlastníkem. Pokud je potřeba bezpečná práce v cizím adresáři, použít descriptor-relative operace s odmítnutím symlinků; samotná jednorázová canonicalize nezabrání souběžné změně cest.

### 19 — Závislost rsa 0.9.10 má neopravenou RustSec advisory

**Závažnost:** advisory střední, CVSS 5.9; dosažitelný dopad v produkčním kódu tohoto repa nebyl prokázán.

**Kód:** `Cargo.lock:3701`; `crates/simple-idm-core/Cargo.toml:33`; `crates/simple-idm-core/src/auth/jwt.rs:269`.

**Vysvětlení:** `cargo audit` identifikuje [RUSTSEC-2023-0071 / CVE-2023-49092](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), timing problém soukromých RSA operací; advisory aktuálně nemá opravenou verzi. Vlastní produkční použití této knihovny zde zpracovává veřejný klíč pro JWKS. JWT podpis zajišťuje `jsonwebtoken` s AWS-LC. Soukromé RSA operace přes `rsa` nalezené v repo jsou v testech. `rsa` je také transitivní závislostí `openidconnect`, který se zde používá pro ověřování upstream tokenů. Proto z výsledku auditu nevyplývá, že server tímto problémem zveřejňuje svůj JWT privátní klíč.

**Náprava:** Pro JWKS zvážit veřejný key parser bez této závislosti; transitivní závislost řešit s aktualizacemi OIDC knihovny. Do dosažení nápravy zdokumentovat konkrétní nedosažitelnost soukromých RSA operací a sledovat advisory. Pouhá změna na jinou neopravenou verzi nebo plošné ignorování auditu není náprava.

## Další ověřené oblasti a omezení

### Unsafe Rust

V produkčním Rust kódu nalezen jeden explicitní blok: `crates/simple-idm-ssh-login/src/bastion.rs:806`, volání `libc::ttyname_r`. Buffer má 1024 zapisovatelných bajtů, předaná délka mu odpovídá, návratová hodnota se kontroluje a nulové ukončení se hledá v mezích bufferu. Při statické kontrole nebyla nalezena konkrétní chyba paměťové bezpečnosti. Toto tvrzení nepokrývá unsafe v závislostech; Miri/sanitizery nebyly spuštěny.

### Tajemství v Gitu

Čtyři nálezy Gitleaks:

| Soubor | Vyhodnocení |
|---|---|
| `crates/simple-idm-core/tests/fixtures/jwt-10-rs256.json:3` | JWT fixture se separátním testovacím veřejným klíčem a testovacím issuerem; dokumentována v testu jako disposable fixture. |
| Historický `crates/simple-idm-bastion/src/server.rs:494` | Standardní testovací WebSocket handshake key, nikoli přístupové tajemství. |
| Historický `docs/OAUTH2_PROXY.md:86` | UUID subjectu v ukázce hlaviček, nikoli bearer credential. |
| Historický `docs/BASTION_IMPLEMENTATION_PLAN.cs.md:94` | Běžný text zachycený generickým pravidlem, nikoli API key. |

Nebyl potvrzen produkční secret. Doplňkový pattern scan historie nenalezl vložený skutečný privátní klíč; shoda v `scripts/bastion-smoke.py` je dynamické generování klíče pro fixture. Lokální `.env`/klíče nebyly použity k provozu auditu ani jejich hodnoty publikovány. Gitleaks nedokazuje nepřítomnost všech tajemství, zejména libovolných hesel bez rozpoznatelného formátu.

`.env.example` obsahuje označený vývojový root token a compose používá vývojové heslo PostgreSQL a publikovaný port. V produkci se tyto příklady nesmí přebírat beze změny; `APP_ENV=production` již root token odmítá. Síťový přístup k PostgreSQL omezit explicitně. Výchozí `AUTH_THROTTLE_CLEAR_ON_START=false` a vypnuté legacy admin fallbacky jsou správné.

### SQL a command injection

V prohlédnutých cestách jsou SQL hodnoty předávány jako bind parametry. Nebyla nalezena konkrétní SQL injection. LDAP login se před vložením do filtru escapuje pomocí `ldap_escape`; prázdné heslo je odmítnuto. StartTLS nyní selhává s chybou namísto tichého plaintext fallbacku; tato funkce tedy není implementována, ale nezavádí zjištěný downgrade.

SSH procesy obvykle předávají samostatné argumenty přes `Command`, nikoli shellovou interpolaci. Bastion má whitelist login/host/terminal hodnot, používá `/usr/bin/ssh`, `--` před cílem, omezené prostředí a kontrolu host key. Jeho `LocalCommand` má samostatné shell quoting a kontroly OpenSSH expanzí. Nebyla prokázána command injection. Přímé signer/login nástroje používají PATH pro `ssh`/`ssh-keygen`; v privilegované službě má být PATH důvěryhodný nebo použita pevná cesta.

### Vstupy a soubory

Signer public key kontroluje pouze prefix a počet částí (`crates/simple-idm-core/src/ssh_signer/cert_signer.rs:166`), finální parsování deleguje na ssh-keygen. Doporučuji strukturovaný parser, přesnou jedinou key record, pevný limit velikosti a timeout procesu. Toto doporučení má nízkou závažnost; slabší kontrola sama nedokládá command injection nebo únik CA klíče.

Hesla nejsou centrálně kontrolována na délku/politiku (`crates/simple-idm-core/src/auth/password.rs:19`, `crates/simple-idm-core/src/password_reset.rs:56`). Doporučuji společnou validaci pro vytvoření, změnu i reset a horní limit náročných vstupů. Argon2 operace běží synchronně; jejich přesun do omezeného blocking poolu sníží riziko vyčerpání async workerů. Toto doporučení má nízkou závažnost; jde o zpevnění dostupnosti, jeho praktická hranice nebyla změřena.

Bastion vytváří session adresář s 0700 a audit soubor s 0600, má omezený souběh a při ztrátě auditu odmítá další terminály. Passkeys vynucují přesný Origin, CSRF, ověření uživatele, jednorázové serverové ceremony state a kontrolu vlastnictví při mutacích. TOTP kontrola opakovaného časového kroku a recovery code spotřebování používají podmíněnou aktualizaci. To jsou správné ochrany; jejich existence neřeší revokační problém 06.

### OIDC interoperabilita a důvěra

Federovaný login v `crates/simple-idm-core/src/oauth2/authorization_code.rs:973` získává access token a UserInfo, ale nevaliduje upstream ID token/nonce jako standardní OIDC RP. Vazba `issuer + subject` a lokální approval je užitečná; samotná implementace však nepřebírá ověřené upstream `acr`/`amr`. Doporučuji použít ověřovací část `openidconnect` také zde, zavést nonce a S256 a ověřit shodu subjectu ID tokenu/UserInfo. Doporučení má nízkou závažnost jako protokolové zpevnění; konkrétní obejití loginu touto odlišností nebylo potvrzeno. Nelze z této cesty dovozovat upstream MFA assurance. AD MFA je v README explicitně delegováno upstreamu; prostý LDAP bind sám žádný MFA claim nepřináší, což musí odpovídat skutečné infrastruktuře.

JWT custom claims používají `serde(flatten)` (`crates/simple-idm-core/src/auth/jwt.rs:51`) a claim mapy nemají zjištěný zákaz rezervovaných názvů (`crates/simple-idm-core/src/auth/claims.rs:94`). Doporučuji rezervovat standardní claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `scope`, `groups`, `amr`, `acr`, `tenant_id`) při konfiguraci i před serializací, aby nevznikaly duplicitní JSON klíče a rozdílná interpretace konzumenty. Doporučení má nízkou závažnost; nebylo potvrzeno, že nynější first-party verifier takovou kolizi přijme jako eskalaci.

## Doporučené pořadí oprav

1. Společná validace OAuth klienta, scopes, grantů, tenantů a tokenového typu: 01–04. Authorization Code a refresh navíc mají explicitně kontrolovat, zda daný grant klient stále smí používat; běžný Authorization Code tok to nyní nekontroluje.
2. Atomické spotřebování kódů a jednotná revokace oprávnění: 05–06.
3. Skutečné SSH extensions a ochrana reverse proxy ve výchozím stavu: 07–08.
4. Obnova autorizace v proxy, fail-closed filtry, throttling, CSRF, logy a klíčová cache: 09–14.
5. Souborová oprávnění, TLS pravidla, podmíněné souborové/header problémy a správa závislostí: 15–19.

Při opravách přidat negativní regresní testy na bezpečnostní invarianty, nikoli jen úspěšné přihlášení. Databázové testy provozovat lokálně u vývojáře pomocí disposable PostgreSQL v Docker Compose (`bash scripts/test-postgres.sh`). CI používá offline SQLx metadata a testy bez PostgreSQL; nepotřebuje přístup k externí databázi. Samostatně provést WebAuthn browser testy a integrační ověření proti skutečně používaným OIDC/AD providerům.

Protokolové doporučení vychází z [OAuth Security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), pravidel jednorázových kódů a klientské autentizace v [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.3) a oddělení účelů tokenů v [JWT BCP, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12).
