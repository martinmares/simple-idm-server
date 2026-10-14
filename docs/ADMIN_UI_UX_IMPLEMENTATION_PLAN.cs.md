# Sjednocení admin UI Simple IDM

Stav: fáze 1 hotová (0.16.0); fáze 2 hotová (0.16.3); fáze 3 zatím nezačala. Schválený návrh z diskuze 2026-10-14.

## Kontrakt

- Zachovat Tabler, navigaci, motivy a stávající autorizační pravidla.
- Každý seznam: hlavička, primární akce vpravo, filtr, výsledky, stránkování.
- Primární akce stejné velikosti a s prefixem +; create/edit vždy modal.
- Základní filtr: Search, běžné podmínky, More filters, Apply, Reset.
- Hlavní filtry aplikovat Enterem/Apply. Pomocné pickery mohou hledat okamžitě.
- URL je autorita pro filtry, stránkování a aktivní tab. Reset nepřebírá staré cookies.
- UUID a dlouhá technická metadata do detailu, s Copy; řádky obvykle 48–64 px.
- Archive znamená archivaci; Delete se nepoužívá pro pouhou deaktivaci.
- Hromadný výběr má jasný rozsah a počet. Potvrzení obsahuje objekty a dopad.
- Zachovat graf balíčků, sdílené uzly, archivované reference a claim mapping.
- Audit rozlišuje aktéra a dotčený objekt. Historicky chybějící aktér se nedopočítává z target ID.

## Fáze 1 — společná struktura a přehledné seznamy

- [x] Společné CSS pro hlavičky, filtry, kompaktní tabulky, akce a modaly.
- [x] Users: odstranit abecedu, Apply/Enter místo automatického přepisování seznamu.
- [x] Users: kompaktní identita, security/stav samostatně, technické údaje v detailu.
- [x] Groups: skutečný filtr, Create group modal, kompaktní tabulka.
- [x] Groups: rozbalitelný graf, claim mappings a archivované reference zachovat.
- [x] Clients: Create modal, kompaktní tabulka, metadata v editačním detailu.
- [x] Identity providers: sjednotit filtr a akce.
- [x] Memberships: taby Users/Groups, URL zachovává aktivní pohled a výběr.
- [x] Claims: taby By client/Group usage, URL zachovává aktivní pohled a výběr.
- [x] Sjednotit názvosloví Archive a velikosti hlavních tlačítek.
- [x] Kompilace šablon a vizuální/browser ověření všech upravených pohledů.

## Fáze 2 — hromadné akce a plnohodnotné filtry

- [x] Users: checkboxy, výběr aktuální stránky, lišta akcí, Archive a Add to group.
- [x] Groups: checkboxy a hromadná archivace se zachováním grafového kontraktu.
- [x] Backend: znovu ověřit oprávnění a stav každého vybraného objektu.
- [x] Výsledek dávky: počty úspěšných/přeskočených/chybných objektů a důvody.
- [x] Audit změn: skutečný actor, cílové objekty, identifikátor dávky.
- [x] Rozšířené filtry Users: auth, MFA/passkeys, skupina; řazení.
- [x] Backend filtry/paginace Groups a Clients bez ztráty metadat grafu.
- [x] Explicitní výběr všech filtrovaných výsledků; nikdy implicitně místo stránky.
- [x] Filtry v aktivním Memberships/Claims pohledu rozšířit při zachování selekce.
- [x] Přidat Copy UUID v detailech a jednotné zobrazení počtů/aktivních filtrů.
- [x] Validační chyby create/edit zobrazovat u polí se zachováním formuláře.

## Fáze 3 — audit a užitečný dashboard

- [ ] Audit: od/do a timezone, actor, target, client, action, outcome, text.
- [ ] Nahradit pevné LIMIT 200 stabilním stránkováním (timestamp + event ID).
- [ ] Sjednotit auditní kontext v emiterech; chybějící historical actor přiznat.
- [ ] Čitelný popis události, samostatná technická data v detailu.
- [ ] Souhrny podle CELÉHO filtrovaného rozsahu, nikoli aktuální stránky.
- [ ] CSV/JSON export stejného filtrovaného rozsahu, explicitní rozsah/limity.
- [ ] Exporty ošetřit pro tabulkové aplikace a nezahrnovat tokeny/hesla.
- [ ] Dashboard: MFA k dokončení a chybná přihlášení s odkazy na filtr.
- [ ] Tenants/domains: stručný single-tenant pohled, jednoduché hledání domén dle potřeby.
- [ ] Integrační ověření filtrů, auditních aktérů, stránkování, exportu a dávek.

## Ověřování a vydání

Po každé fázi: aktualizovat checklist, zaznamenat ověření a zbývající práci.
Nevyžaduje nový frontend framework. Sdílet malé šablonové/CSS/JS části, nikoli
vytvářet obecný renderer všech entit. UI fáze nesmí sama změnit claim semantics.
Verzi zvýšit pomocí `just release-version` po dokončení ověřeného celku.
Commit/push provést podle pokynu uživatele; tento plán sám push neautorizuje.

## Pracovní poznámky

- Audit query dnes vrací LIMIT 200 bez stránkování.
- Společný emit_event dnes nezapisuje actor_sub/actor_client_id.
- Users mají backend stránkování; Groups potřebují úplný graf pro zobrazení stromu.
- Hromadné odstranění vazeb v Memberships už existuje; využít ho.
- Žádná fáze se nemá vydávat za hotovou pouze podle screenshotů bez funkčního ověření.

## Lokální browser ověření fáze 1

Fixture existuje jen v testovací binárce. Nepoužívá DB, reálné uživatele ani
mutace. Generuje skutečné Askama šablony s fiktivními účty a úplným grafem.

```sh
ADMIN_UI_FIXTURE_INFO=/tmp/idm-admin-fixture-info \
  cargo test -p simple-idm-server admin_ui_browser_fixture -- --ignored --nocapture
```

Otevřít `origin` z JSON souboru + `/admin/ui/users` v Playwright CLI a spustit:

```sh
playwright-cli run-code --filename=crates/simple-idm-server/examples/verify-admin-ui.js
```

Fixture ukončit POSTem na `/quit` stejného loopback originu. Screenshoty jsou
v ignorovaném `output/playwright/`. Fixture ověřuje rozložení, modaly, grafové
reference, claim detail, filtry Groups a URL/tab stav. Produkční autorizaci ani
SQL filtrování/paginaci nenahrazuje. Testy formulářů:
`cargo test -p simple-idm-server web_admin::tests`.

Od 0.16.2 Groups filtrují a stránkují seznam na serveru. Úplná metadata grafu
a editory souvisejících skupin se stále načítají pro rozbalování a odkazy mimo
aktuální stránku. Stránkování tedy omezuje zobrazený seznam, nikoli velikost
celého grafu v HTML; jeho optimalizace není součástí tohoto přírůstku.
Staré Users URL s parametrem `letters` backend stále akceptuje, ale nová UI jej
nevytváří a Apply/Reset ho odstraní. Staré cookie filtry se automaticky neobnovují.

### Výsledek fáze 1

- Kompilace všech Askama šablon: `cargo check -p simple-idm-server --offline`.
- 5 jednotkových testů admin formulářů prošlo.
- Browser kontrola Users, Groups, Clients, Memberships, Claims a Identity providers
  prošla v Chrome ve světlém i tmavém motivu: create/edit/detail modaly, kompaktní řádky, dostupné More menu,
  graf a archivované vazby, claim reference, Groups filtr v URL/reload, taby v URL/reload
  a horizontální zarovnání filtru. Fiktivní účty; bez produkčních mutací.
- Verze sjednocena pomocí `just release-version 0.16.0`.
- Hromadné operace, backendové rozšířené filtry a auditní přestavba NEJSOU hotové;
  patří do navazujících fází výše.


## Ověřený přírůstek fáze 2 — 0.16.1

- Users: Archive selected a Add selected to group, Groups: Archive selected.
  Výběr označuje jen viditelné řádky, nejvýše 100 UUID. Žádný implicitní výběr
  dalších stránek. Změna Groups filtru odznačí skryté řádky.
- Potvrzení obsahuje počet, názvy a dopad. Výsledek dávky má souhrn, jednotlivé
  objekty, důvody přeskočení/chyb a batch ID. Opakované přiřazení je no-op.
- Před každým objektem se kontroluje aktuální admin oprávnění; cílový objekt
  a skupina se kontrolují v transakci a v default tenant scope. Změna a její
  audit commitují společně. Neúspěšné pokusy se auditují zvlášť; při výpadku DB
  se jejich batch ID objeví také v logu. Root token nemá vymyšlený user subject;
  událost výslovně nese actor_kind=root_token, bez obsahu tokenu.
- Users filtry: autentizační metoda, lokální TOTP stav, aktivní passkeys,
  přímo přiřazená skupina, poznámka. Filtr skupiny výslovně nezahrnuje dědičnost.
  Řazení username / surname / latest sign-in má stabilní UUID tie-breaker.
  Filtry jsou součástí URL i odkazů stránkování a návratu z akcí.
- Ověřeno: existujících 5 form parsing testů, validace výběru, PostgreSQL test
  archivace/přiřazení/tenant scope/skipped výsledků/audit aktéra/rollbacku při
  selhání auditu, zachování group_groups a user_groups a zánik grantů po
  archivaci balíčku. Skutečný Users handler nad PostgreSQL ověřuje kombinace
  filtrů, celkové počty, stránkování, řazení a odmítnutí akce bez přihlášení.
- Browser: původní regresní scénář + verify-admin-bulk.js (výběr, potvrzení,
  obsah POST formuláře, odznačení skrytých řádků). Fixture POST se zachytává
  jen v prohlížeči; serverové mutace ověřují samostatné DB testy.
- Clippy není instalovaný pro projektový toolchain 1.99.0; nebyl spuštěn.

Pro DB testy použít izolovaný docker-compose.test.yml a jeho dynamický port;
nikdy produkční DB. Například s adresou získanou přes docker compose port:

```sh
ADMIN_UI_TEST_DATABASE_URL=postgres://postgres:local-test-only@127.0.0.1:PORT/simple_idm_test \
  cargo test -p simple-idm-server web_admin::bulk::tests -- --include-ignored
ADMIN_UI_TEST_DATABASE_URL=postgres://postgres:local-test-only@127.0.0.1:PORT/simple_idm_test \
  cargo test -p simple-idm-server user_filters_share -- --ignored
```

Zbývající otevřené body fáze 2 a celá fáze 3 nejsou součástí tohoto přírůstku.


## Ověřený přírůstek fáze 2 — 0.16.2

- Groups: SQL filtr name/description + typ + Current/Archived, stránky po 25.
  Archiv se filtruje a stránkuje celý, bez původního omezení na posledních 25
  záznamů. Detaily a editory ostatních aktivních uzlů zůstávají dostupné pro
  graf; odkaz z Memberships na skrytý uzel otevře jeho editor.
- Clients: SQL Search + Public/Confidential + Active/Inactive/Archived + claim
  maps Enabled/Disabled, stránky po 25. Archiv není omezen na posledních 50.
- Počty a seznam používají stejné predikáty. Stabilní řazení lower(name), UUID;
  požadavek mimo poslední stránku se stáhne na existující stránku. Search je
  case insensitive, po slovech; znakům %, _ a backslash nepřisuzuje SQL wildcard
  význam. Sdílená šablona paginace, URL zachovává filtry a stránku i po akcích.
- Memberships pickery: Users auth/status, Groups regular/virtual, živé hledání,
  počty shod a Reset. Claims pickery: s pravidly / bez pravidel, počty a Reset.
  Každý tab má samostatný URL stav. Výběr a jeho detail se zachovají, a pokud
  vybraný objekt nesplňuje filtr, UI to výslovně označí.
- Aktivní tab se ukládá do view i při vstupu přes hash odkaz; návraty po
  mutations/validation zachovávají view, výběr a příslušné picker filtry.
- Ověřeno: 10 serverových testů včetně PostgreSQL (28 aktuálních + 28
  archivovaných Groups/Clients, kombinace filtrů, celý archiv, stabilní počet,
  poslední stránka, metadata/off-page editory, literal search a návratový URL).
  Browser: původní scénář, verify-admin-bulk.js a verify-admin-filters.js;
  archiv, odkazy na skryté uzly, Reset, picker filtry, URL/reload a tmavý motiv.
- Zůstává otevřen výběr všech filtrovaných výsledků, doplnění UUID/aktivních
  filtrů v dalších detailech, inline validace formulářů a celá fáze 3.


## Dokončení fáze 2 — 0.16.3

- Feedback z nasazení: Memberships seznamy Users/Groups mají přirozenou výšku
  podle obsahu. Odstraněna cap 300 px, vnitřní scrollbar i minimální výška gridu;
  poslední položky jsou dostupné běžným posouváním stránky.
- Select all filtered je oddělen od checkboxu stránky. Server použije stejné
  filtry jako seznam, vrátí úplný výběr nejvýše 100 objektů a odmítne větší
  rozsah. UI ukazuje rozsah, lze odznačit jednotlivé položky nebo celý výběr.
  Potvrzení obsahuje i objekty z jiných stránek. POST odesílá konkrétní UUID;
  server nepřebírá obecný příkaz k mutaci všech aktuálních shod.
- Create/edit a vazbové dialogy s vlastním modal-body zobrazí serverovou chybu
  uvnitř otevřeného dialogu a zachovají hodnoty. Pokud zpráva jmenuje pole,
  přidají jeho invalid feedback a aria vazbu; ostatní chyby zůstanou v souhrnu.
  Úspěch vede na serverový návratový URL. Technické samostatné pattern formy
  bez modal-body používají původní běžný POST.
- Zachováno potvrzení změny group type; po jeho neúspěchu se editor znovu otevře.
  Claim hodnoty nadále používají existující CSV transport. Prázdná single
  hodnota má kontextovou validaci u vstupu místo samostatného browser alertu.
- Copy UUID doplněno v Memberships, Claims, editorech providerů, tenantu a domén.
  Pokud clipboard není dostupný, tlačítko zobrazí hodnotu k ručnímu zkopírování.
  Filtry mají viditelné hodnoty a počty shod / celkového rozsahu.
- Ověřeno: 11 serverových testů včetně PostgreSQL (úplný výběr 27/28 výsledků
  napříč stránkami, 100 povoleno / 101 odmítnuto, původní filtry/dávky/audit).
  Browser scénáře zahrnují dlouhé seznamy, poslední položky, clipboard,
  error/retry/success, HTTP chybu, claim CSV a povinnou hodnotu, potvrzení group
  typu, odznačení off-page výběru a chybu při načtení výběru.

Fáze 3 (Audit, exporty, souhrny a dashboard) zůstává neimplementovaná.
