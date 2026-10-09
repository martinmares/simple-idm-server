# Skupiny a virtuální balíčky — kontrakt a plán změn

Datum: 2026-10-09

Stav: **Implementováno a ověřeno; finální release verze 0.13.8. Nenasazeno agentem.**

Tento dokument je předání dalšímu agentovi. Průběžně aktualizovat checklist,
výsledky ověření a zbývající rozhodnutí. Samotný vznik dokumentu neznamená,
že popsané chování již existuje v aplikaci.

## 1. Cíl a závazná dohoda

Zachovat skládání oprávnění pomocí vnořených a sdílených virtuálních skupin,
vrátit přehledné vizuální vazby do Admin UI a jednoznačně definovat oba typy.

**Virtuální skupina je interní skupina IDM. Její vlastní název se nikdy
neexportuje do tokenového `groups`, ale může obsahovat další skupiny a může
sloužit jako podmínka claim mappingu.**

Fyzická skupina (v anglickém UI `regular group`) je koncový bod: nemůže
obsahovat žádné další skupiny. Její jméno může být exportováno do `groups`
podle konfigurace klienta. Oba typy mohou být přiřazeny uživateli přímo.

| Vlastnost | Fyzická skupina | Virtuální skupina |
| --- | --- | --- |
| Přímé přiřazení uživateli | Ano | Ano |
| Obsahuje další skupiny | Ne | Ano, oba typy |
| Může být členem více virtuálních skupin | Ano | Ano |
| Zdroj claim mappingu podle UUID i názvu/vzoru | Ano | Ano |
| Vlastní název v tokenovém `groups` | Podle klienta | Nikdy |
| Členství se propaguje k potomkům | Nemá potomky | Ano, tranzitivně |
| Členství se propaguje k rodičům | Nikdy | Nikdy |

Příklad:

```text
admin:all [virtual]
├── admin:monitoring [virtual]
│   ├── grafana-admins [physical]
│   └── prometheus-admins [physical]
└── admin:development [virtual]
    ├── gitlab-admins [physical]
    └── registry-admins [physical]
```

- Člen `admin:all` získává členství ve všech uvedených potomcích.
- Přidání potomka do `admin:monitoring` se projeví i u členů `admin:all`.
- Člen samotné `grafana-admins` nezískává členství v `admin:monitoring`.
- Ani přímé členství ve všech potomcích nezakládá členství v rodiči.
- Sdílený potomek je jedna skupina s jedním UUID, nikoli kopie.
- Odebrání jedné cesty nezruší členství získané jinou cestou nebo přímo.
- Zakázat cykly včetně sebeodkazu, i při souběžných zápisech.
- Vazby jsou pouze v rámci stejného tenantu.
- Prázdný virtuální balíček je povolen. Pokud má claim mapping, může stále
  udělovat claim; prázdný obsah tedy neznamená absenci všech oprávnění.
- `admin:all` je obyčejné jméno, nikoli automatické pravidlo pro všechny skupiny.

**Zamítnuté starší návrhy:** zákaz vnořených virtuálních skupin, zploštění
všech balíčků a zákaz claim mappingu z virtuálních skupin. Neimplementovat je.

## 2. Claim mapping a publikace skupin jsou různé operace

Příklad mapování pro konkrétního OAuth klienta:

```text
admin:monitoring -> role=monitoring-admin
```

Člen `admin:all` nebo přímo `admin:monitoring` toto mapování splní.
Člen pouze `grafana-admins` jej nesplní. Výsledný token může obsahovat:

```json
{
  "groups": ["grafana-admins", "prometheus-admins"],
  "role": "monitoring-admin"
}
```

Ukázka předpokládá odpovídající výběr skupin pro daného klienta.
Virtuální skupina není skryta před claim mappingem; skryta je pouze její
vlastní položka v `groups`. Explicitní custom claim z ní je záměrná vlastnost.

Implementace musí rozlišovat:

1. Přímá přiřazení uživatele (oba typy).
2. Efektivní interní členství (oba typy, tranzitivní rozbalení, deduplikace).
3. Publikované `groups` (pouze fyzické, dle režimu a filtrů klienta).
4. Vyhodnocení client-specific claim map nad příslušným interním členstvím.

Nevyřazovat virtuální skupiny ze společného interního resolveru. Jinak by se
rozbilo dědění, mapování i evidence zdroje oprávnění. Publikované názvy
nepoužívat automaticky jako jediný vstup pro pattern-based claim mapping.

Zachovat `include_claim_maps` a možnost klienta dostávat vlastní claims bez
seznamu `groups`. Odstranit volbu `ignore_virtual_groups` jako uživatelskou
volbu; vynechání virtuálních názvů se stává invariantem.

## 3. Výchozí stav repozitáře

Při sepsání: workspace verze **0.13.4**, existují necommitnuté změny účtového
přihlašování/MFA a sdílených skupin. Nepřepsat je, nevracet je zpět.
Před zahájením znovu ověřit `git status` a aktuální verzi.

Již existuje:

- [x] Datový model vazeb parent/child a tranzitivní rozbalení skupin.
- [x] Sdílení potomka více rodiči: migrace `051_share_group_memberships.sql`
  odstraňuje unikátnost samotného child ID; unikátní dvojice zůstává.
- [x] Společné zápisy `db/groups.rs` pro UI/API, kontrola cyklů a tenantů,
  transakční serializace změn grafu.
- [x] Editace členů balíčku bez odstranění vazeb ostatních balíčků.
- [x] Claim mapping podle UUID a podle vzorů názvů.

Zatím není hotovo:

- [x] Fyzická skupina jako povinný koncový bod ve všech zápisových cestách.
- [x] Bezpodmínečné vynechání virtuálních jmen v tokenovém `groups`.
- [x] Konzistentní vstupy UUID/názvů pro claim mapping virtuálních skupin.
- [x] Stromové zobrazení sdílených a vnořených balíčků.
- [x] Kontrola kompatibility existujících dat a klientských nastavení.

Důležitá současná nejednotnost: OAuth vydání tokenu předává claim mappingu
efektivní UUID, ale pro pattern matching názvy již ovlivněné režimem `groups`,
volbou vynechání virtual a klientskými filtry. Nestačí pouze zapnout stávající
`ignore_virtual_groups` všem klientům: virtual pattern mapping by mohl přestat
fungovat, zatímco UUID mapping by fungoval dál.

## 4. Postup a checklist

### Fáze A — audit kompatibility a doplnění technických rozhodnutí

- [x] Projít všechny vydávací cesty: authorization code, refresh, device flow,
  případně další uživatelem podložené tokeny a UserInfo. Ověřit i interní
  administrátorskou autorizaci, importy a automatické přiřazování skupin.
- [x] Najít fyzické skupiny, které mají potomky; vytvořit čitelný report
  obsahující UUID, tenant, vazby a relevantní claim mapy.
- [x] Najít klienty spoléhající na export virtuálních jmen; externí pravidla
  aplikací nelze kompletně zjistit jen z databáze IDM. Popsat migrační dopad.
- [x] Vyjasnit a zdokumentovat vztah klientských include/exclude filtrů
  k claim mappingu. Nyní se liší dopad na UUID a pattern match. Neměnit tuto
  sémantiku potichu: nejprve příklady před/po, pak explicitní rozhodnutí.
- [x] Zachovat režimy `effective`, `direct`, `none`, pokud audit neprokáže
  nutnost změny. `direct` automaticky nepřepínat na `effective`.
  Režim publikace `groups` nesmí sám znemožnit virtual claim mapping.
- [x] Navrhnout kompatibilitu starého pole `ignore_virtual_groups` pro API/CLI
  a importy: odstranit UI volbu, neslibovat účinnost hodnoty false. Přechodné
  přijetí s upozorněním nebo validační chyba musí být výslovně dokumentována.

**Zábrana migrace:** žádné tiché mazání vazeb nebo automatické převádění
fyzické skupiny na virtuální. Změnilo by to tokeny a případně oprávnění.
Historická nekompatibilní data potřebují konkrétní plán převodu a kontrolu
výsledných skupin a claims. Nezakazovat pouhé čtení nebo opravu takových dat
bez promyšlené migrační cesty.

### Fáze B — pravidla modelu a zápisy

- [x] Využít stávající `is_virtual` a tabulku vazeb; nezavádět druhý model.
- [x] Ve společné logice povolit jako rodiče pouze virtuální skupinu.
- [x] Zachovat libovolné vnoření virtuálních skupin a sdílení potomků.
- [x] Zachovat kontrolu sebeodkazu, cyklů, tenantů a archivovaných záznamů.
- [x] Ošetřit změnu typu skupiny ve všech API/UI cestách, souběžně s editací
  vazeb. Virtual s potomky nelze změnit na physical. I změna typu listu mění
  publikaci v `groups`; musí být zřetelná, nikoli nenápadný checkbox.
- [x] Prověřit archivaci/obnovu: neudělovat oprávnění přes archivovaný uzel;
  explicitně stanovit a otestovat chování vazeb při obnově.
- [x] Aktualizovat CLI/API validační hlášky. Není dovoleno obejít pravidla
  přímým API voláním namísto UI.

### Fáze C — tokeny a claim mapping

- [x] Interní efektivní množina nadále obsahuje oba typy skupin.
- [x] Tokenový `groups` nikdy neobsahuje vlastní názvy virtual skupin.
- [x] UUID i pattern mapping mohou použít virtuální skupinu získanou přímo
  nebo tranzitivně. Zachovat client-specific mapy a ochranu rezervovaných claims.
- [x] Použít konzistentní pravidla ve všech vydávacích cestách; neduplikovat
  novou obchodní logiku mezi auth-code, refresh a device flow.
- [x] Ověřit, že klient s `groups=none` může stále dostat vlastní claim.
- [x] Porovnat výstupy před/po pro reprezentativní uživatele a klienty,
  včetně filtrů a přímých přiřazení. Popsat úmyslné změny.

Poznámka k auditování: více map pro stejný scalar claim dnes vybírá první
hodnotu, přičemž samotné `ORDER BY claim_name` neurčuje pořadí shodného jména.
Zaznamenat případné konflikty; nevymýšlet v této změně nový systém priorit
bez samostatné dohody. Pole claims mají stávající deduplikaci.

### Fáze D — Admin UI

- [x] Přehled virtuálních skupin s rozbalovacím stromem potomků.
- [x] Sdílený uzel zobrazit pod více rodiči jako odkaz na stejné UUID.
  Technicky jde o acyklický graf, vizuálně může být prezentován jako strom.
- [x] Zachovat přístup ke všem skupinám včetně nepřiřazených a fyzických listů;
  například samostatným plochým přehledem fyzických skupin.
- [x] U virtuální skupiny umožnit výběr obou typů členů, vyhledávání a bezpečné
  odebrání jedné vazby. Editace sdíleného balíčku ovlivní všechna jeho použití.
- [x] U fyzických skupin odstranit editaci potomků a prázdné `Members (0)`.
- [x] Zobrazit `Included in` a relevantní claim mapy včetně OAuth klienta.
  Rozlišovat přímo navázané mapy od map použitelných přes vzory.
- [x] Jasně odlišit „odebrat z balíčku“ od „smazat skupinu“.
- [x] V uživatelském pohledu rozlišit přímé a zděděné členství a umožnit zjistit
  zdroj oprávnění. Nezaměnit vizuální cestu za jediné vlastnictví skupiny.
- [x] Odstranit klientský checkbox pro export virtual skupin a vysvětlit
  invariant krátkou nápovědou. Claim mapping z virtual zůstává dostupný.

### Fáze E — ověření, dokumentace a předání

- [x] Unit/integrační testy níže a relevantní stávající testy prošly.
- [x] Prohlížečem ověřeno sdílení, rozbalování, editace a validační chyby.
- [x] README, API/CLI nápověda a migrační poznámky odpovídají implementaci.
- [x] Zvednout workspace verzi přes `just release-version <nova-verze>` podle
  skutečného aktuálního stavu; zde nenastavovat samostatné verze jednotlivých crates.
- [x] Aktualizovat tento dokument: co je hotovo, příkazy/výsledky testů,
  zbývající omezení a kroky nasazení. Commit/push provést až na pokyn uživatele.

## 5. Povinné scénáře ověření

1. `admin:all -> admin:monitoring -> grafana-admins`: obě virtual skupiny
   účinné interně, pouze physical v `groups`; mapy obou virtual mohou fungovat.
2. Přidání nového potomka monitoring se projeví členovi all při novém vydání
   tokenu. Již vydané JWT se samy nepřepisují; neslibovat okamžitou revokaci.
3. Člen pouze grafana nezíská členství ani claim monitoring/all.
4. Dva rodiče sdílí stejnou skupinu; odebrání jedné vazby neodstraní druhou.
5. Dvě cesty ke stejnému listu nevytvoří duplicity; přímé členství přežije
   odebrání zděděné cesty.
6. Physical parent je odmítnut přes UI i API. Virtual child pod virtual je povolen.
7. Sebeodkaz, vícekrokový cyklus a souběžné protichůdné hrany jsou odmítnuty.
8. Cross-tenant/archivované skupiny neumožní získat přístup.
9. Virtual claim mapping podle UUID i vzoru funguje bez exportu virtual názvu.
10. Prázdný virtual s mapou nadále uděluje daný claim svému členovi.
11. `effective`, `direct`, `none`, filtry klienta a `include_claim_maps` mají
    dokumentované výsledky v auth-code, refresh i device flow.
12. Změna typu a editace vazeb nemohou souběhem vytvořit physical rodiče.
13. Migrační report zachytí staré physical rodiče a klienty exportující virtual;
    nedojde k neohlášenému mazání nebo rozšíření oprávnění.

## 6. Orientace v kódu a ověřovací příkazy

- `crates/simple-idm-core/src/db/groups.rs` — společné zápisy a integrační test.
- `crates/simple-idm-core/src/auth/claims.rs` — rozbalení a claim mapping.
- `crates/simple-idm-core/src/admin/handlers.rs` — API skupin, klientů a map.
- `crates/simple-idm-core/src/oauth2/authorization_code.rs` — auth-code/refresh.
- `crates/simple-idm-core/src/oauth2/` — dohledat device flow a ostatní cesty.
- `crates/simple-idm-core/src/client_group_filters.rs`, `claim_map_patterns.rs`,
  `group_patterns.rs` — filtry a automatická přiřazení, nezaměňovat jejich účely.
- `crates/simple-idm-server/src/web_admin.rs` a `templates/admin/groups.html`
  — pohledy skupin; dohledat také klientské formuláře a claim mapy.
- `migrations/051_share_group_memberships.sql` — zachovat více rodičů.

Základní ověření (DB testy pouze nad disposable databází):

```sh
cargo fmt --all -- --check
SQLX_OFFLINE=true cargo test -p simple-idm-core --lib
SQLX_OFFLINE=true cargo test -p simple-idm-server --bin simple-idm-server
just test-postgres
just check-version
git diff --check
```

Prohlížečové ověření dělat na lokální testovací instanci, ne na produkčních datech.

## 7. Pracovní záznam

- 2026-10-09: Sepsán kontrakt a plán. Kód ani migrace tohoto návrhu nebyly změněny.
- Další agent: doplnit datum, dokončené fáze, výsledky testů a otevřené body.


### Rozhodnutí implementace 0.13.5

- Client group filters řídí pouze publikované `groups`. UUID i pattern claim
  mapping používají celé efektivní interní členství. Toto je úmyslná změna:
  staré pattern mapy mohou nově udělit claim při `groups=none`, `direct` nebo
  restrictive export filtrech. Před nasazením zkontrolovat report a aplikace.
- `ignore_virtual_groups` zůstává jako deprecated kompatibilní API pole:
  false se přijme, ignoruje a loguje; API vrací true. UI checkbox je odstraněn,
  CLI přepínač skryt s deprecated nápovědou. Historické DB hodnoty zůstávají
  pro audit, nové/aktualizované klienty se ukládají s true.
- Migrace 052 nezplošťuje ani nemaže původní graf. Legacy physical parent
  zůstává čitelný a jeho dědění zachováno do explicitní opravy. UI jej označuje,
  dovolí pouze odstranit reference nebo explicitně změnit typ.
- Archivovaný uzel přeruší průchod. Reference zůstávají v DB; obnovení obnoví
  jejich účinek i claim mapping. UI obnovy na tento dopad upozorňuje.
- Typové a grafové změny jsou chráněny stejným databázovým zámkem a triggery;
  přímé SQL/API nelze použít k vytvoření nového physical parent ani cyklu.
- `scripts/group-contract-audit.sql` je read-only přednasazovací report:
  legacy rodiče/vazby/UUID/tenants/direct mapy, historické client flagy,
  pattern mapy a potenciální konflikty scalar claims. Produkční report zde
  nebyl spuštěn; agent nemá produkční data ani pravidla externích aplikací.
- Interní admin kontrola již vyžadovala fyzickou admin skupinu; pravidlo
  zůstává. Automatická přiřazení a importy mohou přiřazovat oba typy skupin.
  Client credentials nepřiřazuje uživatelské skupiny. UserInfo odráží vydaný
  token, nevypočítává nové členství pro již vydané JWT.

### Dosavadní ověření

- Core unit: 88 passed, 12 DB tests ignored; spuštěno mimo sandbox kvůli
  lokálním HTTP listenerům ve čtyřech existujících testech.
- Disposable PostgreSQL: 12 passed včetně nového kontraktového testu,
  migrace 052 úspěšná, Docker DB po testu odstraněna.
- Server unit: 5 passed.
- Workspace verze zvýšena přes `just release-version 0.13.5`.
- Prohlížeč, API a závěrečné kontroly dokončeny; podrobnosti níže.


### Prohlížeč a API — průběžné výsledky

- Rozbalení `admin:all -> admin:monitoring` ukazuje grafana/prometheus listy;
  sdílené uzly odkazují na stejný editor/UUID. Screenshot vizuálně zkontrolován.
- U `admin:selected` přidán virtual monitoring, filtrovaná volba uložena:
  dříve vybraný skrytý grafana člen zůstal zachován, ostatní balíčky se nezměnily.
- Memberships testovacího uživatele: direct all, inherited monitoring a fyzické
  listy, zdroj all, bez duplicit. U fyzických skupin nejsou prázdné Members akce.
- UI ukazuje direct UUID a pattern mapy s klientem; legacy client flag se ukazuje
  jen jako migrační upozornění, nikoli konfigurovatelná volba.
- HTTP API: physical parent -> 409 physical_parent; virtual s potomky na
  physical -> 409 invalid_group_type; deprecated client false -> 200 a true.
- Read-only audit SQL spuštěno nad dočasnou DB; všechny čtyři výstupy fungují.
- Doplněna oprava unavailable/archived member references: počet viditelný v UI,
  Members editor je dostupný i legacy rodiči s jen archivovanými potomky;
  ukládání výslovně upozorní na odstranění nedostupných referencí.


### Dokončení 2026-10-09

- Implementace a všechny fáze dokončeny. 88 core + 12 PostgreSQL + 5 server
  testů prošlo (105 celkem). Finální server i CLI binárky sestaveny ve verzi 0.13.5.
- `cargo fmt --all -- --check`, `git diff --check`, `just check-version` prošly.
- Prohlížeč ověřil potvrzení změny typu a její odmítnutí; finální UI vrací
  konkrétní validační text bez databázového prefixu/technických detailů.
- Finální HTTP kontrola se správnou Origin hlavičkou ověřila repair editor
  physical rodiče s jen archivovaným potomkem a odstranění reference při save.
- Testovací prohlížeč a server ukončeny, disposable databáze odstraněna.
  Produkční data nebyla čtena ani upravena. Žádný commit/push nebyl proveden.

### Před nasazením (pro správce prostředí)

1. Spustit `scripts/group-contract-audit.sql` nad cílovou DB a uložit výstup.
2. Ověřit externí aplikace, které používaly virtual jména v `groups`, a pattern
   mapy dosud závislé na export filtrech nebo režimu `direct`/`none`.
3. Zálohovat DB běžným postupem prostředí a nasadit binárku 0.13.5;
   server použije standardní migrace 051/052. Historické vazby nejsou mazány.
4. Legacy regular rodiče opravit jednotlivě podle reportu/UI. Neměnit jejich
   typ automaticky; virtual typ přestane publikovat vlastní název v `groups`.
5. Počítat s tím, že staré JWT mají původní claims do expirace; nové přihlášení
   a refresh používají nový kontrakt.

Nezbývají implementační kroky v rozsahu tohoto plánu. Kontrola konkrétních
produkčních konfigurací a vlastní nasazení patří správci prostředí.


### UX úprava 0.13.6 — archivovaní členové

- Neutrální informační blok uvádí jména archivovaných členů místo oranžového počtu.
- Members je zobrazuje jako zaškrtnuté archivované volby; běžné uložení zachová
  reference. Odebrání vyžaduje explicitní odškrtnutí. Předchozí automatické
  odstranění při save (popis 0.13.5 výše) je tímto nahrazeno.
- Backend dovoluje zachovat pouze již existující archivovanou vazbu stejného
  tenantu; novou vazbu na archivovanou skupinu stále odmítá.
- Integrační test doplněn o zachování, explicitní odebrání a zákaz nové vazby.

- Ověření 0.13.6: server sestaven, 12 PostgreSQL integračních testů prošlo,
  fmt/diff/version kontroly prošly. Dočasná DB odstraněna.


### UX úprava 0.13.7 — členství uživatele

- Efektivní členství je seskupené podle přímých přiřazení. Zděděné skupiny
  jsou pod svým zdrojem odsazené a menším písmem, zdroj je zvýrazněný.
- Více přímých zdrojů sdílené skupiny je vidět pod každým přiřazením;
  také přímé členství zděděného uzlu je označeno „also direct“.
- Jde o seskupení podle přímého zdroje, nikoli o tvrzení, že každý potomek
  má v databázi přímo tohoto rodiče. Vnořené vazby zůstávají na Groups stránce.

- Ověření 0.13.7: server i Askama šablona úspěšně sestaveny; fmt, diff a
  workspace version kontroly prošly. Autorizační logika se v této UX úpravě nemění.


### UX úprava 0.13.8 — kompaktní přehled členství

- Tabulku efektivního členství nahrazuje kompaktní seznam ve stejném stylu
  jako Groups: zvýrazněný zdroj, odsazené menší položky, souvislá levá linka
  a badge typu skupiny. Opakované sloupce Inherited/Granted through odstraněny.
- Seskupení podle přímých zdrojů a informace o také přímém přiřazení zachovány.

- Ověření 0.13.8: server/Askama šablona sestaveny, fmt/diff/version kontroly prošly.


### Předání k vydání 0.13.8

Na pokyn uživatele se celý dokončený pracovní stav ukládá do Gitu: kontrakt
skupin, sdílení, claim mapping, kompaktní Admin UI, archivované vazby a dříve
dokončené účtové přihlášení/MFA onboarding. Verze byla připravena standardním
`just release-version 0.13.8`; závěrečné diff/version kontroly prošly.
Push ani produkční nasazení nejsou součástí tohoto kroku.
