# 2026-01-25

## Group id (role, team)

Dnes používáme název groupy následujícím způsobem:
 - ssh:principal:alice
 - ssh:principal:bob
 - ssh:role:devops
 - ssh:role:root
 - ssh:role:admin
 - simple-idm:role:admin
 - simple-idm:role:reader
 - grafana:role:admin
 - grafana:role:editor
 - grafana:role:viewer
 - team:backend
 - team:frontend
 - gitlab:role:developer
 - gitlab:role:maintainer
 - gitlab:ns:o2
 - gitlab:ns:cetin
 - gitlab:ns:datalite

Takže máme několik významů, uvedu příklady:
 - člen nějakého teamu -> `group_name=team:frontend`
 - Aplikační role pro Grafana -> `group_name=grafana:role:admin`
 - Skupina (namespace) v GitLab -> `group_name=gitlab:ns:o2` + `group_name=gitlab:role:developer`
 - Účet pro SSH login -> `group_name=ssh:principal:alice`
 - Obecná role "root" pro SSH -> `group_name=ssh:role:root`

No a v DB to evidujeme čistě jako `String` protože to ani nijak nejde, pokud chci zachovat následující možnosti:
 - <app_name>:role:admin
 - <app_name>:ns:admin
 - <app_name>:<type>:admin

Tohle bych asi neměnil, to dává logiku a asi to nelze přesně normalizovat.

Ale v případě, že jsme se již vydali touto cestou, pak bych potřeboval zavést do simple-idm-server následuící logické související věci (návaznosti):

1. Dnes je v tabulce `user_groups` jen tato vazba:
   - user_id
   - group_id

A já bych chtěl vytvořit tuhle novinku:
 - přiřadit uživatele do skupiny "ssh:*"
 - tedy jakákoliv budoucí group, která vznikne s prefixem "ssh:" se automaticky přiřadí danému uživateli
 - nevím jak tuto změnu udělat beze změny datového modelu, a nevím jestli to beze změny modelu vůbec má význam, jeké navrhuješ řešení pro tuto novinku?

A ještě navazující otázky, které z toho logicky plynou:
 - Nebylo by vhodné někde striktně vyžadovat nejprve vytvoření toho prefixu "ssh:" v nové tabulce?
 - Ale pak by to znamenalo další restrikce na straně vstupu:
   - museli bychome někde specifikovat možné kombinace:
     - `<app>:role:*` <-- povolená kombinace?
     - `<app>:*:*` <-- ne povolená kombinace?
     - `team:<zakaznik>:*` <-- povolená kombinace?
     - `*:<zakaznik>:*` <-- ne povolená kombinace?
     - TEDY CO JSOU POVOLENÉ/NEPOVOLENÉ KOMBINACE A KDE A JAK JE EVIDOVAT? (TROCHU SE Z TOHO STÁVÁ NOČNÍ MŮRA A NE "SIMPLE IDM PROVIDER" ŽE?)

## Clients

V TUI editoru máme ve formulářích "Create client" a "Update client" následující položku `redirect_uris` a v ní máme např. tohle `http://localhost:*/callback, http://127.0.0.1:*/callback`, tedy čistě seznam řetězců oddělených čárkou, což je velice nepříjemné!

Udělal bych to editačně podobně jako ve formuláři "Upravit claim map".
U pložky `claim_value` máme krásně možnost editovat položky v poli (v okně "Upravit claim_value").
Takže editaci toho `redirect_uris` bych udělal podobně, vyskočí nové editační okno -> tam vyplňuji položky -> potvrdím <enter> -> a v okně "Create/Update client" se zobrazí už klidně "čárkou oddělený seznam" (tam už to pole jinak zobrazit nejde).

Tedy položka `redirect_uris` není editovatelná přímo jako `String`, ale je nutné přidat nějaou další klávesovou zkratku, třeba `Ctrl+U` na kterou se otevře ten nový editační dialog pro `Array`.

Dále, opět ve formulářích "Create client" a "Update client" máme položku `scope`, tu vůbec nevalidujeme (nebo možná ano), a tím páděm uživatel si tam může napsat co chce. Preferoval bych podobně jako je u `grant_type` uživateli se po stisku klávesové zkratky (např. Ctrl+O) otevře nějaké nové okno jen s hodnotami, které může vyplnit, (podobně jako máme u `grant_types`). Tedy prostě potřebuju řídit obsah striktně jen možnosti, které dávají smysl. Tedy položka `scope` bude pro uživatele jen read-only (jen uvidí výsledek), a hodnoty může měnit jen po stisku Ctrl+O přes samostatný dialog, rozumíme si?

# 2026-01-27

Teď budeme chvilku diskutovat, mám takovou myšlenku, jak zmenšit velikost toho JWT tokenu:

1. V oauth2_clients (v TUI tab "Clients"), když založím klienta, tak ho můžu přes "patterns" specifikovat, co se může v položce "groups" poslat (dnes neexistuje pro klienty, je to jiný patterns než pro user groups!). Tedy "use case" by byl takový, že pro tohoto klienta nemá smysl posílat žádné jiné groups (ve kterých je uživatel, než jen ty, které vyhoví "patterm"). Logika vyhodnocení by byla podobná jako u user groups patternu: tedy seřadít podle priority a pak pokud je "exclude" tak vyhazuješ, když je "include", tak přidávaš (logika je identická).

2. V claim_maps (v TUI "Client claims") je dnes vazba "clent_id" + "group_id" a nabízí se tady možnost mít něco podobného jako v "user groups", tedy pattern, s úplně tou samou logikou. Někde bych specifikovat "patterns" -> třeba "ssh:*". Fungovalo by to takto:

  - dnes mám tuto "claim map":
    - claim_name = app_role
    - claim_value = Admin
    - group_id (target) = eb030dd8-a3ba-4273-abe9-f9621b849ce2
  - a mohla by vypadat takto (kdybychom tam měli patterns):
    - claim_name = app_role
    - claim_value = Admin
    - patterns:
      - priority=1, pattern=*:admin:*, is_include=true
      - priority=2, pattern=ssh:admin:*, is_include=false
      - priority=2, pattern=datalite:admin:*, is_include=true

Oba ty body bych řešil asi opět podobně jako "user groups", prostě přes schedulery. Klidně nové tabulky, ale tak, aby to neporušilo stávající koncept.

POZOR: tahle změna (2) musí být udělána šetrně, tak abychom nějak neporušily stávající datový model, a musí být v návaznosti na TUI, tak jsou dva pohledy "Client claims" a "Group claims".
