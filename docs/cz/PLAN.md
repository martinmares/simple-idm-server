# 2026-01-25

## 📋 Přehled návrhů a dohod

### 1. Group Patterns - Automatické přiřazení
- ✅ Nová tabulka `user_group_patterns` s patterny jako `ssh:*`
- ✅ Podpora `is_include` (grant/deny) a `priority`
- ✅ Background job pro evaluaci patterns
- ✅ Zachovává free-form String pro group IDs

### 2. TUI - redirect_uris editor
- ✅ Ctrl+U otevře dialog pro editaci pole (array editor)
- ✅ Hlavní formulář zobrazí read-only čárkami oddělený seznam

### 3. TUI - scope editor
- ✅ Ctrl+O otevře dialog s předvyplněnými scopes
- ✅ Možnost přidat custom scope
- ✅ Hlavní formulář zobrazí read-only výsledek

## 🎯 Plán implementace

### Priorita 1 - Database & Backend

#### 1.1 Database migrace
- [ ] Vytvořit migraci pro `user_group_patterns` tabulku
  - Sloupce: `id`, `user_id`, `pattern`, `is_include`, `priority`, `created_at`
  - Foreign key na `users(id)` s ON DELETE CASCADE

#### 1.2 Datový model
- [ ] Přidat `user_group_patterns` do diesel schema
- [ ] Vytvořit struct `UserGroupPattern` v models
- [ ] Implementovat CRUD operace v repository vrstvě

#### 1.3 Pattern matching logika
- [ ] Implementovat funkci pro matching patternu (`ssh:*` matches `ssh:role:admin`)
- [ ] Implementovat evaluaci s prioritami (nejvyšší priorita vyhrává)
- [ ] Rozlišit include/exclude logiku

#### 1.4 Background job
- [ ] Implementovat job pro evaluaci všech patterns
- [ ] Synchronizace `user_groups` tabulky podle výsledků evaluace
- [ ] Naplánovat pravidelné spouštění (cron/scheduler)

#### 1.5 API endpointy
- [ ] `POST /api/users/:id/group-patterns` - vytvoření patternu
- [ ] `GET /api/users/:id/group-patterns` - seznam patterns uživatele
- [ ] `PUT /api/users/:id/group-patterns/:pattern_id` - úprava patternu
- [ ] `DELETE /api/users/:id/group-patterns/:pattern_id` - smazání patternu

### Priorita 2 - TUI Vylepšení

#### 2.1 Array editor pro redirect_uris
- [ ] Vytvořit nový dialog komponentu pro editaci array hodnot
- [ ] Přidat klávesovou zkratku Ctrl+U v Create/Update client formuláři
- [ ] Zobrazit `redirect_uris` jako read-only čárkami oddělený seznam
- [ ] Umožnit přidání/odebrání/úpravu jednotlivých URI v dialogu

#### 2.2 Scope selector dialog
- [ ] Vytvořit dialog s předvyplněnými standardními scopes
  - `openid`, `profile`, `email`, `offline_access`
- [ ] Přidat možnost zadat custom scope
- [ ] Přidat klávesovou zkratku Ctrl+O v Create/Update client formuláři
- [ ] Zobrazit `scope` jako read-only seznam v hlavním formuláři

#### 2.3 Úprava formulářů
- [ ] Upravit Create client formulář (read-only pro `redirect_uris` a `scope`)
- [ ] Upravit Update client formulář (read-only pro `redirect_uris` a `scope`)
- [ ] Přidat nápovědu k novým klávesovým zkratkám

### Priorita 3 - Testing & Dokumentace

#### 3.1 Unit testy
- [ ] Testy pro pattern matching logiku
- [ ] Testy pro prioritizaci a include/exclude
- [ ] Testy pro CRUD operace na `user_group_patterns`

#### 3.2 Integration testy
- [ ] Test background job evaluace
- [ ] Test API endpointů pro pattern management
- [ ] Test TUI dialogů (pokud možné)

#### 3.3 Dokumentace
- [ ] Aktualizovat README s novými features
- [ ] Přidat příklady použití group patterns
- [ ] Dokumentovat nové klávesové zkratky v TUI

## 📝 Poznámky

- **4% týdenního limitu zbývá** - implementace po malých krocích nebo čekat na reset
- **TIMEZONE fix v c2b42c9** - hotovo, nesahat
- Zachovat konzistenci s existujícím kódem (diesel, actix-web, ratatui)
