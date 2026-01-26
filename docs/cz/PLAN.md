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

### Priorita 1 - Database & Backend ✅ HOTOVO

#### 1.1 Database migrace
- ✅ Vytvořit migraci pro `user_group_patterns` tabulku (022_add_user_group_patterns.sql)
  - Sloupce: `id`, `user_id`, `pattern`, `is_include`, `priority`, `created_at`
  - Foreign key na `users(id)` s ON DELETE CASCADE
  - Indexy na `user_id` a `priority DESC`

#### 1.2 Datový model
- ✅ Přidat `UserGroupPattern` struct do db/models.rs
- ✅ Implementováno s sqlx (PostgreSQL)

#### 1.3 Pattern matching logika
- ✅ Implementováno v src/group_patterns.rs
- ✅ Funkce `pattern_matches()` s podporou wildcards
- ✅ Evaluace s prioritami (nejvyšší priorita vyhrává)
- ✅ Include/exclude logika

#### 1.4 Background job
- ✅ Implementován `evaluate_and_sync_patterns()` v src/group_patterns.rs
- ✅ Synchronizace `user_groups` tabulky
- ✅ Scheduler v main.rs s konfigurovatelným intervalem
- ✅ Config: `GROUP_PATTERNS_SYNC_INTERVAL_SECONDS` (default 300s)

#### 1.5 API endpointy
- ✅ `POST /admin/users/:id/group-patterns` - vytvoření patternu
- ✅ `GET /admin/users/:id/group-patterns` - seznam patterns
- ✅ `PUT /admin/users/:user_id/group-patterns/:pattern_id` - úprava
- ✅ `DELETE /admin/users/:user_id/group-patterns/:pattern_id` - smazání

### Priorita 2 - TUI Vylepšení ✅ HOTOVO

#### 2.1 Array editor pro redirect_uris
- ✅ Vytvořen `ArrayEditorState` a rendering funkce
- ✅ Klávesová zkratka Ctrl+U v Create/Update client formuláři
- ✅ `redirect_uris` pole je read-only s hintem "(Ctrl+U edit)"
- ✅ Dialog podporuje: a-add, d-delete, e-edit, ↑↓-navigate

#### 2.2 Scope selector dialog
- ✅ Vytvořen `ScopeSelectorState` s režimy SelectStandard/AddCustom
- ✅ Standardní scopes: `openid`, `profile`, `email`, `offline_access`
- ✅ Možnost přidat custom scope (klávesa 'a')
- ✅ Klávesová zkratka Ctrl+O v Create/Update client formuláři
- ✅ `scope` pole je read-only s hintem "(Ctrl+O edit)"

#### 2.3 Úprava formulářů
- ✅ Create client formulář - `redirect_uris` a `scope` jsou read-only
- ✅ Update client formulář - `redirect_uris` a `scope` jsou read-only
- ✅ Přidány nápovědy k novým zkratkám v UI

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

- **Implementace dokončena 2026-01-26**
- **TIMEZONE fix v c2b42c9** - hotovo, nesahat
- Použité technologie: sqlx + PostgreSQL, actix-web, ratatui
- Token usage: ~86K/200K (57% zbývá)

## 🎉 Shrnutí implementace

### Backend (Group Patterns)
- ✅ Kompletní CRUD API endpointy
- ✅ Pattern matching s wildcards (`ssh:*`, `*:admin`, `ssh:*:admin`)
- ✅ Priority system (vyšší číslo = vyšší priorita)
- ✅ Background job synchronizace každých 5 minut (konfigurovatelné)
- ✅ Migrace 022 aplikována v databázi

### Frontend (TUI)
- ✅ Array editor pro redirect_uris (Ctrl+U)
- ✅ Scope selector s předvyplněnými scopes (Ctrl+O)
- ✅ Read-only zobrazení s hinty v formulářích
- ✅ Plně funkční dialogy s navigací

### Co zbývá (Priorita 3)
- Unit testy pro pattern matching
- Integration testy pro API a background job
- Aktualizace README s příklady použití
