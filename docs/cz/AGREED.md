# 2026-01-25

## Group ID Pattern - Automatické přiřazení skupin

### Problém
Potřeba automaticky přiřadit uživatele do všech budoucích groups s určitým prefixem (např. `ssh:*`), včetně možnosti explicitního deny pro specifické skupiny.

### Řešení

#### Nová tabulka: user_group_patterns

```sql
CREATE TABLE user_group_patterns (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    pattern TEXT NOT NULL,              -- např. "ssh:*" nebo "team:backend:*"
    is_include BOOLEAN NOT NULL DEFAULT true,  -- true = grant, false = deny
    priority INTEGER NOT NULL DEFAULT 0,        -- vyšší číslo = vyšší priorita
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**Vztah:** 1:N s `users` tabulkou

#### Logika evaluace (background job)

1. Načti všechny existující groups z databáze
2. Pro každého uživatele, který má záznamy v `user_group_patterns`:
   - Seřaď jeho patterny podle `priority DESC` (nejvyšší priorita vyhrává)
   - Pro každou existující group:
     - Projdi patterny od nejvyšší priority k nejnižší
     - První matching pattern určí výsledek
     - Pokud `is_include=true` → vytvoř záznam v `user_groups` (pokud neexistuje)
     - Pokud `is_include=false` → smaž záznam z `user_groups` (pokud existuje)

#### Příklad use-case

**Scénář:** User má mít přístup ke všem SSH groupám kromě admin role

```
user_id=1, pattern="ssh:*",          is_include=true,  priority=10
user_id=1, pattern="ssh:role:admin", is_include=false, priority=20
```

**Výsledek:**
- User dostane: `ssh:principal:alice`, `ssh:role:devops`, `ssh:role:root`, atd.
- User NEDOSTANE: `ssh:role:admin` (explicitní deny s vyšší prioritou)

#### Výhody

- **Simple datový model** - jednoduchá tabulka, žádná business logika v IdP
- **Flexibilní** - podpora include i exclude patterns
- **Prioritizace** - řešení konfliktů pomocí priority
- **Performance** - evaluace probíhá v pozadí, ne při každém query
- **Zachovává princip** - group ID zůstávají free-form String bez strukturálních omezení

---

## Clients - UX vylepšení formulářů

### redirect_uris

**Problém:** Editace jako čárkami oddělený string je nepříjemný UX.

**Řešení:**
- Položka `redirect_uris` není editovatelná přímo jako String
- Nová klávesová zkratka (např. `Ctrl+U`) otevře dialog pro editaci pole
- Dialog podobný "Upravit claim_value" - každá URI na samostatném řádku
- Po potvrzení se v hlavním formuláři zobrazí jako čárkami oddělený seznam (read-only)

### scope

**Problém:** Uživatel může zadat cokoliv, chybí validace a nápověda.

**Řešení (kompromis):**
- Položka `scope` je read-only v hlavním formuláři
- Klávesová zkratka (např. `Ctrl+O`) otevře dialog pro výběr
- Dialog nabídne:
  - **Standardní scopes** (předvyplnené možnosti): `openid`, `profile`, `email`, `offline_access`, atd.
  - **+ možnost přidat custom scope** (pro application-specific případy)
- Podobná logika jako u `grant_types`, ale s možností custom hodnot

**Výhoda:** Uživatel má nápovědu pro běžné případy, ale zachovává se flexibilita pro specifické potřeby.
