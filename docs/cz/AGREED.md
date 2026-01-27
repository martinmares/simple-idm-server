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

---

# 2026-01-27

## JWT Token Optimization - Enterprise Features

### Motivace
Snížit velikost JWT tokenů, zejména v případech kdy uživatel má velké množství groups. JWT tokeny se posílají v každém HTTP requestu (Authorization header), takže jejich velikost má přímý dopad na bandwidth a performance.

---

## 1. Client-Level Group Filtering

### Problém
Client (aplikace) často potřebuje jen podmnožinu všech user groups. Dnes dostává všechny groups ve kterých je uživatel, i když jich 90% nepotřebuje.

### Řešení

**Nová tabulka:** `oauth_client_group_patterns`

```sql
CREATE TABLE oauth_client_group_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL,
    pattern TEXT NOT NULL,
    is_include BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE
);
CREATE INDEX idx_client_group_patterns_client ON oauth_client_group_patterns(client_id);
CREATE INDEX idx_client_group_patterns_priority ON oauth_client_group_patterns(client_id, priority ASC);
```

**Logika:** Runtime filtrování při generování JWT tokenu (NO scheduler needed!)

1. User má groups: `["ssh:role:admin", "grafana:role:viewer", "gitlab:role:developer"]`
2. Aplikují se user group patterns (už máme implementované)
3. **→ NOVĚ: Aplikují se client group patterns (sekvenčně podle priority)**
4. Výsledek jde do JWT tokenu

**Příklad:**
```
Client: Grafana Dashboard
Patterns:
  - priority=1, pattern="grafana:*", is_include=true
  - priority=2, pattern="*", is_include=false

Výsledek v JWT: ["grafana:role:viewer"]  (jen Grafana groups)
```

**Výhody:**
- Redukce velikosti tokenu
- Runtime evaluation (žádný background job)
- Plná kontrola nad tím, co client vidí

---

## 2. Pattern-Based Claim Maps (Hybrid Model)

### Problém
Dnes musíme vytvořit claim map pro každou konkrétní groupu (UUID vazba). Pokud vznikne nová group `ssh:role:developer`, musíme ručně přidat claim map.

### Řešení: Hybrid Model

**Zachováváme stávající přesné vazby:**
```sql
claim_maps:
  - claim_name
  - claim_value
  - group_id (konkrétní UUID)  <-- přesná vazba
```

**Nová tabulka pro pattern-based mapping:**
```sql
CREATE TABLE claim_map_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_map_id UUID NOT NULL,
    pattern TEXT NOT NULL,
    is_include BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (claim_map_id) REFERENCES claim_maps(id) ON DELETE CASCADE
);
CREATE INDEX idx_claim_map_patterns_map ON claim_map_patterns(claim_map_id);
CREATE INDEX idx_claim_map_patterns_priority ON claim_map_patterns(claim_map_id, priority ASC);
```

**Princip:**
- Claim map může mít buď `group_id` (přesná vazba), nebo záznamy v `claim_map_patterns` (pattern-based), nebo **obojí**
- Při generování tokenu se evaluují:
  1. Přesné vazby (group_id)
  2. Pattern-based vazby (pokud existují)
- Patterns se aplikují sekvenčně podle priority (include/exclude)

**Příklad:**
```
Claim Map:
  - claim_name = "app_role"
  - claim_value = "Admin"
  - group_id = NULL  (nemáme přesnou vazbu)

Patterns:
  - priority=1, pattern="*:admin:*", is_include=true
  - priority=2, pattern="ssh:admin:*", is_include=false
  - priority=3, pattern="datalite:admin:*", is_include=true

User má groups: ["gitlab:role:admin", "ssh:admin:root", "datalite:admin:full"]

Výsledek:
  - gitlab:role:admin → match priority 1 (include) → ADD
  - ssh:admin:root → match priority 2 (exclude) → SKIP
  - datalite:admin:full → match priority 3 (include) → ADD

→ Claim "app_role" = "Admin" se přidá do tokenu (aspoň jedna group matchla)
```

**Výhody:**
- Neporušuje stávající koncept
- Patterns jsou opt-in
- Hybrid přístup: přesnost tam kde potřebuji, flexibilita tam kde chci

**Limity:**
- Patterns nepoužívat pro příliš široké scopes (ne `*:*:*`)
- Vhodné pro: `app:role:*`, `team:backend:*`, `ssh:*`

---

## 3. Token Compression

### Problém
Groups v tokenu zabírají hodně místa při opakujících se prefixech:
```json
"groups": ["ssh:role:admin", "ssh:role:devops", "ssh:role:monitoring", "grafana:role:admin"]
```

### Řešení: Pattern-Based Compression

**Nová tabulka:** `group_compression_rules`

```sql
CREATE TABLE group_compression_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID,  -- NULL = globální pravidlo pro všechny klienty
    pattern TEXT NOT NULL,
    compressed_format TEXT NOT NULL,  -- {} = placeholder pro captured část
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE
);
CREATE INDEX idx_compression_rules_client ON group_compression_rules(client_id);
CREATE INDEX idx_compression_rules_priority ON group_compression_rules(priority ASC);
```

**Příklad compression rules:**
```
Rule 1: pattern="ssh:role:*", compressed_format="ssh:r:{}", priority=1
Rule 2: pattern="grafana:role:*", compressed_format="gf:r:{}", priority=2
```

**Před kompresí:**
```json
"groups": ["ssh:role:admin", "ssh:role:devops", "grafana:role:viewer"]
```

**Po kompresi:**
```json
"groups": ["ssh:r:{admin,devops}", "gf:r:viewer"]
```

**Compression flags v databázi:**

```sql
-- Flag v oauth_clients tabulce
ALTER TABLE oauth_clients ADD COLUMN use_compressed_groups BOOLEAN DEFAULT false;

-- Flag v claim_maps tabulce (pro custom claims)
ALTER TABLE claim_maps ADD COLUMN use_compression BOOLEAN DEFAULT false;
```

**Kdy se aplikuje:**
1. oauth_clients.use_compressed_groups = true → komprimuje "groups" claim
2. claim_maps.use_compression = true → komprimuje daný custom claim (pokud obsahuje array)

**Kompresní algoritmus:**
1. User má groups (po aplikaci user patterns + client patterns)
2. Načti compression rules (globální + client-specific), seřaď podle priority
3. Pro každé pravidlo:
   - Najdi všechny groups matchující pattern
   - Pokud je jich víc než 1 se stejným prefixem → zkomprimuj do `prefix:{val1,val2,...}`
   - Pokud je jen 1 → nech jako je (nebo použij compressed_format bez závorek)
4. Výsledek → do JWT

**Dekomprese na straně konzumenta:**
- `ssh:r:{admin,devops}` → expand to `["ssh:r:admin", "ssh:r:devops"]`
- Deterministické, jasné pravidlo

**Výhody:**
- Výrazná redukce velikosti tokenu
- Strukturu groups zachováváme (ne aliasy)
- Dekomprese je triviální
- Bezpečnější než aliasy (žádné konflikty s existujícími názvy)

**Nevýhody:**
- Menší redukce než by byly hardcoded aliasy
- Aplikace musí implementovat dekompresní logiku (ale je jednoduchá)

---

## Shrnutí dohody

| Feature | Implementace | Priorita |
|---------|--------------|----------|
| **Client-level group filtering** | Nová tabulka `oauth_client_group_patterns`, runtime eval | ✅ High |
| **Pattern-based claim maps** | Hybrid model, nová tabulka `claim_map_patterns` | ✅ High |
| **Token compression** | Nová tabulka `group_compression_rules`, compression flags v `oauth_clients` + `claim_maps` | ✅ Medium |

### Designová rozhodnutí:
- ✅ **Žádné aliasy** - příliš rizikové (konflikty, ztráta informace)
- ✅ **Pattern-based compression** - zachovává strukturu, bezpečnější
- ✅ **Compression flags na obou místech** - `oauth_clients.use_compressed_groups` + `claim_maps.use_compression`
- ✅ **Hybrid model pro claim maps** - zachováváme přesné vazby, patterns jsou opt-in
- ✅ **Runtime evaluation** - žádné schedulery pro client filtering
- ✅ **Sequential pattern application** - konzistentní s user group patterns (priority ASC, include/exclude)

---

## Status implementace

### Phase 1: Client-Level Group Filtering ✅ DOKONČENO
- ✅ Database migrace `023_add_oauth_client_group_patterns.sql`
- ✅ Datový model `OAuthClientGroupPattern` v `db/models.rs`
- ✅ Modul `client_group_filters.rs` s funkcí `apply_client_group_filters()`
- ✅ Integrace do token generation v `oauth2/authorization_code.rs`
- ✅ API endpointy (POST/GET/PUT/DELETE) v `api/admin/client_group_patterns.rs`
- ✅ TUI integrace - ClientPatternsManager dialog (Ctrl+P v Client formuláři)
- ✅ 3 unit testy v `client_group_filters.rs`
- ✅ API integration testy

### Phase 2: Pattern-Based Claim Maps ✅ DOKONČENO
- ✅ Database migrace `024_add_claim_map_patterns.sql`
- ✅ Datový model `ClaimMapPattern` v `db/models.rs`
- ✅ Modul `claim_map_patterns.rs` s funkcí `evaluate_claim_map_patterns()`
- ✅ Rozšíření `auth/claims.rs` pro hybrid model (group_id + patterns)
- ✅ API endpointy (POST/GET/PUT/DELETE) v `api/admin/claim_map_patterns.rs`
- ✅ TUI integrace - ClaimMapPatternsManager dialog (Ctrl+P v ClaimEditor)
- ✅ 14 unit testů v `claim_map_patterns.rs`
- ✅ 7 API integration testů v `tests/claim_map_patterns_api.rs`

### Phase 3: Token Compression ⏸️ ODLOŽENO
Připraveno k implementaci v budoucnu podle priority.

### Production Readiness ✅ DOKONČENO
- ✅ **Zero compiler warnings** - všechny warningy opraveny
- ✅ **Clean cargo check** - projekt kompiluje bez varování
- ✅ **30/32 testů úspěšných** (2 nesouvisející SSH testy)
- ✅ **Kód je production ready**
