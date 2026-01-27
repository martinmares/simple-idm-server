# Analýza JWT Tokenů a Návrh Optimalizace

## Aktuální Stav JWT Tokenu

### Struktura Claims (src/auth/jwt.rs:23-40)

```rust
pub struct Claims {
    pub sub: String,                    // User ID (UUID)
    pub iss: String,                    // Issuer (např. "https://idm.example.com")
    pub aud: Vec<String>,               // Client IDs (array of UUIDs)
    pub exp: i64,                       // Expiration timestamp
    pub iat: i64,                       // Issued at timestamp
    pub nonce: Option<String>,          // OIDC nonce (jen v ID tokenu)
    pub scope: Option<String>,          // OAuth2 scopes (space-separated)
    pub email: Option<String>,          // User email
    pub preferred_username: Option<String>, // Username
    pub groups: Vec<String>,            // User groups (TADY JE HLAVNÍ PROSTOR PRO OPTIMALIZACI!)
    pub custom_claims: HashMap<String, serde_json::Value>, // Custom claim maps (flattened)
}
```

### Příklad Reálného Tokenu

**Scénář:** User "alice" má 15 groups:
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://idm.example.com",
  "aud": ["client-uuid"],
  "exp": 1738012800,
  "iat": 1738009200,
  "email": "alice@example.com",
  "preferred_username": "alice",
  "groups": [
    "ssh:principal:alice",
    "ssh:role:admin",
    "ssh:role:devops",
    "ssh:role:monitoring",
    "ssh:role:auditor",
    "grafana:role:admin",
    "grafana:role:editor",
    "grafana:role:viewer",
    "gitlab:role:developer",
    "gitlab:role:maintainer",
    "gitlab:ns:o2",
    "gitlab:ns:cetin",
    "team:backend",
    "team:frontend",
    "simple-idm:role:admin"
  ],
  "app_role": "Admin",  // Custom claim z claim_maps
  "departments": ["Engineering", "DevOps"]  // Custom claim array
}
```

**Velikost:**
- Payload (před base64): ~620 bytes
- Base64 encoded: ~827 bytes
- Celý JWT (header + payload + signature): ~1150 bytes

---

## Problémové Oblasti

### 1. Groups Claim - Hlavní problém 🔴

**Aktuálně:** `groups` je `Vec<String>` s plnými názvy

```json
"groups": [
  "ssh:role:admin",      // 15 chars
  "ssh:role:devops",     // 16 chars
  "ssh:role:monitoring", // 20 chars
  "grafana:role:admin",  // 18 chars
  "grafana:role:editor", // 19 chars
  ...
]
```

**Celkem:** ~270 bytes jen pro groups (v příkladu výše)

**Co když user má 50+ groups?** → Token 3000+ bytes → HTTP overhead!

### 2. Custom Claims - Menší problém 🟡

Pokud používáme claim maps s array values:
```json
"departments": ["Engineering", "DevOps", "Operations", "Security"]
```

Taky může nabýt značných rozměrů.

### 3. Opakující se Prefixy - Low-hanging fruit 🟢

Viditelné opakování struktury:
- `ssh:role:*` → 9 chars prefix (opakuje se 5x = 45 bytes)
- `grafana:role:*` → 13 chars prefix (opakuje se 3x = 39 bytes)
- `gitlab:*` → různé kombinace

---

## Současný Token Generation Flow

### Lokace: src/oauth2/authorization_code.rs (řádky 861-919)

```rust
// 1. Získání user groups (respektuje groups_claim_mode)
let user_group_names = match client.groups_claim_mode.as_str() {
    "none" => vec![],
    "direct" => get_direct_user_group_names(...),  // Bez nested expansion
    _ => get_user_group_names(...),                // S nested expansion + virtual filtering
};

// 2. Vytvoření custom claims (pokud povoleno)
let custom_claims = if client.include_claim_maps {
    let user_group_ids = get_effective_user_groups(...).await?;
    build_custom_claims(&state.db_pool, client.id, &user_group_ids).await?
} else {
    HashMap::new()
};

// 3. Vytvoření JWT tokenu
let access_token = state.jwt_service.create_access_token(
    user.id,
    client.client_id.clone(),
    email,
    preferred_username,
    scope,
    user_group_names,  // ← TADY JDOU GROUPS DO TOKENU (bez jakékoli optimalizace!)
    custom_claims,
    expiry_seconds,
)?;
```

**Klíčový bod:** Mezi řádkem 883 (získání groups) a 921 (vytvoření tokenu) **NENÍ ŽÁDNÁ OPTIMALIZACE!**

---

## Navrhované Optimalizace a Jejich Dopad

### Optimalizace #1: Client-Level Group Filtering

**Před:**
```json
"groups": ["ssh:role:admin", "ssh:role:devops", "grafana:role:viewer", "gitlab:role:developer"]
```

**Po (pokud client potřebuje jen Grafana groups):**
```json
"groups": ["grafana:role:viewer"]
```

**Redukce:** 75-90% (závisí na client needs)

**Kde implementovat:**
```rust
// src/oauth2/authorization_code.rs, po řádku 883
let user_group_names = get_user_group_names(...).await?;

// ← NOVĚ: Aplikuj client group filtering
let filtered_groups = if client má patterns {
    apply_client_group_filters(&user_group_names, client_patterns)
} else {
    user_group_names  // Bez změny pro legacy clients
};

// Použij filtered_groups místo user_group_names pro JWT
```

---

### Optimalizace #2: Pattern-Based Claim Maps

**Před:**
- Claim map pro každou konkrétní groupu (UUID vazba)
- Nová group → musíme ručně vytvořit claim map

**Po:**
```
Claim Map:
  claim_name = "app_role"
  claim_value = "Admin"
  patterns:
    - pattern="*:admin:*", is_include=true
    - pattern="ssh:admin:*", is_include=false
```

**Dopad na velikost tokenu:** Nepřímý
- Redukuje nutnost mít velké množství groups v tokenu
- Místo posílání všech groups můžeme poslat jen relevantní subset + spoléhat na claim maps

**Kde implementovat:**
```rust
// src/auth/claims.rs, funkce build_custom_claims()

// Rozšířit logiku:
for claim_map in claim_maps {
    // Stávající logika: check group_id match
    if user_groups.contains(&claim_map.group_id) {
        // přidej claim
    }

    // NOVĚ: Pattern-based matching
    if claim_map má patterns {
        if evaluate_claim_map_patterns(&claim_map.patterns, &user_groups, all_groups) {
            // přidej claim
        }
    }
}
```

---

### Optimalizace #3: Token Compression

**Před:**
```json
"groups": ["ssh:role:admin", "ssh:role:devops", "ssh:role:monitoring"]
```

**Po:**
```json
"groups": ["ssh:r:{admin,devops,monitoring}"]
```

**Redukce:**
- Before: 56 chars
- After: 35 chars
- **Saving: ~37%**

**S více groups a více prefixes:** 40-60% redukce

**Kde implementovat:**
```rust
// src/oauth2/authorization_code.rs, před vytvořením JWT

let final_groups = if client.use_compressed_groups {
    // Načti compression rules (globální + client-specific)
    let rules = get_compression_rules(&state.db_pool, Some(client.id)).await?;
    compress_groups(&filtered_groups, &rules)
} else {
    filtered_groups
};

// Použij final_groups pro JWT
```

---

## Doporučený Postup Implementace

### Fáze 1: Client-Level Group Filtering (NEJVYŠŠÍ PRIORITA)

**Proč začít zde:**
- Největší okamžitý dopad na velikost tokenu
- Nejjednodušší implementace (žádné compression algoritmy)
- Nezávislé na ostatních optimalizacích
- Řeší reálný problém: client dostává 100+ groups, když potřebuje jen 5

**Kroky:**
1. Migrace: tabulka `oauth_client_group_patterns`
2. Pattern matching funkce (reuse z user group patterns)
3. Integrace do token generation (3 místa):
   - authorization_code.rs (authorization code flow)
   - authorization_code.rs (refresh token flow)
   - device_flow.rs (device flow)
4. API endpointy + TUI

**Odhad dopadu:**
- User s 50 groups, client potřebuje 5 → **90% redukce groups velikosti**
- Token 2500 bytes → 800 bytes

---

### Fáze 2: Pattern-Based Claim Maps (VYSOKÁ PRIORITA)

**Proč druhý:**
- Nepřímý vliv na velikost tokenu, ale zásadní pro správu
- Umožňuje efektivnější použití claim maps
- Kombinace s Client Filtering = silný nástroj

**Kroky:**
1. Migrace: tabulka `claim_map_patterns`
2. Pattern evaluation funkce
3. Integrace do `build_custom_claims()`
4. API endpointy + TUI

**Odhad dopadu:**
- Flexibilita > redukce velikosti
- V kombinaci s filtering: umožňuje poslat méně groups, spoléhat na claims

---

### Fáze 3: Token Compression (STŘEDNÍ PRIORITA)

**Proč až třetí:**
- Nejvíc komplexní implementace
- Vyžaduje compression/decompression logiku
- Klienti musí implementovat dekompresi
- Největší dopad když už máme filtering

**Kroky:**
1. Migrace: tabulka `group_compression_rules` + flags
2. Compression algoritmus (src/compression.rs)
3. Decompression (pro testování)
4. Integrace do token generation
5. API endpointy + TUI

**Odhad dopadu:**
- Po client filtering: další 30-50% redukce groups velikosti
- Token 800 bytes → 500 bytes

---

## Celkový Dopad Všech Optimalizací

### Scénář: Power User

**Výchozí stav:**
- User má 50 groups
- Token: ~2800 bytes

**Po Client Filtering (90% groups filtered out):**
- User má 50 groups, client dostane 5
- Token: ~900 bytes
- **Redukce: 68%**

**Po Compression (35% compression ratio):**
- 5 groups zkomprimované
- Token: ~650 bytes
- **Celková redukce: 77%**

### Scénář: Regular User

**Výchozí stav:**
- User má 10 groups
- Token: ~1200 bytes

**Po Client Filtering (50% filtered):**
- Client dostane 5 groups
- Token: ~950 bytes
- **Redukce: 21%**

**Po Compression:**
- Token: ~750 bytes
- **Celková redukce: 38%**

---

## Bezpečnostní a Výkonnostní Úvahy

### Security
- ✅ Client filtering nesmí být bypassnutelný (server-side enforcement)
- ✅ Patterns validace (zamezit `*` nebo příliš široké patterns)
- ⚠️ Compression musí být deterministická (stejný input → stejný output)
- ⚠️ Decompression na straně klienta musí být bezpečná (žádné injection)

### Performance
- ✅ Client filtering: O(N*M) kde N=groups, M=patterns (ale malé hodnoty, in-memory)
- ✅ Claim map patterns: stejná složitost, jen při claim building
- ⚠️ Compression: O(N*R*log(N)) kde R=compression rules (může být pomalé s mnoha rules)
  - **Řešení:** Cache compression rules per client, optimize pattern matching

### Backwards Compatibility
- ✅ Všechny features jsou opt-in (default = current behavior)
- ✅ Starí klienti fungují bez změn
- ✅ Migrace jsou aditivní (žádné breaking changes)

---

## Metriky pro Monitoring

Po implementaci sledovat:

1. **Token Size Distribution**
   - Histogram: velikost tokenů (bytes)
   - P50, P95, P99
   - Breakdown: před/po optimalizacích

2. **Groups Per Token**
   - Průměrný počet groups v tokenu
   - Max groups per token

3. **Filtering Effectiveness**
   - % groups filtered out per client
   - Top clients by filtering ratio

4. **Compression Ratio**
   - Average compression ratio (compressed size / original size)
   - Per compression rule effectiveness

5. **Performance**
   - Token generation latency (P95, P99)
   - Pattern matching time
   - Compression time

---

## Závěr a Next Steps

### 🎯 Doporučení: START WITH PHASE 1

**Phase 1: Client-Level Group Filtering**
- Největší okamžitý dopad
- Nejjednodušší implementace
- Nezávislé na ostatních features
- Real-world problem solving

**Implementation Order:**
1. ✅ Dokumentace (HOTOVO - AGREED.md, PLAN.md)
2. → Database migrace (023_add_oauth_client_group_patterns.sql)
3. → Pattern matching modul (reuse z user patterns)
4. → Integrace do token generation (3 touch points)
5. → API endpointy
6. → TUI support

**Po dokončení Phase 1:**
- Měřit dopad (metriky)
- Získat feedback
- Rozhodnout o Phase 2/3 na základě reálných dat

---

## Technické Poznámky

### Kde přesně se mění kód pro token generation:

**Soubor:** `src/oauth2/authorization_code.rs`

**Authorization Code Flow (handle_authorization_code_token):**
```rust
// Řádek 861-883: Získání user groups
let user_group_names = match client.groups_claim_mode.as_str() { ... };

// ← MÍSTO PRO CLIENT FILTERING (řádek ~884)
let filtered_groups = apply_client_group_filters(...);

// ← MÍSTO PRO COMPRESSION (řádek ~885)
let final_groups = compress_groups_if_enabled(...);

// Řádek 921-940: Vytvoření tokenu (použít final_groups)
let access_token = state.jwt_service.create_access_token(
    ...,
    final_groups,  // místo user_group_names
    ...,
)?;
```

**Refresh Token Flow (handle_refresh_token):**
- Stejná logika, řádky ~1164-1181 + ~1220-1239

**Device Flow (src/oauth2/device_flow.rs):**
- `handle_device_token()`, podobné místo

---

**Připraveno k implementaci! 🚀**
