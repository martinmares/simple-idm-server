# Simple IDM SSH Login

Klientská CLI utility pro získání krátkodobého SSH certifikátu přes Simple IDM Server.

## Funkce

- **Browser Flow** (Authorization Code + PKCE) - rychlé SSO přihlášení přes browser
- **Device Flow** (RFC 8628) - headless fallback pro servery bez browseru
- **Smart Mode** - automatický fallback z browser na device flow
- Automatická správa SSH keypair (Ed25519)
- Podpora pro konfigurovatelné TTL certifikátů
- Integrace s OpenSSH přes `CertificateFile`

## Quick Start

### 1. Instalace

```bash
cargo build --release --bin simple-idm-ssh-login
sudo cp target/release/simple-idm-ssh-login /usr/local/bin/
```

### 2. První přihlášení

```bash
# Smart mode (zkusí browser, fallback na device)
simple-idm-ssh-login login

# Pouze browser flow
simple-idm-ssh-login login --browser

# Pouze device flow
simple-idm-ssh-login login --device
```

### 3. SSH připojení

Po úspěšném login můžete použít běžný SSH:

```bash
ssh your-server.com
```

### 4. Doporučená konfigurace SSH

```bash
simple-idm-ssh-login print-ssh-config >> ~/.ssh/config
```

Nebo manuálně přidejte do `~/.ssh/config`:

```sshconfig
Host *.corp *.example.com
  IdentityFile ~/.ssh/id_simpleidm
  CertificateFile ~/.ssh/id_simpleidm-cert.pub
  IdentitiesOnly yes
```

## Příkazy

### `login`

Získá OIDC token a vyžádá SSH certifikát.

```bash
simple-idm-ssh-login login [OPTIONS]

Options:
  --browser         Force browser flow
  --device          Force device flow
  --issuer <URL>    Override OIDC issuer
  --signer-url <URL> Override signer URL
  --ttl-seconds <N> Override certificate TTL
```

**Příklady:**

```bash
# Smart mode
simple-idm-ssh-login login

# Force device flow
simple-idm-ssh-login login --device

# Custom TTL (8 hours)
simple-idm-ssh-login login --ttl-seconds 28800
```

### `status`

Zobrazí informace o aktuálním certifikátu.

```bash
simple-idm-ssh-login status
```

Výstup:

```
📜 SSH Certificate Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Type: ssh-ed25519-cert-v01@openssh.com user certificate
Public key: ED25519-CERT SHA256:...
Signing CA: ED25519 SHA256:...
Key ID: "simple-idm-cert"
Serial: 1
Valid: from 2026-01-24T10:00:00 to 2026-01-24T11:00:00
Principals:
        alice
        role:devops
Critical Options: (none)
Extensions:
        permit-agent-forwarding
        permit-port-forwarding
```

### `logout`

Smaže lokální certifikát.

```bash
simple-idm-ssh-login logout
```

### `print-ssh-config`

Vypíše doporučený SSH config block.

```bash
simple-idm-ssh-login print-ssh-config
```

## Konfigurace

### Priority konfigurace

1. CLI flags (nejvyšší priorita)
2. Environment variables
3. Config file (`~/.config/simple-idm-ssh-login/config.toml`)
4. Default values

### Config file

Vytvořte `~/.config/simple-idm-ssh-login/config.toml`:

```toml
oidc_issuer = "https://sso.cloud-app.cz"
client_id = "simple-idm-ssh-login"
scopes = ["openid", "profile", "email", "groups"]

signer_url = "https://ssh-signer.cloud-app.cz"
ttl_seconds = 3600

# Optional: custom SSH key path
# ssh_key_path = "/home/user/.ssh/id_simpleidm"
```

### Environment Variables

- `OIDC_ISSUER` - OIDC issuer URL
- `CLIENT_ID` - OAuth2 client ID
- `SIGNER_URL` - SSH signer URL
- `TTL_SECONDS` - Certificate TTL
- `SSH_KEY_PATH` - Custom SSH key path

**Příklad:**

```bash
export OIDC_ISSUER="https://sso.cloud-app.cz"
export SIGNER_URL="https://ssh-signer.cloud-app.cz"
simple-idm-ssh-login login
```

## Artefakty na disku

Default cesty:

- Private key: `~/.ssh/id_simpleidm`
- Public key: `~/.ssh/id_simpleidm.pub`
- Certificate: `~/.ssh/id_simpleidm-cert.pub`

Certifikát je automaticky přepsán při každém `login`.

## OIDC Flows

### Browser Flow (default)

1. Spustí lokální HTTP server na `127.0.0.1:<random-port>`
2. Otevře browser s authorize URL
3. Po callbacku vymění authorization code za token (PKCE)
4. Validuje ID token (iss/aud/exp/nonce + signatura)

**Výhody:**

- Rychlé (přímé SSO)
- User-friendly
- Podpora MFA/passwordless

**Nevýhody:**

- Vyžaduje browser
- Nefunguje na headless serverech

### Device Flow (fallback)

1. Zavolá `/device_authorization` endpoint
2. Zobrazí `user_code` a `verification_uri`
3. Polluje `/token` endpoint
4. Po úspěšném ověření vrátí token

**Výhody:**

- Funguje bez browseru
- Funguje na remote serverech

**Nevýhody:**

- Pomalejší (manuální zadání kódu)
- Více kroků

### Smart Mode

Default chování:

1. Zkusí browser flow
2. Pokud selže (např. `DISPLAY` není dostupný), použije device flow

## Troubleshooting

### "Failed to open browser"

Browser flow selhal, ale můžete manuálně otevřít URL z terminálu.

Nebo použijte device flow:

```bash
simple-idm-ssh-login login --device
```

### "Certificate request failed (401)"

OIDC token je neplatný nebo expiroval. Zkuste znovu:

```bash
simple-idm-ssh-login login
```

### "Certificate request failed (403): No principals available"

Uživatel nemá přiřazené žádné SSH groups (`ssh:principal:*` nebo `ssh:role:*`).

Zkontrolujte groups:

```bash
simple-idm-ctl user-groups list --username <username>
```

### "No certificate found"

Ještě jste se nepřihlásili:

```bash
simple-idm-ssh-login login
```

### "ssh-keygen failed"

Ověřte, že `ssh-keygen` je nainstalován:

```bash
which ssh-keygen
ssh-keygen -V
```

## Bezpečnost

### Token Storage

- **ID token není uložen na disk** - pouze v paměti během requestu
- Certifikát je uložen jako plaintext v `~/.ssh/` (standardní OpenSSH praxe)
- Private key má permissions `600` (pouze vlastník)

### Certificate Validity

- Krátkodobé certifikáty (typicky 1 hodina)
- Žádný refresh - po expiraci musí uživatel znovu zavolat `login`
- Certifikát je podepsán CA klíčem na `simple-idm-ssh-signer`

### SSH Server Trust

SSH server musí mít nakonfigurovaný `TrustedUserCAKeys`:

```sshconfig
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/simple-idm-ssh-signer.pub
```

Bez tohoto nastavení nebude certifikát akceptován!

## Integration s Simple IDM

### OAuth Client Setup

Vytvořte public OAuth2 klienta:

```bash
simple-idm-ctl oauth-clients create \
  --client-id "simple-idm-ssh-login" \
  --name "SSH Login CLI" \
  --grant-types "authorization_code" "urn:ietf:params:oauth:grant-type:device_code" \
  --redirect-uris "http://127.0.0.1:*/callback" \
  --scope "openid profile email groups" \
  --public
```

### User Groups

Přiřaďte uživatelům SSH principals:

```bash
# Direct principal
simple-idm-ctl groups create --name "ssh:principal:alice"
simple-idm-ctl user-groups add --username alice --group "ssh:principal:alice"

# Role-based
simple-idm-ctl groups create --name "ssh:role:devops"
simple-idm-ctl user-groups add --username alice --group "ssh:role:devops"
```

## Development

### Build

```bash
cargo build --bin simple-idm-ssh-login
```

### Test Login

```bash
RUST_LOG=simple_idm_ssh_login=debug \
  ./target/debug/simple-idm-ssh-login login --device
```

### Test Certificate

```bash
# Inspect certificate
ssh-keygen -L -f ~/.ssh/id_simpleidm-cert.pub

# Test SSH (verbose)
ssh -v your-server.com
```

## Licence

Same as Simple IDM Server.
