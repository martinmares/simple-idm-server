# Vydávání Simple IDM

Všech 13 crates používá společnou verzi z `[workspace.package]` v kořenovém
`Cargo.toml`. Členské manifesty mají `version.workspace = true`. Soubor `VERSION`
vyjadřuje záměr vydat release a musí odpovídat této verzi i `Cargo.lock`.

## Příprava další verze

```sh
just release-version 0.12.2
just check-version
git add VERSION Cargo.toml Cargo.lock
git commit -m "Release 0.12.2"
git push origin main
```

Pro GitHub odešli stejný commit také do GitHub remote. Příkaz `release-version`
upraví všechny tři soubory společně; při chybě obnoví jejich původní obsah.
Členské manifesty není nutné upravovat. Skript potřebuje Python 3.11 nebo novější;
`release.sh` vybere dostupnou verzi automaticky, případně použij `RELEASE_PYTHON`.

Změna `VERSION` na `main` spustí ověření, sestavení a publikaci tagu `v<verze>`.
Samotná změna kódu spouští kontrolní pipeline. Tag předem nevytvářej.
Již použitou verzi lze znovu vydat pouze ze stejného commitu; pro nový commit
zvol novou verzi. CI necommituje ani neposílá změny zpět do repozitáře.

## Platformy a obsah balíčků

| Platforma | GitHub | GitLab | Binárky |
| --- | --- | --- | --- |
| Linux AMD64, musl | ano | ano | všech 9 |
| macOS Apple Silicon | ano | — | všech 9 |
| Windows AMD64, MSVC | ano | — | 8, bez unixového bastionu |

Archiv obsahuje server, ctl, oauth2-proxy, oidc-metadata-proxy, token-proxy,
ad-proxy, ssh-login, ssh-signer a na unixových platformách také bastion.
Přibalené jsou README, licence, `VERSION`, SQL migrace a `BUILD.json` s verzí,
commitem, cílovou platformou a seznamem binárek. Unixové balíčky navíc obsahují
ukázkovou konfiguraci bastionu. `SHA256SUMS` ověřuje všechny vydané archivy.

Názvy pro počáteční společnou verzi jsou:

- `simple-idm-0.12.1-linux-amd64.tar.gz`
- `simple-idm-0.12.1-darwin-arm64.tar.gz`
- `simple-idm-0.12.1-windows-amd64.zip`

Linux používá `cargo-zigbuild` a musl. macOS a Windows se sestavují na nativních
GitHub runnerech. OpenSSL je pro tyto release cíle sestaven ze zdrojů a přilinkován
staticky, aby balíčky nevyžadovaly systémovou instalaci OpenSSL. Windows potřebuje
MSVC, Perl a NMake; nelze jej sestavit pomocí samotného `cargo-xwin` na Linuxu.
GitLab proto používá pouze Linux runner.

## Ruční spuštění

Na GitHubu otevři **Actions → Release → Run workflow**, vyber `main` a spusť
workflow. Na GitLabu otevři **Build → Pipelines → New pipeline**, vyber `main`
a spusť pipeline. Oba ruční vstupy vydávají verzi uloženou v daném commitu.
Při opravě neúspěšného vydání s novým commitem zvyš také verzi.

GitHub ukládá balíčky do GitHub Release. GitLab je nejprve uloží do Generic
Package Registry `simple-idm/<verze>` a potom vytvoří release s trvalými odkazy.
Publikační job používá `CI_JOB_TOKEN`; projekt musí povolovat přístup tokenu
k Releases API a Package Registry. GitHub používá vlastní `github.token`
s oprávněním `contents: write` v publikačním jobu.

## Kontroly a lokální sestavení

```sh
just check-version
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
bash scripts/release.sh package x86_64-unknown-linux-musl
```

Před balením musí existovat release binárky ve `target/<target>/release`.
Pro Linux slouží `just release-linux`, pro lokální macOS `just release-macos`.
Windows v CI používá PowerShell s aktivním MSVC prostředím.

CI používá připnutý Rust z `rust-toolchain.toml`, zamčené závislosti a
`SQLX_OFFLINE=true` s verzovanou `.sqlx` cache. Běžné testy nepotřebují databázi.
Ignorované databázové integrační testy se automaticky nespouští; pro jejich
samostatné spuštění použij vyhrazenou testovací PostgreSQL a proměnné uvedené
u konkrétních testů.

Testy release skriptů spustíš pomocí Pythonu 3.11+:

```sh
python3.14 -m unittest discover -s scripts -p 'test_*.py'
```
