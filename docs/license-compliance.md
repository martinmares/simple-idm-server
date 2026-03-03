# License Compliance (AGPL-3.0)

Projekt je licencovaný pod AGPL-3.0.

## Povinnost při provozu služby
- Pokud je služba zpřístupněna uživatelům po síti, musí být dostupné odpovídající zdrojové kódy nasazené verze (včetně lokálních úprav).

## Interní proces (doporučení)
- Udržovat interní repozitář s přesným zdrojovým stavem každého release.
- Evidovat commit SHA nasazené verze v deployment metadata.
- Mít jednoduchý proces, jak uživatel/administrátor získá zdrojové kódy daného nasazení.

## Third-party závislosti
- Pravidelně generovat SBOM (např. CycloneDX).
- Provádět license scan a bezpečnostní scan závislostí v CI.

## Praktické minimum pro audit
- Link/umístění zdrojových kódů nasazené verze.
- Proces evidence změn a release.
- Doložený seznam závislostí (SBOM) a jejich licencí.
