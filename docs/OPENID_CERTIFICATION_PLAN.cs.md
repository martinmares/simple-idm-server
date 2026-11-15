# Plán OpenID Connect certifikace

## Stav a dohoda

- Datum: 18. 10. 2026.
- Stav: schválený budoucí směr; conformance testy ani certifikace zatím neprovedeny.
- Produkt: `simple-idm-server`.
- Cíl: získat oficiální záznam konkrétní verze produktu v seznamu
  certifikovaných implementací OpenID Foundation, s odkazem z README.
- Přesný název žadatele a podpisující odpovědnou osobu potvrdit před podáním.
- Tento plán nyní nezahajuje implementaci ani podání žádosti.

## Rozsah

Prvním cílem jsou profily **Basic OP** a **Config OP**. Před zahájením ověřit
aktuální požadavky a dostupné testovací plány OpenID Foundation.
OpenID4VCI, OpenID4VP a FAPI do této etapy nepatří.

Certifikace provideru automaticky nepokrývá `simple-idm-oauth2-proxy`.
Proxy nadále vyžaduje vlastní bezpečnostní a integrační testy; případná RP
certifikace je samostatný budoucí rozsah.

## Postup a akceptační kritéria

### 1. Izolovaný test a zjištění rozdílů

- [ ] Připravit izolované nasazení IDM s testovacími uživateli a klienty,
      bez produkčních dat a produkčních přístupů.
- [ ] Zaznamenat verzi, commit, konfiguraci a zvolené profily.
- [ ] Připravit discovery URL, dosažitelné endpointy a klienty podle oficiálních
      instrukcí, včetně požadovaných metod autentizace a callback URL.
- [ ] Spustit oficiální conformance suite proti skutečně běžícímu IDM.
- [ ] Uložit výsledky a sestavit seznam odchylek; teprve pak odhadnout pracnost.

Testy spouštíme a obsluhujeme my. Testovací software provádí protokolové
požadavky proti IDM; součástí mohou být interaktivní přihlášení a screenshoty.
Nejde o posouzení kompatibility podle README ani o automatický audit zdrojáků.

### 2. Opravy a reprodukovatelné ověření

- [ ] Opravovat jednotlivé odchylky v malých etapách s regresními testy.
- [ ] Ověřit celý vybraný testovací plán bez výsledků FAILED / INTERRUPTED.
      WARNING / REVIEW / SKIPPED vyhodnotit podle pravidel sady a doložit
      požadovaná vysvětlení nebo důkazy; samotná absence FAILED nestačí.
- [ ] Dokumentovat reprodukovatelné nasazení a opakování testů.
- [ ] Ověřit, že konfigurace pro testy odpovídá deklarovanému způsobu nasazení;
      nevytvářet speciální obcházení kontrol pouze pro certifikaci.

### 3. Oficiální podání a zveřejnění

- [ ] Exportovat výsledky pomocí „Publish for certification“ pro každý profil.
- [ ] Potvrdit název žadatele, produktu, konkrétní verzi a odpovědnou osobu.
- [ ] Ověřit aktuální poplatek / případnou způsobilost k OSS výjimce.
- [ ] Po samostatném schválení odpovědnou osobou vyřešit platbu, žádost
      a podpis Declaration of Conformance; tento plán je neopravňuje provést.
- [ ] Vyřešit případné dotazy při zpracování žádosti OpenID Foundation.
- [ ] Ověřit zveřejnění správné verze a profilů v oficiálním seznamu.
- [ ] Teprve poté doplnit README o přesný rozsah, oficiální odkaz a případné
      označení OpenID Certified podle pravidel programu.

## Doklady pro interní audit

Uchovat testovací logy, prohlášení, oficiální záznam, verzi a konfiguraci
nasazení. Jde o self-certifikaci protokolové shody, která může sloužit jako
podklad pro audit. Sama nepředstavuje certifikaci NIS2, bezpečnostní audit
celého produktu ani ověření HA nebo proxy. Tyto oblasti dokládat samostatně.
Po změnách ovlivňujících protokol opakovat relevantní testy a posoudit dopad
na deklarovanou shodu a zveřejněnou certifikaci podle pravidel programu.

## Oficiální podklady

- [Testování OIDC providerů](https://openid.net/certification/connect_op_testing/)
- [Testovací portál](https://www.certification.openid.net/)
- [Podání a zveřejnění certifikace](https://openid.net/certification/how-to-submit-your-certification-request/)
- [Význam self-certifikace](https://openid.net/certification/what-is-self-certification-faq/)
- [Oficiální seznam implementací](https://openid.net/certification/certified-openid-connect-implementations/)
- [Poplatky](https://openid.net/certification/fees/)
- [Podmínky OSS výjimky](https://openid.net/certification/open-source-project-certification-policy/)
