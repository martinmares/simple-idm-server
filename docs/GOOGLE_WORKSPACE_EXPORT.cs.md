# Export Workspace uzivatelu pro pripravu federace

Skript `scripts/export_google_workspace_users.py` vyexportuje uzivatele jedne
Workspace domeny pres Admin SDK Directory API. Google SDK je pouze klient pro
volani tohoto API: administrator se prihlasi v browseru a povoli cteni adresare.
Skript nezna heslo, nemeni Google ucty ani Simple IDM a neuklada OAuth tokeny.

## 1. Priprav Google projekt a Desktop klienta

Muzes pouzit existujici projekt `OAuth for DataLite`. Web klient pro SSO zustava
beze zmeny; pro export vytvor druhy klient typu Desktop app. Audience ponech
External, pokud SSO pouzivaji i osobni Gmail ucty. Pridani scope do consent
screen samo nemeni scopes, ktere SSO server pozaduje pri prihlaseni.
Samostatny projekt je volitelny pro oddeleni administrativniho exportu.

1. V Google Cloud Console vyber projekt `OAuth for DataLite`.
2. V **APIs & Services -> Library** vyhledej **Admin SDK API** a povol ji.
3. V **Google Auth Platform** ponech existujici Branding a Audience.
4. V **Data Access** pridej scope
   `https://www.googleapis.com/auth/admin.directory.user.readonly`.
5. V **Clients -> Create client** vyber **Desktop app**, nazev napr.
   `simple-idm-directory-export`. Nepouzivej existujici Web client pro SSO.
6. Stahni credentials JSON a uloz ho do `.tmp/google-directory-desktop.json`.
   Desktop klient pouziva lokalni loopback callback; verejne SSO callbacky
   sem nepridavej.

Pouzity admin ucet musi mit opravneni cist uzivatele Workspace. OAuth consent
sam o sobe tato opravneni neudeli. Nepotrebujeme service account ani domain-wide
delegation. Vychazime z [oficialniho Python quickstartu](https://developers.google.com/workspace/admin/directory/v1/quickstart/python),
ale pozadujeme pouze read-only scope a nepersistujeme tokeny.

## 2. Nainstaluj zavislosti na svem Macu

Z korene repozitare, s Pythonem 3.10 nebo novejsim:

```bash
umask 077
mkdir -p .tmp
python3 -m venv .tmp/google-directory-venv
.tmp/google-directory-venv/bin/python -m pip install -r scripts/requirements-google-workspace-export.txt
chmod 600 .tmp/google-directory-desktop.json
```

Credentials, exporty ani tokeny nedavej do Gitu. `.tmp/` je v tomto repozitari
ignorovany adresar. Export obsahuje osobni udaje a jeho soubor ma prava 0600.

## 3. Export a porovnani s existujici identitou

Hodnotu `--expected-sub` prevezmi z detailu sveho schvaleneho uzivatele v IDM.

```bash
.tmp/google-directory-venv/bin/python scripts/export_google_workspace_users.py \
  --credentials .tmp/google-directory-desktop.json \
  --admin mares@datalite.cz \
  --domain datalite.cz \
  --output .tmp/datalite-users.json \
  --format json \
  --check-email mares@datalite.cz \
  --expected-sub '<SUB_Z_DETAILU_UZIVATELE_V_IDM>'
```

Browser otevira Google prihlaseni. Vyber Workspace admin ucet, nikoliv osobni
Gmail. Cekani na callback ma limit 180 sekund a HTTP volani timeout 30 sekund.
API se cte po strankach, takze export neni omezen na prvnich 500 uzivatelu.
Pri shode se vypise `Directory ID matches the supplied OIDC sub.`; pri neshode
skript skonci chybou pred vytvorenim exportu. Bez obou kontrolnich parametru
se provede jen export. Strankovani a filtr domeny popisuje
[users.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list).

Pro CSV pouzij `--format csv --output .tmp/datalite-users.csv`. Export obsahuje:

- `google_id` (text, nikoliv cislo nebo UUID)
- `email` (primarni email)
- `first_name`, `last_name`
- `is_active`, `suspended`, `archived`

Standardne jsou zahrnute i suspendovane a archivovane ucty, ale
`is_active=false`. Pro aktivni ucty pridej `--active-only`. Pro kontrolu ID
pouzivej JSON nebo textovy editor: tabulkovy program muze dlouha cislicova ID
zaokrouhlit. CSV obsahuje profilove hodnoty z adresare; pri otevirani
v tabulkovem programu je importuj jako text, ne jako vzorce.

Skript neprepise existujici vystupni soubor. Pro dalsi export zvol novy nazev.
Google ID z API zatim nazyvame `google_id`, ne automaticky `sub`: prvni
porovnani se skutecnym OIDC prihlasenim je nutne pred navrhem predparovani.

## 4. Import pres simple-idm-ctl

Na server nasad novou binarku `simple-idm-server` a lokalne aktualizuj
`simple-idm-ctl`. Neni potreba nova migrace. Prihlas se do CLI jako IDM administrator.
Python export sam nic neimportuje. Zapis provadi zabezpecene Admin API,
nikoliv prime spojeni CLI do databaze; Web UI pro tento import neni.

Nejprve pouze nahled (zadne zmeny):

```bash
simple-idm-ctl users import-google \
  --file .tmp/datalite-users.json \
  --provider google \
  --domain datalite.cz \
  --approve
```

`--approve` i v nahledu ukazuje zamysleny stav novych identit. Teprve `--apply`
povoluje zapis. Po kontrole nahledu a duveryhodnosti exportu:

```bash
simple-idm-ctl users import-google \
  --file .tmp/datalite-users.json \
  --provider google \
  --domain datalite.cz \
  --approve --apply
```

- Bez `--approve` se nove identity vytvori jako `pending`; login bude mozny
  az po schvaleni v Admin UI. S `--approve` jde o explicitni administrativni
  schvaleni duveryhodneho Directory exportu misto invitation flow.
- Username noveho uzivatele je cast emailu pred `@`, napr. `pavel.rosecky`.
  Kolize bez rozliseni velikosti pismen zabrani zapisu; nepridavaji se automaticke
  pripony. Google ID zustava textovy subject.
  Profilova jmena se prevezmou z exportu. Heslo je NULL, lokalni heslo disabled.
- Pozastavene a archivovane ucty se preskoci; nikdo nedostane zadne skupiny,
  admin prava ani passkey. Ty spravuj oddelene.
- `--email uzivatel@datalite.cz` lze opakovat pro vyber konkretnich uctu.
  Alternativne priprav JSON pole jen s pozadovanymi zaznamy. Vynechani zaznamu
  neodebira ani nedeaktivuje uz existujici IDM uzivatele.
- `--tenant-id <UUID>` vybira tenant. Vychozi UUID je
  `11111111-1111-1111-1111-111111111111`; provider slug se hleda jen v tomto tenantu.
- Import podporuje jen aktivni provider typu `google` s issuerem
  `https://accounts.google.com`. Hosted domain, pokud je nastavena, musi odpovidat.
- Exactni existujici vazba se preskoci, vcetne jiz existujiciho uzivatele `mares`.
  Jeji approval stav se nemeni ani s `--approve`; pending vazbu schval v UI.
- Konflikt emailu, username nebo identity nelze automaticky prepsat. Lokalni/AD
  ucet se neprevadi a smazany ci neaktivni ucet se neobnovuje.
- Jakykoliv konflikt zabrani zapisu cele davky. CLI pri `--apply` skonci chybou.
  Pri opakovanem spusteni se plan vzdy znovu overuje proti aktualni DB.
- Uzivatel, identita a audit se zapisuji v jedne transakci. Chyba vrati celou
  davku zpet; import neuklada cast uzivatelu. Kratky zamykaci timeout brani
  dlouhemu cekani pri soubehu se zmenami v UI.
- Limit davky je 1000 uzivatelu a souboru 1 MiB. Vstup je JSON z exporteru,
  ne CSV. ID musi zustat string; duplicitni emaily nebo ID jsou chyba.

Import duveruje administratorovi a souboru: nevola znovu Google a neoveruje
puvod exportu. Neoznacuje `email_verified=true`, protoze export neni overeny
OIDC claim. Pouzij vlastni overeny export a pred prvnim predparovanim porovnej
Directory ID se skutecnym OIDC sub dle kroku 3. Osobni ucet `mares.uo@gmail.com`
neni soucast firemniho adresare; pro nej zustava invitation flow.

Pri chybe HTTP 403 zkontroluj zapnuti Admin SDK API, roli prihlaseneho admina
a Workspace API access policy. Google Cloud IAM role neopravnuje ke cteni
Workspace uzivatelu; potrebujes Workspace roli s Users Read API privilegiem.
Bezpecnostni omezeni neobchazej pridanim
zapisovych scopes. Secrets ani OAuth tokeny neposilej v diagnostice.

## 5. Oprava username po starsim importu

Starsi importer pouzival cely email jako username. Neni nutne ucty mazat ani
znovu importovat. S novym serverem a CLI nejprve zobraz nahled:

```bash
simple-idm-ctl users normalize-google-usernames \
  --provider google \
  --domain datalite.cz
```

Zkontroluj sloupce `old_username`, `new_username` a `action`. Zapis povol
opakovanim stejneho prikazu s `--apply`. Exportni JSON zde neni potreba.

- Meni pouze aktivni, nesmazane federovane ucty vybraneho Google providera
  a domeny, kde `username=email` (bez rozliseni velikosti pismen).
- Vlastni username, napr. `mares`, nemeni. Nemenene zaznamy maji akci `skip`.
- `--tenant-id <UUID>` a opakovane `--email <email>` omezuji rozsah stejne jako
  u importu. Vychozi tenant UUID je `11111111-1111-1111-1111-111111111111`.
- Kazda kolize navrzeneho username, i se smazanym uctem nebo jinym navrhem
  v davce, zablokuje cely zapis. Kontrola je bez rozliseni velikosti pismen.
- Prejmenovani i audit se ukladaji v jedne transakci. Opakovane spusteni po
  oprave uz nic neprejmenuje. Neni potreba migrace DB.
- UUID uzivatele, email, profil, Google issuer/sub, approval, hesla, skupiny
  a existujici sessions zustavaji beze zmeny.

Novy token bude obsahovat nove `preferred_username`. Jiz vydane tokeny mohou
mit puvodni hodnotu do sve expirace; externi aplikace identifikujici uzivatele
podle `preferred_username` mohou potrebovat vlastni upravu. Stabilni OIDC
identifikator `sub` se nemeni. Tato oprava nepridava obecnou editaci username
do Admin UI; je to explicitni administrativni CLI operace.

## Lokalni testy bez Google credentials

```bash
python3 -m unittest discover -s scripts -p 'test_export_google_workspace_users.py'
```
