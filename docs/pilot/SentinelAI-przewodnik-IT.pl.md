# Przewodnik IT SentinelAI

*Wersja pilotażowa. Wersja angielska: [IT guide](SentinelAI-IT-guide.en.md). Opis prostym językiem: [SentinelAI dla firm](SentinelAI-dla-firm.pl.md). Program ma interfejs w języku angielskim, dlatego nazwy przycisków i ekranów podajemy po angielsku.*

## 1. Architektura

| Składnik | Gdzie działa | Co robi |
| --- | --- | --- |
| **Core** | Komputer centralny, usługa Windows `SentinelAICore` („SentinelAI Local Core”), konto `NT SERVICE\SentinelAICore`, start automatyczny opóźniony | Odbiera dane od Agentów, ocenia reguły, przechowuje alerty, ryzyko i licencję pilotażową, obsługuje Desktop. |
| **Desktop** | Tylko komputer centralny, działa jako zalogowany użytkownik Windows | Aplikacja administracyjna: Devices, Alerts, Risk, Reports, Settings. Logujesz się kontem administratora SentinelAI utworzonym podczas instalacji. |
| **Agent** | Każdy komputer, także centralny; usługa Windows `SentinelAIAgent` („SentinelAI Endpoint Agent”), konto `NT AUTHORITY\LocalService`, start automatyczny | Odczytuje inwentarz komputera, ustawienia i stan zabezpieczeń oraz wybrane zdarzenia Windows i wysyła je do Core. Zapisuje tylko własne pliki stanu i nigdy nie zmienia ustawień Windows ani Waszych plików. |
| **Updater** | Instalowany razem z Core i z każdym Agentem | Klient weryfikacji paczek używający tylko kluczy publicznych. Podczas instalacji, aktualizacji i naprawy instalator weryfikuje podpisane paczki własną wbudowaną kopią. Niczego nie pobiera. |

**Lokalizacje danych**

| Lokalizacja | Zawartość |
| --- | --- |
| `%ProgramFiles%\SentinelAI\{Core,Agent,Desktop,Updater}` | Kod programu instalacji centralnej, zapisywalny tylko dla Administratorów i SYSTEM (zob. punkt 10). `Core\pilot-license` zawiera klucze publiczne pilotażu i dane kontaktowe. |
| `%ProgramData%\SentinelAI\Core` | Baza SQLite Core `sentinelai.db`, konfiguracja i potwierdzenia własności. Baza zawiera konto administratora (skrót hasła), urządzenia, alerty i klucz pilotażowy. |
| `%ProgramData%\SentinelAI\Agent` | Agent komputera centralnego: stan rejestracji i jego dane uwierzytelniające, chronione przez DPAPI konta LocalService. |
| `%ProgramData%\SentinelAI\Setup` | Przypięty publiczny klucz zaufania instalatora i potwierdzenie własności. Bez haseł i tokenów. |
| `%ProgramFiles%\SentinelAI Setup\SentinelAI-Setup.exe` | Zainstalowana kopia instalatora, uruchamiana przez **Odinstaluj** przy **SentinelAI** w **Ustawienia → Aplikacje → Zainstalowane aplikacje** (Windows 10: **Aplikacje i funkcje**). |
| `%ProgramFiles%\SentinelAI Agent\…`, `%ProgramData%\SentinelAI Agent\…` | Na pozostałych komputerach: Agent, Updater, zainstalowana kopia instalatora Agenta, konfiguracja Agenta i jego dane uwierzytelniające chronione przez DPAPI. |
| `LocalMachine\My`, certyfikat o przyjaznej nazwie „SentinelAI Core local network” (podmiot: nazwa komputera) | Własny certyfikat TLS Core dla sieci lokalnej. Klucz prywatny jest nieeksportowalny i dostępny tylko dla konta usługi Core, SYSTEM i Administratorów. |

Wszystkie dane zostają na komputerze centralnym. Core w wersji pilotażowej nie nawiązuje połączeń wychodzących: nie ma usługi w chmurze, serwera licencji, telemetrii do dostawcy ani automatycznych aktualizacji.

## 2. Sieć

- **Jeden port.** Core nasłuchuje na porcie TCP **5443** (HTTPS) na każdym interfejsie IPv4 komputera centralnego, wyłącznie dla Agentów. Wszystkie funkcje administracyjne, logowanie i Desktop są dostępne tylko pod `http://127.0.0.1:5000`, czyli z samego komputera centralnego. Żądania tych funkcji na porcie 5443 dostają odpowiedź `404`.
- **Reguła zapory.** Instalator dodaje jedną regułę przychodzącą `SentinelAI-Core-LocalNetwork` („SentinelAI Core (Agents on the local network)”): TCP 5443, program `SentinelAI.Core.exe`, adres zdalny **LocalSubnet**, tylko profile **domenowy i prywatny**, nigdy publiczny. Skutki:
  - Agenci muszą być w tej samej podsieci co komputer centralny. Komputery w innym VLAN-ie lub łączące się przez VPN nie są obsługiwane przez domyślną regułę.
  - Windows nie stosuje tej reguły, gdy sieć jest sklasyfikowana jako **publiczna**, a tak jest domyślnie dla nowej sieci. Na komputerze centralnym ustaw w Ustawieniach Windows sieć firmową jako **prywatną**.
- **TLS.** TLS 1.3 jest używany zawsze, gdy obie strony go obsługują. TLS 1.2 jest używany tylko wtedy, gdy jedną ze stron jest Windows 10, który nie ma TLS 1.3. Core akceptuje wyłącznie zestawy szyfrów AES-GCM (dla TLS 1.2 z wymianą kluczy ECDHE) i zrywa każde inne połączenie, zanim zostaną wymienione jakiekolwiek dane. TLS 1.1 i starsze nigdy nie są włączone.
- **Przypinanie certyfikatu.** Instalator tworzy własny certyfikat Core (ECDSA P-256, z podpisem własnym, ważny 10 lat). Nigdzie nie jest instalowany żaden urząd certyfikacji. Każdy Agent ufa Core tylko wtedy, gdy odcisk SHA-256 jego certyfikatu dokładnie zgadza się z przypięciem z kodu rejestracyjnego. Niewłaściwy certyfikat kończy połączenie podczas uzgadniania TLS, zanim zostanie wysłany jakikolwiek token czy dane uwierzytelniające. Desktop → **Settings → Local network** pokazuje adresy, port i odcisk.
- **Ruch Agenta.** Co 30 sekund Agent wysyła krótki sygnał życia. Inwentarz wysyła co sześć godzin i w ciągu kilku sekund po zmianie monitorowanego ustawienia (nie częściej niż co 30 sekund), stan zabezpieczeń co godzinę, a nowe zdarzenia w paczkach.

## 3. Wymagania

- Windows 10 w wersji 22H2 x64 lub Windows 11 x64, na komputerze centralnym i na każdym komputerze z Agentem. Windows na ARM i 32-bitowy Windows nie są obsługiwane.
- Komputer centralny, który pozostaje włączony, ze stałym adresem IP (statycznym lub z rezerwacją DHCP) albo nazwą DNS rozpoznawaną przez pozostałe komputery.
- Wszystkie komputery w tej samej podsieci, sieć ustawiona jako prywatna lub domenowa.
- Konto administratora na każdym komputerze do instalacji. Instalator korzysta z wbudowanego Windows PowerShell 5.1 i nigdy nie zmienia zasad wykonywania ani innych zabezpieczeń; wymuszona kontrola aplikacji lub tryb ograniczonego języka mogą go więc zablokować.
- Wolny port TCP 5443 na komputerze centralnym. Sprawdź to przed instalacją: `Get-NetTCPConnection -LocalPort 5443 -ErrorAction SilentlyContinue` nie może niczego pokazać. Instalator sprawdza port dopiero w trakcie instalacji, a nieudana nowa instalacja zostawia częściowy stan, który kolejny instalator odrzuca (kod `SETUP-OWNERSHIP`); w takim przypadku skontaktuj się z dostawcą.
- Nie jest potrzebny dostęp do internetu, instalacja .NET ani przeglądarka; programy zawierają własne środowisko uruchomieniowe.

## 4. Instalacja centralna

1. **Sprawdź pobrane pliki.** Porównaj sumę kontrolną SHA-256 każdego pliku z `SHA256SUMS.txt` z tego samego wydania:
   ```powershell
   Get-FileHash .\SentinelAI-Setup.exe -Algorithm SHA256
   Get-Content .\SHA256SUMS.txt
   ```
   Skrót musi się zgadzać; wielkość liter nie ma znaczenia. Jeśli się różni, nie uruchamiaj pliku.
2. **Uruchom `SentinelAI-Setup.exe`.** Instalator nie jest podpisany cyfrowo, więc Windows SmartScreen pokaże **System Windows ochronił ten komputer**. Wybierz **Więcej informacji**, sprawdź nazwę pliku i wybierz **Uruchom mimo to**. Zatwierdź monit administratora (UAC).
3. **Poczekaj**, aż instalator zweryfikuje osadzone paczki i sprawdzi komputer. Na komputerze, na którym jest już ta instalacja SentinelAI, instalator zamiast tego oferuje Repair, Upgrade albo Uninstall. Częściowy lub nierozpoznany stan instalacji zostanie odrzucony (kod `SETUP-OWNERSHIP`).
4. **Wpisz otrzymany klucz pilotażowy.** Instalator sprawdza go na komputerze, bez połączenia z siecią, zanim cokolwiek zainstaluje. Klucz uszkodzony, obcy lub wygasły zostanie odrzucony z kodem `SETUP-PILOT-KEY` lub `SETUP-PILOT-EXPIRED`.
5. **Utwórz administratora SentinelAI:** nazwę użytkownika i hasło o długości 12–1024 znaków. To konto służy do logowania w Desktopie; nie jest kontem Windows.
6. **Pozostaw zaznaczone „Allow Agents on other computers in this local network to connect”.** Odznaczenie tworzy instalację tylko lokalną, która monitoruje wyłącznie komputer centralny.
7. **Wybierz Install SentinelAI.** Instalator tworzy certyfikat Core, instaluje Core, tworzy administratora, uruchamia Core i dodaje regułę zapory, zapisuje klucz pilotażowy, instaluje i rejestruje własnego Agenta komputera centralnego, a następnie instaluje Desktop, Updater i skrót w menu Start. Jeśli krok się nie powiedzie, instalator zgłosi błąd i nie zgłosi sukcesu. Jedynym wyjątkiem jest klucz pilotażowy: jeśli Core nie może go zapisać, instalacja się kończy, a instalator prosi o wpisanie klucza w Desktopie.
8. **Otwórz Desktop** z instalatora albo przez **Start → SentinelAI** i zaloguj się. **Devices** pokazuje komputer centralny.

## 5. Dodawanie komputerów

**Utwórz kody.** W Desktopie → **Devices → Add computers** wybierz:

- adres, którego używają Agenci: nazwę komputera, zalecaną, gdy jest rozpoznawana, albo adres IPv4, który musi pozostać stały;
- liczbę kodów (1–50);
- ich ważność: 1 godzina, 8 godzin, 24 godziny (domyślnie), 3 dni lub 7 dni.

**Copy codes** kopiuje kody do schowka, z pominięciem historii schowka. **Save codes as files** zapisuje po jednym pliku `.sentinelai-enroll` na kod, o nazwie `SentinelAI-computer-NN-….sentinelai-enroll`. Każdy kod jest tajny i rejestruje dokładnie jeden komputer; przekaż go tylko osobie instalującej ten komputer. Niewykorzystane kody są widoczne na liście z datą wygaśnięcia i można je unieważnić.

**Instalacja interaktywna.** Na dodawanym komputerze:

1. Sprawdź `SentinelAI-Agent-Setup.exe` z `SHA256SUMS.txt` i uruchom go (SmartScreen: **Więcej informacji → Uruchom mimo to**). Zatwierdź UAC.
2. Wklej kod albo wybierz **Open code file...**, a potem **Install SentinelAI Agent**.
3. Zanim cokolwiek zmieni, instalator łączy się z Core pod adresem z kodu, sprawdza przypięcie certyfikatu i pyta Core, czy kod jest nadal ważny.
4. Po udanej instalacji komputer pojawia się w Desktopie → **Devices**.

**Instalacja cicha.** Uruchom z uprawnieniami administratora lub jako SYSTEM:

```
SentinelAI-Agent-Setup.exe /quiet /codefile <ścieżka do pliku .sentinelai-enroll>
```

Nie pojawia się żadne okno. Instalator Agenta jest programem okienkowym Windows, więc PowerShell nie czeka na niego i nie ustawia `$LASTEXITCODE`; kod wyjścia odczytaj tak:

```powershell
(Start-Process .\SentinelAI-Agent-Setup.exe -ArgumentList '/quiet', '/codefile', '"C:\Kody\PC01.sentinelai-enroll"' -Wait -PassThru).ExitCode
```

Wynik podaje kod wyjścia:

| Kod | Znaczenie |
| --- | --- |
| 0 | Zainstalowano i zarejestrowano. |
| 1 | Nieoczekiwany błąd. |
| 2 | Nieprawidłowy wiersz polecenia. |
| 3 | To nie jest prawidłowy kod rejestracyjny. Nic nie zmieniono. |
| 4 | Core nieosiągalny pod adresem z kodu. Nic nie zmieniono. |
| 5 | Certyfikat nie zgadza się z przypięciem w kodzie. Nic nie zmieniono. |
| 6 | Kod wygasł, został użyty lub unieważniony. Nic nie zmieniono. |
| 7 | Na tym komputerze jest już zainstalowany Agent. Nic nie zmieniono. |
| 8 | Instalacja nie powiodła się; instalator usunął to, co zainstalował. |
| 9 | Core nie potwierdził rejestracji; instalator usunął Agenta. Utwórz nowy kod. |
| 12 | Instalacja nie powiodła się, a sprzątanie nie zakończyło się: uruchom `/uninstall`, potem zainstaluj ponownie. |
| 1603 | Instalator nie mógł się uruchomić, sprawdzić samego siebie ani przygotować chronionego obszaru roboczego. Nic nie zmieniono. |
| 1460 | Instalator nadal działał po 30 minutach. |

**Przykład dla zasad grupy (GPO).** Jeden kod na komputer: zmień nazwę każdego zapisanego pliku kodu na `<NAZWAKOMPUTERA>.sentinelai-enroll` i umieść go w folderze `codes` w udziale, który mogą czytać tylko komputery domeny, razem z `SentinelAI-Agent-Setup.exe`. Utwórz skrypt uruchamiania komputera w **Konfiguracja komputera → Zasady → Ustawienia systemu Windows → Skrypty (uruchamianie/zamykanie) → Uruchamianie**; działa on jako SYSTEM:

```powershell
$share = '\\fileserver\SentinelAI$'
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAIAgent') { exit 0 }
$code = Join-Path $share "codes\$env:COMPUTERNAME.sentinelai-enroll"
if (-not (Test-Path -LiteralPath $code)) { exit 0 }
# Folder zapisywalny tylko dla administratorów, więc nikt nie podmieni instalatora przed uruchomieniem.
$work = Join-Path $env:ProgramFiles 'SentinelAI Deploy'
New-Item -ItemType Directory -Path $work -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $share 'SentinelAI-Agent-Setup.exe'), $code -Destination $work -Force
$codeFile = Join-Path $work "$env:COMPUTERNAME.sentinelai-enroll"
$setup = Start-Process -FilePath (Join-Path $work 'SentinelAI-Agent-Setup.exe') -ArgumentList '/quiet', '/codefile', "`"$codeFile`"" -Wait -PassThru
Remove-Item -LiteralPath $work -Recurse -Force
exit $setup.ExitCode
```

Kody są ważne najwyżej 7 dni, więc twórz je tuż przed wdrożeniem, a pliki kodów usuń, gdy komputery pojawią się w Desktopie. Najpierw przetestuj skrypt na jednym komputerze.

**Przykład dla Microsoft Intune.** Każdy kod rejestruje jeden komputer, więc przy kilku komputerach utwórz osobną aplikację Win32 dla każdego z nich albo użyj skryptu podobnego do przykładu GPO.

1. Zmień nazwę pliku kodu danego komputera na `code.sentinelai-enroll` i spakuj go razem z `SentinelAI-Agent-Setup.exe` w jednym folderze narzędziem Microsoft Win32 Content Prep Tool.
2. Skonfiguruj aplikację:
   - **Polecenie instalacji:** `SentinelAI-Agent-Setup.exe /quiet /codefile code.sentinelai-enroll`. Instalator Agenta rozwiązuje ścieżkę względną względem bieżącego folderu, którym dla aplikacji Win32 jest folder, do którego Intune ją rozpakowuje.
   - **Polecenie dezinstalacji:** `SentinelAI-Agent-Setup.exe /uninstall /quiet`.
   - **Zachowanie instalacji:** System.
   - **Reguła wykrywania:** istnieje klucz rejestru `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAIAgent`.
   - **Kody powrotu:** 0 oznacza sukces, pozostałe opisuje tabela powyżej.
3. Przypisz aplikację tylko do tego komputera. Najpierw przetestuj ją na jednym komputerze.

## 6. Usuwanie komputerów i dezinstalacja

- **Usuń komputer.** W Desktopie otwórz komputer w **Devices**, wybierz **Remove computer** i potwierdź. Jego dane uwierzytelniające zostają unieważnione, więc Agent nie może już przekazywać danych, a komputer znika z Devices, Risk i raportów; jego historia zostaje zachowana. Własnego Agenta komputera centralnego nie można usunąć.
- **Odinstaluj Agenta** na tym komputerze:
  - interaktywnie: **Ustawienia → Aplikacje → Zainstalowane aplikacje** (Windows 10: **Aplikacje i funkcje**) **→ SentinelAI Agent → Odinstaluj**;
  - po cichu: `"%ProgramFiles%\SentinelAI Agent\Setup\SentinelAI-Agent-Setup.exe" /uninstall /quiet`. Kod wyjścia 0 oznacza zakończenie, 10 oznacza, że dezinstalacja się nie zakończyła (uruchom ją ponownie), a 11, że nie znaleziono Agenta zainstalowanego przez instalator Agenta.

  Dezinstalacja usuwa usługę, pliki programu, dane i dane uwierzytelniające Agenta, wpis w Aplikacjach oraz zainstalowaną kopię instalatora. Gdy ta kopia sama wykonuje dezinstalację, zostaje przeniesiona do `%ProgramData%\SentinelAI-Setup`, a Windows usuwa ją przy następnym uruchomieniu komputera; foldery produktu znikają od razu, a nowa instalacja nie musi czekać.
- **Odinstaluj instalację centralną.**
  1. Zamknij Desktop.
  2. Otwórz **Ustawienia → Aplikacje → Zainstalowane aplikacje** (Windows 10: **Aplikacje i funkcje**) **→ SentinelAI → Odinstaluj**. Instalator otworzy się z zaznaczonym **Uninstall**; wybierz **Continue**, aby go wykonać.
  3. **Keep security history and protected configuration** jest domyślnie zaznaczone. Dezinstalacja usuwa wtedy usługi, regułę zapory, pliki programu i skrót, a zachowuje bazę, konfigurację i certyfikat Core. Późniejszy instalator z tej samej linii wydań przywraca instalację z tą samą tożsamością, a dotychczasowi Agenci znowu jej ufają.
  4. Aby usunąć także dane, odznacz to pole i wpisz **DELETE**. Usuwa to również certyfikat i klucz Core; dotychczasowi Agenci nie połączą się już nigdy.

  Konserwację może wykonać dowolne konto administratora Windows, nie tylko to, którym zainstalowano SentinelAI. Przycisk **Uninstall SentinelAI** w Desktopie, widoczny po zakończeniu pilotażu, otwiera ten sam proces w instalatorze i zamyka Desktop.

## 7. Klucz pilotażowy i jego wygaśnięcie

- Klucz to podpisany tekst, który przesyła dostawca. Zawiera nazwę firmy oraz daty początku i końca i jest weryfikowany bez połączenia z siecią na podstawie kluczy publicznych wbudowanych w to wydanie. Nie ma limitu komputerów ani powiązania z konkretną instalacją.
- Instalator prosi o niego podczas instalacji centralnej. Desktop → **Settings → Pilot license** pokazuje klienta, datę wygaśnięcia i liczbę pozostałych dni oraz przyjmuje nowy klucz, który przedłuża lub zastępuje obecny.
- Core sprawdza klucz przy wpisaniu i przy każdym odczycie stanu, korzystając z własnego zapisu czasu, więc cofnięcie zegara nie przedłuża pilotażu.
- Na siedem dni przed końcem Desktop pokazuje „Pilot ends in N days — contact us”. Po zakończeniu **całe monitorowanie działa dalej**, a Desktop pokazuje komunikat z danymi kontaktowymi dostawcy i przyciskiem **Uninstall SentinelAI**. Oba komunikaty można ukryć do wylogowania.
- Klucz pilotażowy nigdy nie wyłącza funkcji bezpieczeństwa i nie daje dostępu do funkcji w chmurze.

## 8. Aktualizacje i naprawa

- Nie ma automatycznych aktualizacji. Dostawca dostarcza nowszy `SentinelAI-Setup.exe` z tej samej linii wydań, podpisany tym samym kluczem.
- Aby **zaktualizować**, zamknij Desktop, uruchom nowszy instalator na komputerze centralnym i wybierz **Upgrade**. Instalator weryfikuje podpisaną paczkę, wymienia razem Core, Agenta komputera centralnego, Desktop i Updater, a jeśli nowa wersja nie uruchomi się poprawnie, automatycznie przywraca poprzednią. Dane, konto administratora, rejestracje, klucz pilotażowy i certyfikat Core zostają zachowane.
- Aby **naprawić**, uruchom instalator tej samej wersji i wybierz **Repair**. Odtwarza to także regułę zapory, jeśli została usunięta lub zmieniona.
- Starszy instalator pozwala tylko odinstalować; nie obniża wersji.
- Instalacja wykonana wcześniejszym instalatorem dawała też kontu Windows, które ją zainstalowało, pełną kontrolę nad folderami Core. Pierwsza aktualizacja, naprawa lub dezinstalacja, uruchomiona przez dowolnego administratora, usuwa ten dostęp.
- **Agentów na pozostałych komputerach** nie można w pilotażu zaktualizować w miejscu: instalator Agenta odrzuca komputer, na którym Agent już jest (kod wyjścia 7). Aby zainstalować nowszego Agenta:
  1. Odinstaluj starego Agenta.
  2. Zainstaluj nowy instalator Agenta z nowym kodem. Komputer pojawi się wtedy jako nowe urządzenie.
  3. Usuń stary wpis w Desktopie.

## 9. Rozwiązywanie problemów

**Agent nie może się połączyć (kod wyjścia 4 albo komputer przestaje się zgłaszać)**
- Na komputerze centralnym:
  - Desktop → **Settings → Local network** musi pokazywać, że Agenci mogą się łączyć.
  - Sieć musi być **prywatna** lub domenowa, a nie publiczna.
  - Reguła zapory `SentinelAI-Core-LocalNetwork` musi istnieć i być włączona. **Repair** ją odtwarza.
  - Port 5443 nie może być zajęty przez inny program. `netsh interface ipv4 show excludedportrange protocol=tcp` pokazuje zakresy zarezerwowane przez Windows. Core dalej działa lokalnie i zapisuje w dzienniku, że nasłuch sieciowy jest wyłączony; zwolnij port i uruchom ponownie usługę „SentinelAI Local Core”.
- Na komputerze z Agentem uruchom `Test-NetConnection <komputer centralny> -Port 5443`. Agent musi być w tej samej podsieci co komputer centralny.

**Niezgodne przypięcie (kod wyjścia 5)**
- Certyfikat komputera pod tym adresem nie jest tym z kodu. Albo kod należy do innej instalacji centralnej, albo instalację centralną zainstalowano ponownie z usunięciem danych, co tworzy nowy certyfikat.
- Utwórz nowe kody w Desktopie i sprawdź odcisk w **Settings → Local network**. Agentów zarejestrowanych ze starym certyfikatem trzeba odinstalować i zainstalować ponownie z nowym kodem.

**Zapora**
- Dozwolone są tylko profile domenowy i prywatny oraz podsieć lokalna. Zapora innego producenta na komputerze centralnym wymaga równoważnej reguły dla przychodzącego TCP 5443 z podsieci lokalnej do `SentinelAI.Core.exe`.

**Zmiana adresu IP**
- Agenci nadal używają adresu ze swojego kodu.
  - Kody z nazwą komputera działają dalej po zmianie adresu IP.
  - Kody z adresem IP przestają działać.
- Przywróć poprzedni adres, na przykład rezerwacją DHCP, albo zainstaluj ponownie Agentów, których to dotyczy, z nowymi kodami używającymi nazwy komputera.

**Inteligentna kontrola aplikacji, antywirus lub EDR blokuje instalator**
- Instalatory nie są podpisane cyfrowo.
  - Jeśli Inteligentna kontrola aplikacji (Smart App Control) jest włączona, Windows może je blokować, a ta funkcja nie ma wyjątku dla pojedynczego programu. W wielu wersjach Windows 11 nie da się jej ponownie włączyć bez reinstalacji systemu, więc wyłączaj ją świadomie albo użyj innego komputera.
  - W programach antywirusowych i EDR dopuść pliki po ich skrócie SHA-256 z `SHA256SUMS.txt`, zgodnie z polityką firmy.
- Instalator nie wyłącza kontroli aplikacji, trybu ograniczonego języka ani innych zabezpieczeń; jeśli go blokują, zgłasza niepowodzenie.

**Agent zgłasza dziennik Zabezpieczenia jako „access denied”**
- To oczekiwane. Agent działa jako LocalService, które nie może czytać dziennika Zabezpieczenia Windows, więc oparte na nim wykrycia (nieudane logowania i logowania przez Pulpit zdalny, tworzenie zaplanowanych zadań, wyczyszczenie dziennika Zabezpieczenia) nie działają w standardowej instalacji. Wykrycia z dzienników System, PowerShell i Microsoft Defender działają, z wyjątkiem dwóch, które odczytują angielskie teksty Windows i dlatego działają tylko w angielskim Windows: instalacji sterowników i zmiany sposobu uruchamiania usług ochrony.

## 10. Podsumowanie modelu bezpieczeństwa

- **Tylko lokalnie.** Dane zostają na komputerze centralnym. Core otwiera jeden port sieciowy, tylko dla Agentów, ograniczony do podsieci lokalnej i profili prywatnego i domenowego. Administracja jest dostępna wyłącznie na samym komputerze centralnym.
- **Silny, przypięty TLS.** TLS 1.3, a TLS 1.2 tylko na Windows 10, wyłącznie z AES-GCM. Agenci ufają Core tylko na podstawie dokładnego odcisku jego certyfikatu, a żaden urząd certyfikacji nie jest instalowany.
- **Jednorazowe kody rejestracyjne.**
  - Każdy kod jest ważny najwyżej 7 dni, a Core przechowuje tylko skrót jego tokenu.
  - Kody nigdy nie trafiają do dzienników, a instalator Agenta sprawdza przypięcie, zanim wyśle token.
  - Dane uwierzytelniające każdego Agenta są chronione przez DPAPI jego konta LocalService.
- **Najmniejsze uprawnienia.**
  - Agent działa jako LocalService i tylko odczytuje dane; zapisuje wyłącznie własny stan i nigdy nie zmienia ustawień Windows ani Waszych plików.
  - Core działa na własnym wirtualnym koncie usługi.
  - Foldery programu i danych są zapisywalne tylko dla Administratorów i SYSTEM, a dla każdej usługi tylko tam, gdzie zapisuje własny stan. Żaden folder nie daje osobnego dostępu kontu Windows, które zainstalowało SentinelAI, więc programy tego konta uruchomione bez podniesienia uprawnień nie mogą zmienić tego, co uruchamia Core lub Agent, a instalację może konserwować dowolny administrator.
- **Podpisane paczki.** Instalator weryfikuje podpis i skrót każdej paczki kluczem publicznym wbudowanym w instalator i wymienia kod programu transakcyjnie, z automatycznym wycofaniem zmian.
- **Dostęp administracyjny.** Desktop wymaga konta administratora SentinelAI utworzonego podczas instalacji.
- **Minimum danych.**
  - Zbierane są tylko stałe, wymienione wartości i pola zdarzeń.
  - Hasła, treść plików, treść skryptów i nazwy użytkowników nigdy nie są zbierane.
- **Licencja pilotażowa offline.** Licencja jest weryfikowana bez połączenia z siecią na podstawie kluczy publicznych; monitorowanie nigdy od niej nie zależy.
- **Ograniczenia.**
  - To oprogramowanie pilotażowe bez niezależnego audytu bezpieczeństwa i certyfikatów.
  - Instalatory nie są podpisane cyfrowo.
  - Zabezpieczenia zakładają, że administratorzy Windows komputera centralnego są zaufani.
