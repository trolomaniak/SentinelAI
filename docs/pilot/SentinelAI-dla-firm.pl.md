# SentinelAI dla Twojej firmy

*Wersja pilotażowa. Wersja angielska: [SentinelAI for business](SentinelAI-for-business.en.md). Szczegóły techniczne dla działu IT: [przewodnik IT](SentinelAI-przewodnik-IT.pl.md).*

## Czym jest SentinelAI

SentinelAI pilnuje bezpieczeństwa komputerów z Windows w małej firmie i w jednym miejscu pokazuje, co wymaga uwagi. Odpowiada na pytania takie jak: czy dysk jest zaszyfrowany? Czy antywirus działa poprawnie? Czy aktualizacje automatyczne są włączone i kiedy ostatnio zainstalowano aktualizacje? Czy komputer czeka na ponowne uruchomienie? Czy Microsoft Defender znalazł złośliwe oprogramowanie? Który komputer jest teraz największym ryzykiem?

Jest przeznaczony dla firm bez własnego zespołu bezpieczeństwa. Nie zastępuje antywirusa: sprawdza, czy ochrona, którą już macie, jest włączona i działa, oraz wskazuje ryzykowne ustawienia i podejrzane zdarzenia.

## Co monitoruje

Działa dziś tylko to, co jest wymienione poniżej:

- **Urządzenia i oprogramowanie:** nazwa komputera, wersja Windows, procesor, pamięć, dyski oraz lista aplikacji zainstalowanych dla całego komputera (nazwa, wersja, wydawca).
- **BitLocker:** czy dysk systemowy Windows jest zaszyfrowany i chroniony.
- **Antywirus i Microsoft Defender:** stan antywirusa zgłaszany przez Zabezpieczenia Windows oraz ochrona w czasie rzeczywistym i ochrona przed naruszeniami w Defenderze, a także wiek jego sygnatur.
- **Zapora Windows:** czy każdy profil zapory jest włączony i czy usługa zapory działa.
- **Windows Update:** ustawienie aktualizacji automatycznych oraz kiedy ostatnio wyszukano i zainstalowano aktualizacje.
- **Oczekujące ponowne uruchomienie:** czy Windows czeka na restart, aby dokończyć aktualizacje.
- **Ryzykowne ustawienia:** na przykład wyłączona Kontrola konta użytkownika (UAC), Pulpit zdalny bez uwierzytelniania na poziomie sieci, stary protokół udostępniania plików SMB1, automatyczne logowanie oraz konta lokalnych administratorów.
- **Wykrywanie zdarzeń bezpieczeństwa:** na przykład znalezienie złośliwego oprogramowania przez Microsoft Defender albo jego wyłączenie, wyczyszczenie dziennika zdarzeń, instalacja usługi lub sterownika z nietypowego miejsca, podejrzany skrypt oznaczony przez PowerShell. Obejmuje to wykrycia z dziennika Zabezpieczenia Windows (powtarzające się nieudane logowania, ryzykowne logowania przez Pulpit zdalny, nowe zaplanowane zadania i wyczyszczenie dziennika Zabezpieczenia): instalator daje Agentowi prawo tylko do odczytu tego dziennika i włącza w Windows inspekcję tworzenia zaplanowanych zadań, a odinstalowanie cofa obie zmiany. Wykrycia działają w Windows w każdym języku, także polskim.
- **Ocena ryzyka:** każdy komputer dostaje ocenę od 0 do 100 z wyjaśnieniem, a ocena firmy to ocena jej najbardziej zagrożonego komputera.
- **Alerty i incydenty:** każde ustalenie staje się alertem z dowodami i zalecanym działaniem. Oznaczacie go jako badany, zaakceptowany lub rozwiązany.
- **Raporty:** raport bezpieczeństwa za wybrany okres, zapisywany jako plik HTML.

Alerty powstają dla ryzykownych ustawień i wykryć. Pozostałe wartości, takie jak oczekujące ponowne uruchomienie, szczegóły Defendera i lokalni administratorzy, Desktop pokazuje do przejrzenia.

## Jak to działa

- **Jeden komputer centralny** w firmie uruchamia SentinelAI: usługę centralną (Core), aplikację Desktop, w której widać wszystko, oraz własnego Agenta.
- **Każdy pozostały komputer** ma tylko małego Agenta SentinelAI, który przekazuje dane do komputera centralnego przez sieć lokalną.
- **Dane zostają w Twojej firmie.** Wszystko jest przechowywane na komputerze centralnym. SentinelAI nie wysyła danych do nas ani do żadnej usługi w chmurze, a wersja pilotażowa nie łączy się z internetem.

## Co jest zbierane, a co nie

**Zbierane:** informacje o urządzeniach, ustawieniach i stanie zabezpieczeń wymienione wyżej, nazwy, wersje i wydawcy zainstalowanych aplikacji oraz stała lista zdarzeń Windows (z dzienników System, PowerShell i Microsoft Defender), tylko z polami potrzebnymi do wykrywania. Konta użytkowników pojawiają się wyłącznie jako identyfikatory techniczne (SID), nigdy jako nazwy.

**Niezbierane:** hasła ani inne dane uwierzytelniające, klucze odzyskiwania BitLocker, treść plików, dokumentów i wiadomości e-mail, historia przeglądarki, treść skryptów PowerShell, teksty komunikatów zdarzeń, nazwy użytkowników, grup i domen oraz aplikacje zainstalowane tylko dla jednego użytkownika lub ze Sklepu Microsoft.

## Warunki pilotażu

- **Bezpłatnie** w okresie pilotażu.
- **Na czas określony:** klucz pilotażowy jest ważny przez uzgodniony okres, zwykle od 30 do 90 dni. Desktop pokazuje, ile dni zostało, i przypomina o końcu na siedem dni wcześniej.
- **Bez limitu** liczby komputerów.
- **Po zakończeniu pilotażu:** całe monitorowanie działa dalej. Desktop wyświetla komunikat z prośbą o kontakt i naszymi danymi kontaktowymi oraz przycisk **Uninstall SentinelAI**. Odinstalowanie zachowuje dane, chyba że wyraźnie wybierzecie ich usunięcie. Nowy klucz w każdej chwili przedłuża pilotaż.

## Wymagania

- Windows 10 w wersji 22H2 (64-bitowy) lub Windows 11 (64-bitowy) na każdym komputerze.
- Jeden komputer centralny, który pozostaje włączony, ze stałym adresem IP albo nazwą, którą pozostałe komputery potrafią znaleźć.
- Wszystkie komputery w tej samej sieci lokalnej (tej samej podsieci), a w Windows ustawiona sieć **prywatna** lub domenowa, nie **publiczna**.
- Konto administratora Windows do instalacji na każdym komputerze.

## Jak zacząć w trzech krokach

1. **Zainstaluj na komputerze centralnym.** Pobierz pliki, sprawdź je zgodnie z przewodnikiem IT, uruchom `SentinelAI-Setup.exe`, wpisz klucz pilotażowy i utwórz konto administratora SentinelAI.
2. **Dodaj pozostałe komputery.** W Desktopie otwórz **Devices → Add computers** i utwórz po jednym kodzie na komputer. Na każdym komputerze uruchom `SentinelAI-Agent-Setup.exe` i wklej jego kod.
3. **Przejrzyj wyniki.** W Desktopie zobacz **Devices**, **Alerts** i **Risk**, a w **Reports** wygeneruj raport.

## Uczciwie o ograniczeniach

- **To oprogramowanie pilotażowe.** Jest testowane automatycznie na Windows, w tym przez rzeczywiste instalacje w naszym systemie budowania, ale nie jest jeszcze używane w wielu firmach. Nie przeszło niezależnego audytu bezpieczeństwa i nie deklarujemy zgodności z żadnymi normami ani certyfikatów.
- **Instalatory nie są podpisane cyfrowo.** Windows SmartScreen ostrzeże, że wydawca jest nieznany. Przed uruchomieniem zawsze sprawdzaj pobrane pliki z opublikowanymi sumami kontrolnymi SHA-256. Inteligentna kontrola aplikacji (Smart App Control) lub niektóre programy antywirusowe i EDR mogą blokować niepodpisane programy.
- **Tylko Windows.** Nie ma jeszcze wersji dla Linuksa ani macOS.
- **Desktop tylko na komputerze centralnym.** Alerty i raporty ogląda się tam; nie ma dostępu przez przeglądarkę ani telefon.
- **Brak automatycznych aktualizacji.** Nowe wersje dostarczamy my: uruchamiacie je na komputerze centralnym, a Agentów na pozostałych komputerach instaluje się ponownie z nowymi kodami.
- **Interfejs po angielsku.** Sam program jest w języku angielskim.

## Kontakt

[Nazwa firmy] · [adres e-mail] · [numer telefonu] · [strona internetowa]

## Najczęstsze pytania

**Czy SentinelAI spowolni nasze komputery?** Agent odczytuje stały zestaw ustawień i zdarzeń: krótki komunikat o stanie co 30 sekund, inwentarz urządzenia co sześć godzin i w ciągu kilku sekund po zmianie monitorowanego ustawienia, stan zabezpieczeń co godzinę, a nowe zdarzenia na bieżąco.

**Czy SentinelAI coś zmienia na naszych komputerach?** Agent tylko odczytuje; nigdy nie zmienia ustawień Windows ani Waszych plików. Zmianę ustawienia lub usunięcie zagrożenia zawsze wykonujecie sami. Sam instalator zmienia tylko to, czego wymaga monitorowanie: regułę zapory na komputerze centralnym, a na każdym komputerze prawo Agenta do odczytu dziennika Zabezpieczenia i inspekcję tworzenia zaplanowanych zadań. Odinstalowanie cofa te zmiany.

**Czy widzicie nasze dane?** Nie. Wszystko zostaje na Waszym komputerze centralnym i nic nie jest do nas wysyłane.

**Co jeśli komputer centralny jest wyłączony?** Agenci próbują się z nim łączyć i znowu przekazują dane, gdy wróci. Desktop pokazuje, kiedy każdy komputer ostatnio się zgłosił.

**Co się stanie po zakończeniu pilotażu?** Monitorowanie działa dalej. Desktop prosi o kontakt i oferuje odinstalowanie.

**Jak usunąć SentinelAI?** Usuń każdy komputer w Desktopie i odinstaluj **SentinelAI Agent** w **Ustawienia → Aplikacje** systemu Windows. Na komputerze centralnym odinstaluj SentinelAI w ten sam sposób; dane zostają, chyba że wpiszesz **DELETE**, aby je usunąć.
