# Pierwsze maile do firm (wewnętrzne)

Szablony do pozyskania pierwszych firm pilotażowych. Nie trafiają do wydania: skrypt wydania kopiuje tylko cztery dokumenty dla klienta. Pola w nawiasach kwadratowych uzupełnij przed wysłaniem. Wszystko, co obiecują te maile, musi zgadzać się z [SentinelAI dla firm](SentinelAI-dla-firm.pl.md); po każdej zmianie produktu sprawdź je ponownie.

## Zanim wyślesz

- **Zgoda na informację handlową.** W Polsce przesyłanie e-mailem informacji handlowej (marketingu bezpośredniego) bez wcześniejszej zgody odbiorcy jest zakazane, także między firmami (Prawo komunikacji elektronicznej oraz ustawa o świadczeniu usług drogą elektroniczną). Dlatego pierwszy mail tylko pyta o zgodę na przesłanie informacji, a opis pilotażu wysyłasz dopiero po odpowiedzi „tak”. Granica bywa różnie oceniana, więc przed większą wysyłką skonsultuj szablony z prawnikiem; to nie jest porada prawna.
- **Najpierw ciepłe kontakty.** Najbezpieczniej i najskuteczniej zaczynać od osób, które znasz, poleceń i firm, które same zostawiły kontakt (na przykład po rozmowie na wydarzeniu).
- **RODO.** Adres w rodzaju imie.nazwisko@firma.pl to dane osobowe. Pierwszy mail zawiera krótką informację o przetwarzaniu (stopka poniżej). Prowadź listę osób, które odmówiły lub nie odpowiedziały, i nie pisz do nich ponownie; ich adresy usuń w terminie podanym w stopce.
- **Jeden mail, jedna firma.** Pisz do konkretnej osoby, nie do listy. Bez śledzenia otwarć, bez załączników w pierwszym mailu i nigdy z instalatorem w załączniku.
- **Nie obiecuj więcej niż pilotaż.** Bez deklaracji zgodności (RODO, NIS2, ISO), bez „gwarancji bezpieczeństwa” i straszenia atakami. Bez wersji na Linuksa lub macOS, dostępu przez przeglądarkę czy zdalnej pomocy, których pilotaż nie ma.

## Do kogo pisać

Firmy z około 5–50 komputerami z Windows 10 22H2 lub Windows 11 (64-bit), w jednym biurze i jednej sieci, bez własnego zespołu bezpieczeństwa: z jedną osobą „od komputerów” albo z zewnętrzną firmą informatyczną. Na przykład:

- biura rachunkowe i kadrowo-płacowe (dane finansowe i osobowe klientów);
- kancelarie prawne, notarialne i doradców podatkowych;
- gabinety i małe przychodnie (dane o zdrowiu);
- biura projektowe, architektoniczne i agencje;
- małe firmy handlowe i produkcyjne z biurem;
- lokalne firmy informatyczne obsługujące małe firmy: jeden partner może przeprowadzić pilotaż u kilku swoich klientów.

Nie pasują: firmy bez komputera, który może pozostać włączony, z komputerami w wielu lokalizacjach lub łączącymi się przez VPN, z komputerami Mac lub Linux, a także firmy, w których Smart App Control lub polityka EDR nie pozwolą uruchomić niepodpisanego instalatora.

## Mail 1: pierwszy kontakt (prośba o zgodę)

**Temat (do wyboru):**
- Krótkie pytanie o komputery w [nazwa firmy]
- Czy mogę przesłać informację o bezpłatnym pilotażu?
- [Imię], pytanie od [Imię Nazwisko] z [miasto]

```text
Dzień dobry,

nazywam się [Imię Nazwisko] i tworzę w Polsce SentinelAI, program, który pokazuje małym firmom stan zabezpieczeń ich komputerów z Windows. Szukam kilku firm takich jak [nazwa firmy], które bezpłatnie wypróbują go u siebie i powiedzą mi szczerze, co o nim myślą.

Zanim cokolwiek prześlę, chcę zapytać: czy mogę wysłać krótką informację o pilotażu (jedna strona)? Wystarczy odpowiedzieć „tak”. Jeśli temat Państwa nie interesuje, wystarczy krótkie „nie” — nie napiszę ponownie.

Pozdrawiam
[Imię Nazwisko]
[Firma] · [telefon] · [strona internetowa]

---
Adres e-mail mam z [źródło, np. strony internetowej firmy]. Administratorem danych jest [Firma, adres]. Używam go tylko, aby zapytać o zgodę na przesłanie informacji; bez Państwa zgody usunę go w ciągu 30 dni. Mają Państwo prawo do dostępu do danych, ich usunięcia i sprzeciwu: [adres e-mail].
```

**Wariant dla biura rachunkowego** (zamiast pierwszego akapitu):

```text
nazywam się [Imię Nazwisko] i tworzę w Polsce SentinelAI, program, który w jednym miejscu pokazuje, czy komputery w biurze są dobrze zabezpieczone: czy dyski są zaszyfrowane, antywirus działa, a aktualizacje są instalowane. Biura rachunkowe przechowują dane wielu klientów, dlatego szukam kilku z nich, które bezpłatnie wypróbują program u siebie i powiedzą mi szczerze, co o nim myślą.
```

**Wariant dla firmy informatycznej (partnera):**

```text
nazywam się [Imię Nazwisko] i tworzę w Polsce SentinelAI, program, który pokazuje stan zabezpieczeń komputerów z Windows w małej firmie: jeden komputer centralny, mały Agent na każdym komputerze, dane zostają u klienta. Szukam firm informatycznych, które przeprowadzą bezpłatny pilotaż u jednego lub kilku swoich klientów i powiedzą mi, czego brakuje do codziennej pracy.
```

## Mail 2: jedno przypomnienie (opcjonalne, po 5–7 dniach roboczych, tylko bez odpowiedzi)

Przypomnienie to kolejna wiadomość bez zgody odbiorcy; wysyłaj je tylko wtedy, gdy zaakceptujesz to ryzyko po konsultacji prawnej.

**Temat:** Re: [temat maila 1]

```text
Dzień dobry,

wracam jeden raz do pytania z [data]: czy mogę przesłać krótką informację o bezpłatnym pilotażu SentinelAI? Jeśli nie, rozumiem i nie będę pisać ponownie.

Pozdrawiam
[Imię Nazwisko]
```

Po braku odpowiedzi na przypomnienie zakończ kontakt i usuń adres zgodnie ze stopką.

## Mail 3: informacja o pilotażu (po zgodzie)

**Temat:** SentinelAI — informacja o bezpłatnym pilotażu

```text
Dzień dobry,

dziękuję za zgodę. Krótko o pilotażu:

Czym jest SentinelAI
Program dla firm bez własnego zespołu bezpieczeństwa. Na jednym komputerze w firmie pokazuje, czy komputery z Windows są dobrze zabezpieczone i co wymaga uwagi:
- czy dyski są zaszyfrowane (BitLocker), antywirus i Microsoft Defender działają, a zapora jest włączona;
- czy aktualizacje Windows są instalowane i czy komputer czeka na ponowne uruchomienie;
- ryzykowne ustawienia, np. wyłączona Kontrola konta użytkownika, stary protokół SMB1 albo automatyczne logowanie;
- podejrzane zdarzenia, np. znalezienie złośliwego oprogramowania, wyłączenie Defendera, wyczyszczenie dziennika zdarzeń, powtarzające się nieudane logowania;
- znane podatności w popularnych programach i w Windows, na podstawie dostarczanych przez nas danych;
- ocenę ryzyka każdego komputera z wyjaśnieniem, alerty z zalecanym działaniem, rejestr ryzyk firmy i raport za wybrany okres.
Nie zastępuje antywirusa: sprawdza, czy ochrona, którą Państwo już mają, jest włączona i działa. Agent na komputerach tylko odczytuje dane i niczego nie zmienia.

Dane zostają w firmie
Wszystko jest przechowywane na komputerze centralnym w Państwa sieci. Nic nie jest wysyłane do nas ani do chmury. Program i raporty są po polsku.

Warunki pilotażu
- bezpłatnie, zwykle przez 30–90 dni, bez limitu komputerów i bez zobowiązań;
- potrzebny jest komputer, który pozostaje włączony, Windows 10 22H2 lub Windows 11 (64-bit) na każdym komputerze i wszystkie komputery w jednej sieci lokalnej;
- w zamian proszę o dwie krótkie rozmowy: po pierwszym tygodniu i pod koniec pilotażu;
- po zakończeniu monitorowanie działa dalej; program można w każdej chwili odinstalować, a dane zostają, dopóki sami ich nie usuną.

Uczciwie: to wersja pilotażowa. Nie przeszła jeszcze niezależnego audytu bezpieczeństwa, a instalatory nie są podpisane cyfrowo, więc Windows wyświetli ostrzeżenie SmartScreen. Szczegóły i ograniczenia opisuje dokument „SentinelAI dla firm”: [link].

Jeśli to brzmi interesująco, proponuję 20-minutową rozmowę, żeby sprawdzić, czy SentinelAI pasuje do Państwa firmy: [dwa–trzy terminy] albo [link do kalendarza].

Pozdrawiam
[Imię Nazwisko]
[Firma] · [telefon] · [strona internetowa]
```

## Mail 4: przed instalacją (po rozmowie)

**Temat:** SentinelAI — przygotowanie do instalacji [data]

```text
Dzień dobry,

dziękuję za rozmowę. Przed instalacją [data, godzina] proszę przygotować:

1. Komputer centralny, który pozostanie włączony, z Windows 10 22H2 lub Windows 11 (64-bit), ze stałym adresem IP (np. rezerwacją DHCP) albo nazwą, którą znajdą pozostałe komputery.
2. Ustawienie sieci firmowej w Windows na „prywatną” (nie „publiczną”) na komputerze centralnym.
3. Konto administratora Windows na każdym komputerze, który chcą Państwo dodać, i listę tych komputerów.
4. Wolny port TCP 5443 na komputerze centralnym (przewodnik IT opisuje, jak to sprawdzić).

Pliki instalacyjne i sumy kontrolne SHA-256 są tutaj: [link do strony pobierania]. Przed uruchomieniem proszę sprawdzić sumę kontrolną — instrukcję zawiera przewodnik IT: [link]. Nie wysyłam instalatorów w załącznikach.

Klucz pilotażowy prześlę osobnym mailem w dniu instalacji. Szczegóły techniczne dla osoby od IT: [link do przewodnika IT].

Pozdrawiam
[Imię Nazwisko]
```

**Osobny mail z kluczem** (w dniu instalacji): krótki tekst z kluczem z `tools/pilot-license issue --customer "<firma>" --days <dni>` i datą końca pilotażu. Bez innych danych w tym samym mailu.

## Mail 5: przed końcem pilotażu (około 7 dni przed końcem)

**Temat:** SentinelAI — pilotaż kończy się [data]

```text
Dzień dobry,

pilotaż SentinelAI kończy się [data]. Monitorowanie będzie działać dalej, a Desktop wyświetli prośbę o kontakt.

Bardzo pomoże mi odpowiedź na pięć pytań (wystarczą krótkie zdania albo rozmowa [termin]):
1. Co było najbardziej przydatne?
2. Co było niezrozumiałe albo zbędne?
3. Czy coś ważnego zostało pominięte?
4. Czy instalacja i codzienne korzystanie były proste?
5. Czy chcieliby Państwo korzystać z SentinelAI dalej i na jakich warunkach?

Jeśli chcą Państwo kontynuować, prześlę nowy klucz, który przedłuży pilotaż. Jeśli nie, program można odinstalować w Ustawieniach Windows → Aplikacje (opis w przewodniku IT); dane zostają na komputerze centralnym, dopóki sami ich nie usuną.

Dziękuję za pomoc
[Imię Nazwisko]
```

## Krótkie odpowiedzi na częste pytania

- **„Czy widzicie nasze dane?”** Nie. Wszystko zostaje na komputerze centralnym w Państwa sieci; program nic do nas nie wysyła.
- **„Czy to spowolni komputery?”** Agent tylko odczytuje ustawienia i wybrane zdarzenia Windows i przesyła niewielkie ilości danych do komputera centralnego.
- **„Czy to zastępuje antywirusa?”** Nie. Sprawdza, czy antywirus i inne zabezpieczenia są włączone i działają.
- **„Czy to zapewnia zgodność z RODO lub NIS2?”** Nie deklarujemy zgodności z żadnymi normami ani przepisami. Program pomaga zobaczyć stan zabezpieczeń komputerów; ocenę zgodności robi się osobno.
- **„Ile to będzie kosztować po pilotażu?”** [Uzupełnij przed wysyłką; do czasu decyzji: „Pilotaż jest bezpłatny i nie zobowiązuje. Warunki dalszego korzystania ustalimy razem, także na podstawie Państwa opinii.”]
- **„Dlaczego Windows ostrzega przed instalatorem?”** Instalatory pilotażu nie są jeszcze podpisane cyfrowo, więc SmartScreen pokazuje nieznanego wydawcę. Dlatego zawsze sprawdzamy plik po sumie kontrolnej SHA-256 z naszej strony.
