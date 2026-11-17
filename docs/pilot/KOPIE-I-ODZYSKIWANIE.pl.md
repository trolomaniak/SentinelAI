# Kopie i odzyskiwanie SentinelAI

Kopie obejmują bazę Core: konta aplikacji, urządzenia, obserwacje, alerty, decyzje, rejestr ryzyk, dane CVE i ustawienia. Archiwum zawiera też referencyjny opis połączenia. Odtwarzanie zachowuje zaufaną lokalną konfigurację instalacji.

## Włączenie kopii

1. Otwórz **Ustawienia → Szyfrowane kopie zapasowe i odzyskiwanie**.
2. Wpisz i powtórz hasło odzyskiwania, a następnie zapisz plik klucza `.sakey`. Anulowanie zapisu nie konfiguruje Core. Istniejący plik klucza nie zostanie zastąpiony.
3. Przechowuj ten plik oraz hasło w bezpiecznych miejscach dostępnych po utracie komputera centralnego.
4. Jawnie zapisz harmonogram i retencję. Domyślnie harmonogram jest wyłączony; proponowane wartości to co 24 godziny i siedem kopii. Zakres wynosi 1–168 godzin i 1–30 kopii.
5. Utwórz kopię ręcznie, sprawdź wynik weryfikacji i wyeksportuj zaszyfrowane archiwum `.sab` na osobny nośnik lub do kontrolowanego magazynu.

Do odzyskania potrzebne są **archiwum, pasujący plik klucza i hasło**. Kopie na tym samym dysku pomagają przy błędach danych. Ochrona przed utratą komputera wymaga także eksportu poza ten komputer. Retencja Core nie usuwa samodzielnie wyeksportowanych plików.

## Odtworzenie na tym samym komputerze

1. W razie potrzeby napraw zaufany kod instalacji, zachowując istniejące dane i certyfikat.
2. Otwórz odzyskiwanie Core z Ustawień albo ekranu logowania. Zatwierdź uprawnienia administratora Windows.
3. Wybierz archiwum i plik klucza, wpisz hasło i zweryfikuj punkt przywracania. Podgląd sprawdza pełną kopię przed zatrzymaniem usługi.
4. Sprawdź datę i organizację. Nowsze dane oraz decyzje mogą zostać utracone. Gdy bieżąca baza jest czytelna, proces zachowuje późniejsze unieważnienia Agentów, zabezpieczenia zegara licencji oraz dane operacyjne kopii.
5. Ponownie wpisz hasło i przepisz `RESTORE`. Proces zatrzyma własną usługę, zachowa kopię bezpieczeństwa, odtworzy bazę i sprawdzi uruchomiony Core.
6. Po sukcesie zaloguj się kontem z przywróconej bazy. Przejrzyj ustawienia i ponownie włącz harmonogram kopii.

Niewykorzystane kody dołączania są unieważniane. Lokalny certyfikat i pin, rejestracja usług oraz stan lokalnego Agenta pozostają na miejscu. Urządzenia dołączone dopiero po wykonaniu kopii mogą wymagać ponownej obsługi przez administratora.

Jeżeli operacja została przerwana, ponownie otwórz odzyskiwanie i odśwież stan. Przed kolejną próbą użyj opcji cofnięcia niedokończonego odtworzenia, sprawdzając jego punkt i wymagane słowo potwierdzenia. Pozostaw dziennik operacji i kopię bezpieczeństwa do obsługi przez program. Cofnięcie do uszkodzonej wcześniejszej bazy nie naprawi jej samoistnie.

## Przeniesienie na nowy komputer

1. Przygotuj świeżą centralną instalację SentinelAI z właściwym zaufaniem wydania i kluczem pilota.
2. Wykonaj migrację przed dołączaniem zdalnych Agentów i rozpoczęciem pracy. Nowa baza musi pochodzić z ostatnich 24 godzin, mieć jednego administratora, najwyżej własnego lokalnego Agenta oraz nie mieć skonfigurowanych kopii ani wcześniejszych decyzji biznesowych.
3. Wybierz tryb migracji, sprawdź archiwum, ponownie wpisz hasło i potwierdź przez `MIGRATE`.
4. Po udanym odtworzeniu zaloguj się kontem z kopii. Nowy komputer zachowa własną konfigurację i certyfikat. Jego lokalny Agent zostanie powiązany z odzyskaną organizacją.
5. Zainstaluj ponownie zdalnych Agentów, używając nowych kodów i nowego pinu. Ich wcześniejsze rekordy zachowują historię; nowe dołączenie tworzy nową tożsamość endpointu.

Certyfikat LAN ma nieeksportowalny klucz Windows. Zaufanie starego komputera nie przenosi się przez skopiowanie bazy. Podczas migracji poprzedni Core powinien pozostawać odłączony od sieci.

## Pojemność i wyniki

Pakiet jawny ma limit 1 GiB wraz z metadanymi. Tworzenie wymaga wolnego miejsca roboczego co najmniej sześciokrotnie większego niż snapshot bazy plus 64 MiB, oprócz miejsca na zachowane kopie i bieżącą bazę. Błędy miejsca, uprawnień, rozmiaru lub weryfikacji są widoczne w stanie operacji.

Weryfikacja dotyczy wskazanego czasu sprawdzenia. Można ją powtórzyć przed eksportem lub odtworzeniem. Kopie nieobecne na dysku są oznaczane osobno. Przywracanie i klucz odzyskiwania obsługuj jak dane administracyjne klienta.

Szczegóły formatu, interfejsów i testów: [Backup and recovery](../BACKUP-RECOVERY.md).
