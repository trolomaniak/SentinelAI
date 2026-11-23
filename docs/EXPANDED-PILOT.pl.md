# Plan rozbudowanego pilota SentinelAI

Zakres zatwierdzony przez właściciela: realizacja kolejno, od backupu i odzyskiwania. Plan rozpoczął się po PR #55: poprawki raportów, warunków CVE i SQLite oraz historia Defendera. Ta lista jest planem; nie oznacza dostarczenia wszystkich funkcji.

| Kolejność | Obszar | Wynik dla użytkownika | Stan |
| --- | --- | --- | --- |
| 1 | Backup i odzyskiwanie | Szyfrowane kopie, harmonogram, retencja, eksport, weryfikacja i sprawdzone odtworzenie | Scalone w PR #56. Testy lokalne i Windows przeszły |
| 2 | Powiadomienia bezpieczeństwa | Krytyczne wykrycia, utrata monitoringu, grupowanie, opcjonalny e-mail/webhook i historia dostarczenia | W realizacji |
| 3 | Pokrycie monitoringu | Dostępność źródeł, luki i wiek danych każdego urządzenia | Zaplanowane |
| 4 | Pulpit operacyjny Overview | Problemy wymagające działania, zmiany i stan pracy administratora | Zaplanowane |
| 5 | Historia i trendy | Snapshoty, wersja polityki, przyczyny zmian, okresy 7/30/90 dni | Zaplanowane |
| 6 | Katalog oprogramowania | Wyszukiwanie aplikacji w firmie, wersje i historia zmian | Zaplanowane |
| 7 | Centrum podatności | CVE i produkty w skali firmy, dotknięte urządzenia i priorytety aktualizacji | Zaplanowane |
| 8 | Obsługa zagrożeń Defendera | Chronologia jednego wykrycia oraz powiązanie z alertem i sprawą | Zaplanowane |
| 9 | Sprawy i zadania naprawcze | Właściciel, terminy, komentarze i powiązane ustalenia | Zaplanowane |
| 10 | Weryfikacja napraw | Oddzielenie deklaracji operatora od potwierdzenia świeżymi danymi | Zaplanowane |
| 11 | Profile i wyjątki | Wymagania dla grup urządzeń, uzasadnienie i wygaśnięcie odstępstw | Zaplanowane |
| 12 | Aktualizacje i restarty | Faktycznie brakujące poprawki, błędy, wiek restartu i plan prac | Zaplanowane |
| 13 | Konta, role i MFA | Osobne tożsamości techników, uprawnienia i bezpieczeństwo sesji | Zaplanowane |
| 14 | Audyt i diagnostyka | Historia operacji oraz kontrolowany pakiet dla wsparcia | Zaplanowane |
| 15 | Zarządzanie flotą | Grupy, właściciele, krytyczność, wdrożenia i utrzymanie całego Agenta | Zaplanowane |
| 16 | Raport efektów pilota | Raport techniczny i kierowniczy, potwierdzone poprawy i porównanie okresów | Zaplanowane |
| 17 | Dodatkowe kontrole Windows | Wybrane ASR, Secure Boot, TPM, Credential Guard, definicje Defendera i zmiany lokalnych administratorów | Zaplanowane |
| 18 | Kontrolowane działania i integracje | Zamknięty katalog autoryzowanych poleceń, wynik i audyt; integracje ze zgłoszeniami | Zaplanowane |

Zależności mogą wymagać wspólnych podstaw technicznych, np. tożsamości przed przydzielaniem uprawnień do działań. Takie podstawy należy opisać w zadaniu i zachować rozdział między funkcją już dostarczoną a planowaną. Każdy etap obejmuje polski i angielski interfejs, testy odpowiadające ryzyku zmiany oraz aktualizację dokumentacji.

Backup przechowywany na komputerze centralnym pomaga przy błędach danych. Ochrona przed utratą tego komputera wymaga także wyeksportowanego archiwum oraz osobnego pliku klucza odzyskiwania. Certyfikat LAN obecnej instalacji jest nieprzenośny; scenariusz migracji musi jawnie obsłużyć nowe zaufanie Agentów.
