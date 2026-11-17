# Powiadomienia bezpieczeństwa

Otwórz **Powiadomienia** w Desktop. Zobaczysz nowe, ponownie otwarte lub eskalujące alerty krytyczne oraz utratę i odzyskanie świeżych heartbeatów urządzeń. Powtarzające się obserwacje są grupowane. Centrum działa w Core również po zamknięciu Desktop.

1. Ustaw kategorie, próg braku heartbeatów (5–120 minut) i okno grupowania (1–60 minut).
2. Domyślnie e-mail i webhook są wyłączone. Do lokalnego centrum nie potrzebujesz integracji.
3. Jeśli chcesz wysyłkę, podaj publiczny adres HTTPS na porcie 443 lub serwer SMTP na porcie 587 z STARTTLS oraz kontem i hasłem. Włącz wybrany kanał i zapisz ustawienia. Program nie wysyła automatycznej wiadomości testowej.
4. Puste pola wymiany zachowują zapisane dane. Pełny adres webhooka, sekret podpisu i hasło SMTP są chronione przez Windows i nie wracają do interfejsu. Do ich usunięcia służy jawna opcja wyczyszczenia.
5. Sprawdzaj historię dostarczenia. Sukces oznacza przyjęcie przez serwer, a nie przeczytanie wiadomości. Po błędzie możliwe są ponowienia i duplikaty; odbiornik webhooka powinien rozpoznawać identyfikator powiadomienia.

Wysyłane dane obejmują rodzaj zdarzenia, identyfikatory, regułę, wagę, liczbę wystąpień i czas. Nie obejmują nazw komputerów, kont użytkowników ani surowych dowodów. SMTP wymaga obsługi uwierzytelniania hasłem PLAIN lub LOGIN przez TLS; OAuth, port 465 i serwery w prywatnej sieci nie są obsługiwane.

Brak heartbeatów nie dowodzi włamania ani wyłączenia komputera. Core nie może wysłać wiadomości podczas awarii własnego komputera lub jego połączenia. Centrum zachowuje do 10 000 powiadomień z docelową retencją 30 dni; najstarsze wpisy i ich kolejka mogą zostać usunięte przy osiągnięciu limitu.

Po odtworzeniu kopii lub migracji wysyłka jest wyłączana, dane dostępowe usuwane, a oczekujące wiadomości anulowane. Ponownie skonfiguruj i włącz kanały po sprawdzeniu odzyskanej instalacji. Szczegóły protokołu i ograniczeń: [Security notifications](../NOTIFICATIONS.md).
