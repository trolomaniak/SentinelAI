# Pokrycie monitoringu

W Desktop otwórz **Pokrycie monitoringu**. Włącz **Tylko problemy z monitoringiem**, aby znaleźć komputery z brakiem lub nieaktualnością danych, ograniczonym dostępem do źródeł, przerwą w łączności albo zachowaną luką. Wybierz urządzenie, aby zobaczyć szczegóły telemetrii, kanałów zdarzeń i historię luk.

Heartbeat pokazuje, kiedy Core ostatnio odebrał sygnał od urządzenia. Jego wiek nie określa świeżości pozostałych danych. Inwentaryzacja domyślnie pozostaje aktualna przez 12 godzin, telemetria przez 3 godziny, a status kanału zdarzeń przez 2 godziny od odbioru. Datę z przyszłości interfejs wskazuje osobno, ponieważ wieku takiego raportu nie można potwierdzić.

Czytaj stan źródła razem ze świeżością. Ostatni odczyt mógł być udany, ale nieaktualny. Świeży raport może wskazywać między innymi brak uprawnień, wyłączony dziennik albo źródło nieobsługiwane na tym urządzeniu. Osobne wiersze pokazują stan antywirusa Defender i stan jego dziennika zdarzeń.

Historia ciągłości pokazuje czas wykrycia, czas odbioru i zakres identyfikatorów rekordów. Pierwsze rozpoczęcie odczytu wyznacza granicę dostępnej historii. Ponowne rozpoczęcie po utracie lub zmianie punktu odczytu może pozostawić lukę. Zakres rekordów nie pozwala ustalić dokładnej długości przerwy. Pusta historia oznacza brak zachowanych informacji o lukach w wyświetlanym okresie.

Szczegóły progów, retencji i API znajdziesz w [Monitoring coverage](../MONITORING-COVERAGE.md).
