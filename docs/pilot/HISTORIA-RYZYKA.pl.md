# Historia ryzyka i trendy

W Desktop otwórz **Ryzyko**. Wybierz organizację lub urządzenie, a następnie okres 24 godziny, 7, 30 albo 90 dni. Wykres pokazuje rzeczywiście zapisane punkty. W tabeli znajdziesz czas pomiaru, wynik wyświetlany, wynik surowy przed limitem 100, politykę i zaobserwowane zmiany względem poprzedniego pomiaru.

Core zapisuje najwyżej jeden pomiar w każdym sześciogodzinnym przedziale UTC. Przerwy w pracy usługi pozostawiają luki. Jeśli w wybranym okresie brak pomiarów, aplikacja pokazuje pustą historię. Najnowsza ocena w widoku Ryzyka jest obliczana osobno.

Zmiana statusu alertu, odnowienie obserwacji, jej wiek, polityka i kontekst mogą wpłynąć na wynik. Opis pokazuje rozpoznane zmiany danych wejściowych. Zapisany status rozwiązania sam nie weryfikuje naprawy. Jeśli dostępne dane nie wyjaśniają różnicy, opis pozostaje nieustalony. Zmiana polityki nie przelicza wcześniejszych wyników.

Historia jest przechowywana do 90 dni i do 250 000 punktów urządzeń. Po osiągnięciu limitu Core usuwa najstarsze kompletne pomiary floty. Raport pokazuje zapisane pomiary organizacji z wybranego okresu osobno od oceny bieżącej. [Szczegóły pomiaru i API](../RISK-HISTORY.md).
