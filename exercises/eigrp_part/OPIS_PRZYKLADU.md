# Nierównomierne równoważenie obciążenia w P4

Ten przykład pokazuje prostą implementację nierównomiernego równoważenia obciążenia, podobnego do mechanizmu EIGRP unequal-cost load balancing. Pakiety do tej samej sieci docelowej mogą być wysyłane kilkoma trasami, ale trasy o niższym koszcie dostają większy udział ruchu.

Całość składa się z trzech głównych części:

- programu P4 `load_balance.p4`, który wykonuje forwarding w przełącznikach,
- kontrolera `mycontroller.py`, który oblicza trasy i wpisuje reguły do tablic P4,
- skryptów `send.py` i `receive.py`, które służą do testowania rozkładu ruchu.

## Deklarowanie topologii i metryk

Topologia Minineta jest opisana w plikach `topology.json` oraz `topology_4.json`. Te pliki mówią, jakie hosty i przełączniki istnieją oraz jak są połączone portami.

Przykładowo `topology.json` opisuje topologię trójkąta:

```text
h1 -- s1 -- s2 -- h2
       \   /
        s3 -- h3
```

Osobno zdefiniowane są metryki tras. Kontroler nie korzysta bezpośrednio z listy linków Minineta, tylko z pliku metryk:

- dla `topology.json` używany jest `topology_metrics_4.json`,
- dla `topology_4.json` używany jest `topology_metrics.json`.

W pliku metryk znajdują się między innymi:

```json
{
  "from": "s1",
  "to": "s2",
  "from_port": 2,
  "metric": 10,
  "next_hop_mac": "08:00:00:00:02:02"
}
```

Taki wpis oznacza, że ze switcha `s1` można iść do `s2` przez port `2`, koszt tego linku wynosi `10`, a ramka Ethernet powinna dostać adres MAC następnego skoku `08:00:00:00:02:02`.

Metryki są kierunkowe. Jeżeli ruch ma działać w obie strony, potrzebne są osobne wpisy dla obu kierunków, na przykład `s1 -> s2` i `s2 -> s1`.

Dla każdego switcha można też ustawić parametr `variance`:

```json
"s1": {
  "variance": 4
}
```

`variance` określa, jak bardzo droższa trasa może być jeszcze użyta. Jeżeli najkrótsza trasa ma koszt `10`, a `variance` wynosi `4`, to kontroler może użyć tras o koszcie do `40`.

## Określanie dostępnych tras

Kontroler buduje graf sieci z wpisów `link_metrics`. Każdy switch jest wierzchołkiem, a każdy wpis metryki jest skierowaną krawędzią.

Dla każdej pary:

```text
switch źródłowy -> sieć docelowa
```

kontroler szuka wszystkich prostych tras, czyli takich, które nie zawierają pętli. Robi to funkcja `find_all_paths`, używając prostego BFS.

Przykład dla ruchu z `s1` do sieci przy `s2` w topologii trójkąta:

```text
s1 -> s2
s1 -> s3 -> s2
```

Następnie kontroler:

1. liczy całkowity koszt każdej trasy,
2. dla każdego portu wyjściowego zostawia najlepszą trasę,
3. znajduje najkrótszą trasę,
4. odrzuca trasy droższe niż `variance * najkrótszy_koszt`,
5. przelicza metryki na udział w ruchu.

Udział jest liczony odwrotnie proporcjonalnie do metryki. Niższa metryka oznacza większy udział. Kontroler zamienia ten udział na liczbę slotów w tablicy `ucmp_nhop`.

Przykład:

```text
trasa A: koszt 10
trasa B: koszt 20
```

Trasa A powinna dostać około dwa razy więcej ruchu niż trasa B.

Kontroler wypisuje też informację, jaki udział dostała dana trasa, na przykład:

```text
s1 to 10.0.2.0/24: s1 -> s2 gets 5/8 slots (62.5%)
s1 to 10.0.2.0/24: s1 -> s3 -> s2 gets 3/8 slots (37.5%)
```

## Zapis tras do tablic P4

Program P4 ma dwie najważniejsze tablice w ingressie:

```p4
table ucmp_select
```

oraz

```p4
table ucmp_nhop
```

Pierwsza tablica, `ucmp_select`, wybiera zakres slotów dla danej sieci docelowej. Reguła mówi na przykład:

```text
dla 10.0.2.0/24 użyj slotów od 60, razem 8 slotów
```

Druga tablica, `ucmp_nhop`, mówi, co oznacza konkretny slot:

```text
slot 60 -> wyślij portem 2 do s2
slot 61 -> wyślij portem 2 do s2
slot 62 -> wyślij portem 3 do s3
...
```

Jeżeli jedna trasa ma dostać większy udział ruchu, kontroler wpisuje ją do większej liczby slotów.

Dodatkowo kontroler programuje tablicę egressową:

```p4
table send_frame
```

Ta tablica ustawia źródłowy adres MAC ramki wychodzącej z danego portu switcha.

## Jak działa hashowanie i wybór indeksu

W `load_balance.p4` akcja `set_ucmp_select` wylicza indeks następnego skoku:

```p4
hash(meta.nhop_select,
     HashAlgorithm.crc16,
     base,
     { ... pola pakietu ... },
     total_weight);
```

Wynik trafia do `meta.nhop_select`. Jest to indeks slotu używany potem w tablicy `ucmp_nhop`.

Znaczenie parametrów jest następujące:

- `base` - początek zakresu slotów dla danej sieci docelowej,
- `total_weight` - liczba slotów przydzielonych tej sieci,
- pola pakietu - dane użyte do wyliczenia hasha.

Dla TCP hash używa między innymi:

- adresu IP źródłowego,
- adresu IP docelowego,
- protokołu,
- TTL,
- portu TCP źródłowego,
- portu TCP docelowego,
- numerów sekwencyjnych TCP.

W `send.py` port źródłowy TCP jest losowany dla każdego pakietu. Dzięki temu kolejne pakiety mogą trafić w różne sloty, a więc w różne trasy.

Przykład:

```text
sloty 0-4  -> trasa s1 -> s2
sloty 5-7  -> trasa s1 -> s3 -> s2
```

Jeżeli hash zwróci slot `2`, pakiet pójdzie pierwszą trasą. Jeżeli zwróci slot `6`, pakiet pójdzie drugą trasą.

To nie jest round-robin. Decyzja zależy od hasha pól pakietu. Przy większej liczbie pakietów rozkład powinien zbliżać się do udziałów zaprogramowanych przez kontroler.

## Śledzenie trasy pakietu

Program P4 zapisuje odwiedzone switche w polu IPv4 `identification`. Każdy switch dopisuje swój numer do tego pola.

Przykład:

```text
s1 -> s3 -> s2
```

może zostać zakodowane jako kolejne identyfikatory switchy. Skrypt `receive.py` odczytuje `IP.id`, dekoduje numery switchy i wypisuje trasę pakietu.

Dzięki temu na hoście odbierającym można zobaczyć, którędy faktycznie szły pakiety i czy ruch rozkłada się zgodnie z oczekiwaniami.

## Uruchomienie: topologia trójkąta

Pierwszy scenariusz używa `topology.json`. Jest to topologia trzech switchy w kształcie trójkąta. Testujemy ruch:

```text
10.0.1.1 -> 10.0.2.2
```

czyli z hosta `h1` do hosta `h2`.

### 1. Uruchom Mininet

W katalogu przykładu:

```bash
make run
```

Domyślnie `Makefile` używa pliku:

```text
topology.json
```

### 2. Uruchom kontroler

W osobnym terminalu, w tym samym katalogu:

```bash
./mycontroller.py topology_metrics_4.json
```

Ten plik metryk odpowiada topologii trójkąta z hostami w sieciach `10.0.1.0/24`, `10.0.2.0/24` i `10.0.3.0/24`.

Kontroler powinien wypisać, które trasy dostały jaki udział ruchu.

### 3. Otwórz terminale hostów

W konsoli Minineta uruchom osobne terminale dla hostów:

```text
mininet> xterm h1 h2
```

### 4. Uruchom odbiornik na h2

W terminalu hosta `h2` uruchom:

```bash
./receive.py
```

Odbiornik będzie wypisywał przychodzące pakiety, zdekodowaną ścieżkę oraz prosty licznik udziałów.

### 5. Wyślij pakiety z h1 do h2

W terminalu hosta `h1` uruchom:

```bash
./send.py 10.0.2.2 "test" 20
```

Dla stabilniejszej obserwacji rozkładu można wysłać więcej pakietów:

```bash
./send.py 10.0.2.2 "test" 50
```

Każdy pakiet ma losowany port źródłowy TCP, więc hash może wybrać różne sloty i różne trasy.

### 6. Zmień metryki i porównaj wynik

W pliku `topology_metrics_4.json` można zmienić koszty linków, na przykład koszt bezpośredniej trasy `s1 -> s2` albo trasy przez `s3`.

Po zmianie metryk należy ponownie uruchomić środowisko albo przynajmniej ponownie uruchomić kontroler, aby wpisał nowe reguły do switchy.

Warto obserwować dwie rzeczy:

1. co wypisuje kontroler, czyli jaki udział dostała każda trasa,
2. co wypisuje `receive.py`, czyli jak faktycznie rozłożyły się odebrane pakiety.

Jeżeli jedna trasa ma niższą metrykę, powinna dostać więcej slotów i większy udział ruchu.

## Uruchomienie: topologia przeciętego romba

Drugi scenariusz używa `topology_4.json`. Jest to topologia czterech switchy, którą można traktować jako przecięty romb:

```text
        s2
       /  \
h1 -- s1 -- s4 -- h2
       \  /
        s3
```

Istnieją trzy główne możliwości dojścia z `s1` do `s4`:

```text
s1 -> s4
s1 -> s2 -> s4
s1 -> s3 -> s4
```

Dzięki temu dobrze widać wybór kilku tras o różnych kosztach.

### 1. Uruchom Mininet z inną topologią

W katalogu przykładu:

```bash
make run TOPO=topology_4.json
```

Jeżeli środowisko wymaga jawnego czyszczenia po poprzednim uruchomieniu, można wcześniej wykonać:

```bash
make stop
make clean
```

### 2. Uruchom kontroler dla topologii czteroswitchowej

W osobnym terminalu:

```bash
./mycontroller.py topology_metrics.json
```

Ten plik metryk odpowiada topologii z `s1`, `s2`, `s3`, `s4` oraz hostami w sieciach `10.0.1.0/24` i `10.0.4.0/24`.

### 3. Otwórz terminale hostów

W konsoli Minineta uruchom osobne terminale dla hostów:

```text
mininet> xterm h1 h2
```

Host `h2` ma w tej topologii adres:

```text
10.0.4.4
```

### 4. Uruchom odbiornik na h2

W terminalu hosta `h2` uruchom:

```bash
./receive.py
```

### 5. Wyślij pakiety z h1 do h2

W terminalu hosta `h1` uruchom:

```bash
./send.py 10.0.4.4 "test" 20
```

Dla stabilniejszej obserwacji rozkładu można wysłać więcej pakietów:

```bash
./send.py 10.0.4.4 "test" 50
```

Na odbiorniku powinny pojawić się informacje o trasach, na przykład przez `s1 -> s4`, `s1 -> s2 -> s4` albo `s1 -> s3 -> s4`, zależnie od metryk i ustawionego `variance`.

## Co warto obserwować

Najważniejsze jest porównanie trzech informacji:

1. metryk w pliku JSON,
2. udziałów wypisanych przez kontroler,
3. ścieżek i liczników wypisanych przez odbiornik.

Jeżeli zmniejszymy metrykę trasy, powinna dostać większy udział. Jeżeli zwiększymy ją ponad limit `variance`, trasa powinna zniknąć z użycia. Jeżeli dwie trasy mają podobne metryki, powinny dostawać podobny udział slotów.

Ten przykład dobrze pokazuje podział ról:

- P4 szybko przekazuje pakiety na podstawie gotowych tablic,
- kontroler oblicza decyzje routingowe i programuje przełączniki,
- hash w dataplane wybiera konkretny slot dla pakietu,
- liczba slotów przypisanych trasie decyduje o jej udziale w ruchu.
