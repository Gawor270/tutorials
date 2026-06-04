# Aktywne monitorowanie polaczen z dynamicznym ECMP w P4

Ten przyklad rozszerza podstawowe rownoważenie obciążenia o aktywny pomiar ruchu w sieci. Kontroler co 1,5 sekundy wysyła specjalny pakiet sondujacy, który obiega siec i zbiera telemetrie z każdego switcha. Na podstawie zmierzonego obciążenia kontroler aktualizuje podzial slotów ECMP dla switcha s1.

Całosc sklada sie z trzech czesci:

- programu P4 `load_balance.p4`, który wykonuje forwarding pakietów IP oraz obsluguje pakiety sondy,
- kontrolera `mycontroller.py`, który instaluje reguly routingu, wysyla sondy i aktualizuje tablice ECMP,
- skryptów `send.py` i `receive.py`, które służa do testowania przesylania ruchu miedzy hostami.

## Topologia

Topologia jest opisana w pliku `topology.json` i przedstawia trójkat trzech switchy:

```text
h1 -- s1 -- s2 -- h2
       \   /
        s3 -- h3
```

Z punktu widzenia ruchu z h1 do h2, switch s1 ma dwie możliwe trasy:

```text
s1 -> s2         (port 2, trasa bezposrednia, metryka 10)
s1 -> s3 -> s2   (port 3, trasa przez s3, metryka 30)
```

## Konfiguracja switchy

Zamiast jednego pliku metryk, każdy switch ma oddzielny plik konfiguracyjny:

- `s1-runtime.json` opisuje trasy znane switchowi s1,
- `s2-runtime.json` opisuje trasy znane switchowi s2,
- `s3-runtime.json` opisuje trasy znane switchowi s3.

Przykladowy wpis w `s1-runtime.json`:

```json
{
  "destination": "10.0.2.2/32",
  "metric": 10,
  "nhop_dmac": "08:00:00:00:02:02",
  "nhop_ipv4": "10.0.2.2",
  "port": 2
}
```

Taki wpis mówi, że pakiet do hosta `10.0.2.2` należy wyslac portem `2`, przepisujac docelowy adres MAC na `08:00:00:00:02:02`.

Parametr `variance` w sekcji `eigrp` kontroluje, jak droga trasa może byc jeszcze brana pod uwage. Dla s1 `variance` wynosi `4`, co oznacza że trasy o koszcie do cztery razy wiekszym niż najlepsza sa dopuszczalne. Trasa bezposrednia ma koszt 10, a przez s3 koszt 30, wiec obie mieszcza sie w limicie.

## Tablice P4

Program P4 ma dwie tablice w ingressie do routingu pakietów IP:

```p4
table ecmp_select
table ecmp_nhop
```

Działaja tak samo jak w przykladzie UCMP: `ecmp_select` dopasowuje docelowy adres IP i wybiera zakres slotów, `ecmp_nhop` mapuje numer slotu na konkretny port i adres MAC nastepnego skoku.

Dodatkowa tablica w egressie:

```p4
table send_frame
```

Przepisuje zrodlowy adres MAC ramki wychodzacej z danego portu.

Ostatnia tablica:

```p4
table swid
```

Ustawia identyfikator switcha wpisywany do naglówka sondy przy każdym przejsciu. Dzieki temu kontroler wie, z którego switcha pochodzi dany fragment telemetrii.

## Pakiet sondujacy

Program P4 obsługuje osobny typ pakietu z ethertype `0x0812`. Taki pakiet nie jest routowany jak normalny ruch IP. Zamiast tego, w ingressie switch czyta pierwszy naglówek `probe_fwd` i wysyla pakiet na wskazany port.

Struktura pakietu sondujacego po wyjsciu z kontrolera:

```text
Ethernet (type=0x0812)
Probe    (hop_cnt=0)
ProbeFwd (egress_spec=3)
ProbeFwd (egress_spec=3)
ProbeFwd (egress_spec=2)
ProbeFwd (egress_spec=1)
```

Każdy switch w egressie dopisuje naglówek `probe_data` zawierajacy:

- identyfikator switcha (`swid`),
- numer portu wyjsciowego,
- liczbe bajtów, które przeszly przez ten port od ostatniej sondy,
- znacznik czasu poprzedniej sondy i obecnej.

Po przejsciu przez wszystkie cztery skoki sonda wraca do interfejsu `s1-eth1` i kontroler ja odbiera.

## Petla sondy

Sonda jest wysylana na interfejsie `s1-eth1`, który laczy kontroler ze switchem s1 od strony hosta h1. Pakiet obiega siec nastepujaca sciezka:

```text
s1-eth1 -> s1 (wychodzi portem 3) -> s3 (wychodzi portem 3) -> s2 (wychodzi portem 2) -> s1 (wychodzi portem 1) -> s1-eth1
```

Petla obejmuje lacznik s1-s3 oraz s3-s2, czyli cała trasę posrednia. Dzieki temu kontroler widzi, jak bardzo obciażona jest ta sciezka.

## Pomiar obciazenia i aktualizacja slotów

Kontroler odczytuje z sondy czas miedzy kolejnymi przejsciami (`cur_time - last_time`) oraz liczbe bajtów. Ze wzoru:

```text
Mbps = (bajty * 8) / czas_w_mikrosekundach
```

wylicza przepustowosc w Mbps dla każdego portu.

Nastepnie przelicza obciążenie portu 3 switcha s1 na podzial 10 slotów ECMP metodą odwrotnie proporcjonalna: im wieksze obciążenie portu 3, tym mniej slotów dostaje trasa przez s3, a wiecej dostaje trasa bezposrednia przez port 2.

Przykladowe wyjscie kontrolera przy braku ruchu:

```text
[probe] sw=1 port=3: 0.000 Mbps
[probe] sw=3 port=3: 0.000 Mbps
[probe] sw=2 port=2: 0.000 Mbps
[rebalance] s1->h2  p2:10 slots  p3:0 slots  (p3 util=0.000 Mbps)
```

Przykladowe wyjscie podczas dużego ruchu przez port 3:

```text
[probe] sw=1 port=3: 2.450 Mbps
[rebalance] s1->h2  p2:9 slots  p3:1 slots  (p3 util=2.450 Mbps)
```

Aktualizacja nastepuje po każdej odebranej sondzie, czyli co okolo 1,5 sekundy.

## Uruchomienie

### 1. Uruchom Mininet

W katalogu przykladu:

```bash
make run
```

### 2. Uruchom kontroler

W osobnym terminalu, w tym samym katalogu. Kontroler wymaga uprawnien do tworzenia surowych gniazd sieciowych (sniffer i sender na interfejsie `s1-eth1`):

```bash
sudo ./mycontroller.py
```

Kontroler dziala bez przerwy i wypisuje telemetrie z każdej odebranej sondy. Zatrzymuje go Ctrl+C.

### 3. Otworz terminale hostów

W konsoli Minineta:

```text
mininet> xterm h1 h2
```

### 4. Uruchom odbiornik na h2

W terminalu hosta h2:

```bash
./receive.py
```

### 5. Wyslij pakiety z h1 do h2

W terminalu hosta h1:

```bash
./send.py 10.0.2.2 "test" 50
```

Każdy pakiet ma losowany port zrodlowy TCP, wiec hash wybiera różne sloty i różne trasy.

### 6. Obserwuj rebalansowanie

Żeby zobaczyc jak dziala rebalansowanie, wygeneruj ruch przez port 3 (trasa posrednia). Najproœciej wyslac dużo pakietów do h3, które przechodzą przez s3:

W terminalu hosta h1:

```bash
./send.py 10.0.3.3 "load" 300
```

Podczas wysylania obserwuj wyjscie kontrolera w osobnym terminalu. Wartosc `p3 util` powinna wzrosnac, a liczba slotów dla portu 3 na trasie do h2 zmniejszyc sie.

## Co obserwowac

Najważniejsze jest porównanie dwóch zródel informacji:

1. wyjscia kontrolera, który pokazuje zmierzone obciążenie i aktualny podzial slotów,
2. wyjscia `receive.py` na h2, który pokazuje z jakich tras faktycznie korzystaly pakiety.

Kiedy port 3 jest idle, kontroler daje wszystkie 10 slotów trasie bezposredniej. To jest poprawne zachowanie: skoro trasa posrednia jest wolna, caly ruch i tak mozna wyslac tansza trasa.

Kiedy port 3 jest obciążony, kontroler przesuwa sloty w strone trasy bezposredniej, zmniejszajac ilosc ruchu kierowanego przez s3.

Ten przyklad pokazuje podzial ról:

- P4 gromadzi telemetrie w naglówkach sondy podczas normalnego forwardingu,
- kontroler interpretuje telemetrie i aktualizuje reguly w czasie rzeczywistym,
- hash w dataplane rozklada ruch zgodnie z aktualnymi proporcjami slotów.
