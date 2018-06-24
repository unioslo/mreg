#### API for såkalte host-objekter

Se også: [Generell API-kravspesifikasjon](API.md)

### GET /hosts
Returnerer et JSON-objekt med en liste over alle hosts (kun navn).

### GET /hosts/*name-or-ip*

##### Hvis hosten finnes
Returnerer status 200 OK og et JSON-objekt med alle dataene fra hosts-tabellen for denne hosten.

Responsen skal også inneholde detaljer om eventuelle andre A, AAAA, PTR, CNAME, og TXT-records som tilhører denne hosten.

Responsen skal også inkludere en [ETag-header](https://en.wikipedia.org/wiki/HTTP_ETag),
til å bruke i tilfelle man ønsker å gjøre endringer.

##### Mulige statuskoder ved feil:
- 404 Not Found
- 403 Forbidden (hvis brukeren ikke har lov til å se denne hosten)
- 401 Unauthorized (hvis mangler autentisering)

### POST /hosts

##### Parametre
Body skal være et JSON-objekt.  
Påkrevde felt:
- name
- ipaddress
- contact (email)

Valgfrie felt:  
- hinfo (Danner en [HINFO](https://en.wikipedia.org/wiki/List_of_DNS_record_types#HINFO)-record)
- comment

`ipaddress` skal enten være en spesifikk IP, eller et subnett (isåfall betyr det at systemet skal velge en tilfeldig ledig adresse på det subnettet).

##### Restriksjoner:
- Hvis `ipaddress` ikke er i et subnett som styres av MREG, så skal det kreve force.
- Dersom `name` har flere A-records, så skal det kreve force.
- Dersom `name` har CNAME, SRV eller NAPTR pekende på seg, så skal det kreve force.
- Dersom `name` vil overlappe med en CNAME record, skal forespørselen avvises
  med 409 Conflict og en advarsel.

##### Hvis alt gikk bra:
- Status: 201 Created
- Location: /hosts/*name*

##### Mulige statuskoder ved feil:
- 409 Conflict (hvis noe finnes fra før av som gir konflikt med det nye)
- 400 Bad Request (hvis parametrene ikke gir mening)
- 403 Forbidden (hvis brukeren ikke har lov til å gjøre dette)
- 401 Unauthorized (hvis mangler autentisering)

### PATCH /hosts/*name*

Endre eksisterende host.
Request body skal være et JSON-objekt som inneholder kun de feltene som skal endres.

##### Tilleggskrav
Klienten skal sende med en [If-Match-header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match) med Etag-verdien fått fra tidligere GET-kall,
slik at serveren kan avslå forespørselen dersom hosten har blitt endret av noen andre i mellomtiden. Mangler denne headeren, skal serveren avvise forespørselen.

##### Hvis alt gikk bra:
- Status: 204 No Content
- Location: /hosts/*name* (spesielt nyttig hvis man endret navnet)

##### Mulige statuskoder ved feil:
- 404 Not Found
- 412 Precondition Failed (hvis ETag ikke stemte)
- 409 Conflict (Hvis den oppdaterte sonen vil komme i konflikt med andre data i systemet)
- 400 Bad Request (hvis parametrene ikke gir mening)
- 403 Forbidden (hvis brukeren ikke har lov til å gjøre dette)
- 401 Unauthorized (hvis mangler autentisering)
