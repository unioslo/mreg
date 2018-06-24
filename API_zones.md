#### API for soner

Se også: [Generell API-kravspesifikasjon](API.md)

## GET /zones
Hente liste over alle sonene.

Mulige statuskoder:
- 200 OK (Body: en json-liste over soner, select name from zones)
- 401 Unauthorized (hvis mangler autentisering)

## GET /zones/*name*

Hente all info om en gitt sone.

Mulige statuskoder:
- 200 OK (body skal være et json-objekt med alle felter fra zones for den valgte sonen)
- 404 Not Found
- 401 Unauthorized (hvis mangler autentisering)

Responsen skal også inkludere en [ETag-header](https://en.wikipedia.org/wiki/HTTP_ETag),
til å bruke i tilfelle man ønsker å gjøre endringer.

## POST /zones

Opprette en ny [DNS-sone](https://en.wikipedia.org/wiki/DNS_zone).

##### Parametre
Body skal være et JSON-objekt.  
Påkrevde felt:  
- name
- ns (skal være en array)
- email (hostmaster)
- refresh
- retry
- expire
- ttl

##### Virkemåte:
INSERTer i zones- og ns-tabellene. Første oppgitte nameserver antas å være "primary" nameserver for sonen (primary_ns-feltet).
I noen tilfeller (se *glue records*) INSERTes også en rad i A-record-tabellen.
Serial-feltet (som inngår i SOA-recorden) beregnes automatisk ut i fra dagens dato.

##### Restriksjoner:
- Hvis man forsøker å opprette en ny sone med navneservere som befinner seg i en sone som MREG er ansvarlig for, så skal det kreve force dersom disse ikke allerede eksisterer som A-records.

##### Glue records
Dersom det delegeres undersoner, og NS for undersone er i den samme, må man i moder-sonen ha såkalte glue records, dvs. lim mellom moder-sonen og undersonen slik at resolvere kan spore seg ned til ansvarlig(e) navneserver(e). Dersom man i en undersone (av en sone systemet er ansvarlig for) setter eller endrer en NS-record må derfor systemet definere eller endre en A-record i modersonen.
https://www.usit.uio.no/om/organisasjon/iti/gd/doc/hostmaster/mreg-krav.html#dns-soner-og-resource-records

##### Hvis alt gikk bra:
- Status: 201 Created
- Location: /zones/*name*

##### Mulige statuskoder ved feil:
- 409 Conflict (hvis sone finnes fra før av som gir konflikt med den nye sonen)
- 400 Bad Request (hvis parametrene ikke gir mening)
- 403 Forbidden (hvis brukeren ikke har lov til å gjøre dette)
- 401 Unauthorized (hvis mangler autentisering)

## PATCH /zones/*name*

Endre eksisterende sone. Man kan endre detaljer for [SOA-recorden](https://en.wikipedia.org/wiki/SOA_record) og/eller navneserverne.
Man kan IKKE endre navnet på sonen.
Request body skal være et json-objekt som inneholder kun de feltene som skal endres.

Klienten skal sende med en [If-Match-header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match) med Etag- verdien fått fra tidligere GET-kall,
slik at serveren kan avslå forespørselen dersom sonen har blitt endret av noen andre i mellomtiden. Mangler denne headeren, skal serveren avvise forespørselen.

Mulige statuskoder:
- 204 No Content (betyr at alt gikk OK)
- 404 Not Found
- 412 Precondition Failed (hvis endret av noen andre i mellomtiden slik at ETag ikke stemte)
- 409 Conflict (Hvis den oppdaterte sonen vil komme i konflikt med andre data i systemet)
- 400 Bad Request (hvis parametrene ikke gir mening)
- 403 Forbidden (hvis brukeren ikke har lov til å gjøre dette)
- 401 Unauthorized (hvis mangler autentisering)

I tilfelle 409 eller 400, bør response body inneholde en mer detaljert problembeskrivelse. Dvs. liste hvilke felter som hadde feil verdi eller hva det var konflikt med.

## DELETE /zones/*name*

Slette en sone.

- Dersom man forsøker å slette en sone som fremdeles har registrerte entries, så skal det kreve force.

Mulige statuskoder:
- 204 No Content (betyr at alt gikk OK)
- 404 Not Found
- 403 Forbidden (hvis brukeren ikke har lov til å gjøre dette)
- 401 Unauthorized (hvis mangler autentisering)
