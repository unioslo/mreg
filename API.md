## API for hver tabell/entitet

[Zones](API_zones.md)  
[Hosts](API_hosts.md)

## Generelt om API

### REST
Vi prøver å følge REST-prinsipper så godt det lar seg gjøre. Lesestoff:  
http://www.restapitutorial.com/lessons/restquicktips.html  
http://www.restapitutorial.com/lessons/httpmethods.html  
http://www.restapitutorial.com/httpstatuscodes.html  

### Autentisering
Alle API-metodene vil kreve en form for autentisering, men vi har ennå ikke bestemt hvordan det skal gjøres. Det bør gå greit å implementere det i etterkant.

Noen&#8482; må finne ut hvor finkornet rettighetsstyringen skal være. Sagt på en annen måte, hvor mange dimensjoner det skal være i rettighetsmatrisen, og hvordan hver dimensjon skal deles opp.
- Nivåer av brukere (vanlig + "superbruker"?). Forskjellige typer endringer kan kreve forskjellig nivå. F.eks. tilgang til "force".
- Eierskap til objekter, basert på  organisasjonstilhørighet og/eller gruppemedlemskap

#### Implementasjon

Klienter sender brukernavn eller api-nøkkel som en http-header med hver forespørsel.
Eksempel på mulige måter å gjøre dette på er [JSON Web Token](https://jwt.io/) eller [http basic auth](https://en.wikipedia.org/wiki/Basic_access_authentication).

Server verifiserer credentials for å avgjøre identiteten. Deretter gjøres kanskje LDAP-oppslag for å finne gruppetilhørighet og slikt. Eventuell rettighetstabell sjekkes også. Så sammenligner man med hvilke objekter som blir forespurt endret, for å avgjøre om vedkommende har tilgang eller ikke.

### Versjonering

Les https://www.troyhunt.com/your-api-versioning-is-wrong-which-is/

Foreslår at vi gjør det på denne måten:
```
/api/v1/...
```

### Force

Noen operasjoner skal i noen tilfeller avvises og gi en advarsel. Det kan være avhengig av hvilke data som finnes i systemet fra før av, eller om det er en "alvorlig" operasjon.

I de tilfellene kan man oppgi en egen parameter ("force") for å overstyre dette og gjennomføre operasjonen. Isåfall bør advarselen likevel komme, men som en infomelding.
