-- Det som ligger i zone-tabellen er grunnlag for SOA-records
CREATE TABLE zones(
	zoneid serial PRIMARY KEY not null,
	name text UNIQUE not null,
	primary_ns text not null,
	email text,   --  constraint med regexp?
	serialno int, --  må ha constraint; YYYYMMDD00
	refresh int, --   > retry
	retry int, --     < refresh
	expire int, --    > refresh+retry
	ttl int --        >= 0
);

-- Får vel ikke brukt constraints til å kreve glue records?
-- Det må håndheves i Pythonkoden i stedet.
-- Det står i kravspek at glue records IKKE automatisk skal fjernes
-- hvis NS-recorden fjernes.
CREATE TABLE ns(
	zoneid int REFERENCES zone(zoneid) not null,
	name text not null,
	ttl int --        >= 0
);

-- host-tabellen inneholder de såkalte "host-objektene".
-- HINFO-presetverdier kan legges i Pythonkoden.
-- Hvert hostobjekt har name+address som vil bli eksportert til en A-record
-- og en PTR-record, hvis det er mulig.
CREATE TABLE hosts(
	hostid serial PRIMARY KEY not null,
	name text not null,
	address inet not null,
	ttl int,
	macaddress macaddr,
	contact text not null,
	hinfo text,
	loc text,
	comment text
);

-- Skal lage en cronjobb som importerer subnett slik som beskrevet her:
-- http://www.usit.uio.no/om/tjenestegrupper/cerebrum/utvikling/dokumentasjon/dns/dns-1-1.html#import-av-data-om-subnett
CREATE TABLE subnets(
	range cidr,
	comment text,
	dns_delegated boolean
);

-- Ekstra A-records legges her
CREATE TABLE a_records(
	hostid int REFERENCES host(hostid),
	name text,
	address inet,
	ttl int
);

-- Ekstra PTR-records legges her
CREATE TABLE aaaa(
	hostid int REFERENCES host(hostid),
	name text,
	address inet,
	ttl int
);

-- Ekstra PTR-records legges her
CREATE TABLE ptr(
	hostid int REFERENCES host(hostid),
	address inet,
	name text,
	ttl int
);

-- CNAME
-- Må lage constraint: Det kan ikke finnes en CNAME record med et navn
-- som allerede er i bruk i andre records (A, MX, TXT ...).
-- Det betyr også at det ikke kan finnes et host-objekt med det navnet.
CREATE TABLE cname(
	name text,
	cname text
);

CREATE TABLE naptr(
	naptrid serial PRIMARY KEY not null,
	preference int,
	order int,
	flag char(1),
	service text,
	regex text,
	replacement text
);

-- kravspeken bruker begrepet "service-name", det er en verdi satt sammen
-- av service, proto og domain-feltene.
-- Vet ikke om det gir mer mening å slå sammen disse feltene i tabellen.
CREATE TABLE srv(
	srvid serial PRIMARY KEY not null,
	service text,  -- f.eks. 'ldap'
	proto text, -- constraint: 'tcp' or 'udp'
	domain text, -- f.eks. 'usit.uio.no'
	priority int,
	weight int,
	port int,
	ttl int,
	target text
);

CREATE TABLE txt(
	txtid serial PRIMARY KEY not null,
	hostid int REFERENCES host(hostid) not null,
	txt text not null
);
