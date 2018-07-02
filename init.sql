-- ADVARSEL: Dette scriptet vil SLETTE ALLE DATA fra databasen

-- Kjør f.eks. slik: psql -1 -f init.sql
-- Nyttig lesning:
-- http://petereisentraut.blogspot.com/2010/03/running-sql-scripts-with-psql.html

-- Egen datatype for ttl, siden det er brukt flere steder.
-- Minimum 300 sekunder (5 minutter).
DROP DOMAIN IF EXISTS ttl_type CASCADE;
CREATE DOMAIN ttl_type AS int
CONSTRAINT ttl_minimum CHECK (
	VALUE >= 300
);

DROP DOMAIN IF EXISTS email_type CASCADE;
CREATE DOMAIN email_type AS text
CHECK (VALUE ~ '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$');

-- Det som ligger i zone-tabellen er grunnlag for SOA-records.
-- Systemet må sørge for at det som oppgis som primary master name server
-- (primary_ns) til også blir lagt inn som en rad i ns-tabellen.
DROP TABLE IF EXISTS zones CASCADE;
CREATE TABLE zones(
	zoneid serial PRIMARY KEY not null,
	name text UNIQUE not null,
	primary_ns text not null,
	email email_type,
	serialno bigint CHECK (
		          -- YYYYMMDD00
		    serialno >= 1000000000
		AND serialno <= 9999999999
	),
	refresh int,
	retry int,
	expire int,
	ttl ttl_type,
	CHECK (
		refresh > retry
		AND expire > refresh + retry
		AND retry >= 300
	)
);

-- NS records:
-- Såkalte "Glue" records må håndheves i Pythonkoden.
-- Implementeres ved å legge til et host-objekt i tillegg.
-- Det står i kravspek at glue records IKKE automatisk skal fjernes
-- hvis NS-recorden fjernes, det betyr at man trenger ikke ta hensyn til det
-- ved sletting av NS-records.
DROP TABLE IF EXISTS ns;
CREATE TABLE ns(
	nsid serial PRIMARY KEY not null,
	zoneid int REFERENCES zones(zoneid) not null,
	name text not null,
	ttl ttl_type
);

DROP TABLE IF EXISTS hinfo_presets CASCADE;
CREATE TABLE hinfo_presets(
	hinfoid serial PRIMARY KEY not null,
	cpu text not null,
	os text not null
);

-- host-tabellen inneholder de såkalte "host-objektene".
-- HINFO-presetverdier kan legges i Pythonkoden.
-- Hvert hostobjekt har name+address som vil bli eksportert til en A-record
-- og en PTR-record, hvis det er mulig.
DROP TABLE IF EXISTS hosts CASCADE;
CREATE TABLE hosts(
	hostid serial PRIMARY KEY not null,
	name text UNIQUE not null,
	contact email_type not null,
	ttl ttl_type,
	hinfo int REFERENCES hinfo_presets(hinfoid),
	loc text CHECK(loc ~ '^\d+ \d+ \d+ [NS] \d+ \d+ \d+ [EW] \d+m$'),
	comment text
);

DROP TABLE IF EXISTS ipaddress;
CREATE TABLE ipaddress(
	hostid int REFERENCES hosts(hostid) not null,
	ipaddress inet UNIQUE not null,
	macaddress macaddr   -- For å kunne lage config til DHCP-serveren
);

DROP TABLE IF EXISTS ptr_override;
CREATE TABLE ptr_override(
	hostid int REFERENCES hosts(hostid) not null,
	ipaddress inet UNIQUE not null
);

DROP TABLE IF EXISTS txt;
CREATE TABLE txt(
	txtid serial PRIMARY KEY not null,
	hostid int REFERENCES hosts(hostid) not null,
	txt text not null
);

-- CNAME
-- Må begrenses i Python: Hvis en host (en rad i hosts-tabellen)
-- har et cname, så er det ikke tillatt med andre records (A/AAAA, MX, TXT ...).
-- Det betyr at det må gis ERROR dersom man prøver å registrere CNAME på noe
-- som allerede har en ip-adresse (som jo blir til A/AAAA), txt, hinfo, etc.
-- I motsatt fall må man fjerne cname før man kan legge til andre ting.
DROP TABLE IF EXISTS cname;
CREATE TABLE cname(
	hostid int REFERENCES hosts(hostid) not null,
	cname text not null,
	ttl ttl_type
);

-- Skal lage en cronjobb som importerer subnett slik som beskrevet her:
-- http://www.usit.uio.no/om/tjenestegrupper/cerebrum/utvikling/dokumentasjon/dns/dns-1-1.html#import-av-data-om-subnett
DROP TABLE IF EXISTS subnets;
CREATE TABLE subnets(
	subnetid serial PRIMARY KEY not null,
	range cidr not null,
	description text,
	vlan int,
	dns_delegated boolean
);

DROP TABLE IF EXISTS naptr;
CREATE TABLE naptr(
	naptrid serial PRIMARY KEY not null,
	hostid int REFERENCES hosts(hostid) not null,
	preference int CHECK (preference >= 0),
	orderv int CHECK (orderv >= 0),
	flag char(1) CHECK (flag ~ '^[sAUP]$'),
	service text not null,
	regex text,
	replacement text not null
);

-- kravspeken bruker begrepet "service-name", det er en verdi satt sammen
-- av service, proto og domain-feltene.
DROP TABLE IF EXISTS srv;
CREATE TABLE srv(
	srvid serial PRIMARY KEY not null,
	service text not null CHECK(service ~ '^_[a-z]+\._(tcp|udp)\.([\w\-]+\.)+$'),
	priority int,
	weight int,
	port int,
	ttl ttl_type,
	target text
);
