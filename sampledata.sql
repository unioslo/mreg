-- ADVARSEL: Dette scriptet vil SLETTE ALLE DATA fra databasen,
--           før det legger inn eksempeldataene på nytt.

TRUNCATE TABLE zones,ns,hosts,ipaddress,ptr_override,subnets,
	cname,naptr,txt,srv,hinfo_presets RESTART IDENTITY;

INSERT INTO zones(name,primary_ns,email,serialno,refresh,retry,expire,ttl)
VALUES('uio.no', 'ns1.uio.no', 'hostmaster@uio.no', 2018062703,
	10800, 3600, 1814400, 43200);

INSERT INTO ns(zoneid, name, ttl)
VALUES((SELECT zoneid FROM zones WHERE name='uio.no'), 'ns1.uio.no', 43200),
	((SELECT zoneid FROM zones WHERE name='uio.no'), 'ns2.uio.no', 43200),
	((SELECT zoneid FROM zones WHERE name='uio.no'), 'nn.uninett.no', 43200),
	((SELECT zoneid FROM zones WHERE name='uio.no'), 'server.nordu.net', 43200);

INSERT INTO zones(name,primary_ns,email,serialno,refresh,retry,expire,ttl)
VALUES('ifi.uio.no', 'bestemor.ifi.uio.no', 'hostmaster@ifi.uio.no',
	2018062903, 1800, 900, 960000, 86400);

INSERT INTO ns(name, ttl, zoneid)
VALUES('ifi.uio.no', 300, (SELECT zoneid FROM zones WHERE name='ifi.uio.no')),
	('ns1.uio.no', 300, (SELECT zoneid FROM zones WHERE name='ifi.uio.no')),
	('nn.uninett.no', 300, (SELECT zoneid FROM zones WHERE name='ifi.uio.no'));

INSERT INTO hinfo_presets(cpu,os) VALUES('IBM-PC', 'LINUX');
INSERT INTO hinfo_presets(cpu,os) VALUES('IBM-PC', 'WINDOWS');
INSERT INTO hinfo_presets(cpu,os) VALUES('NET','NET');

INSERT INTO hosts(name, contact, ttl, hinfo, comment) VALUES
	('ns1.uio.no', 'hostmaster@uio.no', 43200, 1, 'primary ns for uio.no'),
	('ns2.uio.no', 'hostmaster@uio.no', 43200, 1, 'secondary ns for uio.no'),
	('ifi.uio.no', 'hostmaster@uio.no', 511, 1, 'glue record for ifi.uio.no'),
	('uio.no', 'hostmaster@uio.no', 43200, null, null),
	('sid-lc.forsbring.no', 'hostmaster@uio.no', 43200, null, 'ptr override'),
	('www.nakmi.no', 'hostmaster@uio.no', 43200, null, 'ptr override');

INSERT INTO ipaddress(ipaddress, hostid)
VALUES('129.240.2.6', (SELECT hostid FROM hosts WHERE name='ns1.uio.no')),
	('2001:700:100:2::6', (SELECT hostid FROM hosts WHERE name='ns1.uio.no')),
	('129.240.2.42', (SELECT hostid FROM hosts WHERE name='ns2.uio.no')),
	('2001:700:100:425::42', (SELECT hostid FROM hosts WHERE name='ns2.uio.no')),
	('129.240.64.2', (SELECT hostid FROM hosts WHERE name='ifi.uio.no'));

INSERT INTO ptr_override(ipaddress, hostid)
VALUES('129.240.187.49', (SELECT hostid FROM hosts WHERE name='sid-lc.forsbring.no')),
	('129.240.171.57', (SELECT hostid FROM hosts WHERE name='www.nakmi.no'));

INSERT INTO subnets(range,description,vlan)
VALUES('129.240.202.0/23',':kn:usit:|USIT-internt klientnett, secondary paa 200-nettet',null),
	('129.240.199.16/28',':bi:|AAK abel-gw, VLAN 602 (koo)', 602),
	('129.240.150.0/28', ':kn:|installasjonsnett abel-gw, vlan 1245 (andreas)', 1245),
	('129.240.161.128/30', ':nn:|Budsentralen - frankeringsmaskin, vlan 833 (alj)', 833);

-- AUTOGEN.
INSERT INTO hosts(name, ttl, contact) VALUES('uio-gw8.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('128.39.65.18',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.24.177',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.24.229',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.24.253',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.13',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.45',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.53',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.69',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.101',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.165',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.177',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.182',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.190',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.193',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.25.217',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.100.29',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.100.41',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.100.45',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.100.129',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.100.188',
	(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no'));
UPDATE hosts SET loc='59 56 23 N 10 43 50 E 80m'
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no');
INSERT INTO txt(txt,hostid) VALUES('University of Oslo, Norway',
	(SELECT hostid FROM hosts WHERE name='uio.no'));
INSERT INTO txt(txt,hostid) VALUES('google-site-verification=cDsrExFpfrxrzZukaw2Pyi4J7nQ4-hxfVOsIrZa34YY',
	(SELECT hostid FROM hosts WHERE name='uio.no'));
INSERT INTO txt(txt,hostid) VALUES('v=spf1 mx ip4:129.240.10.0/25 ip6:2001:700:100:10::/64 ip6:2001:700:100:8210::/64 include:spf.uio.no ?all',
	(SELECT hostid FROM hosts WHERE name='uio.no'));
INSERT INTO txt(txt,hostid) VALUES('dropbox-domain-verification=eovcv1nrw2n5',
	(SELECT hostid FROM hosts WHERE name='uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='NET' AND os='NET')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='uio-gw8.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('carla.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.2.8',
	(SELECT hostid FROM hosts WHERE name='carla.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='carla.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('gid-win2012.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.15.61',
	(SELECT hostid FROM hosts WHERE name='gid-win2012.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='WINDOWS')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='gid-win2012.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('priss.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO cname(cname,ttl,hostid) VALUES('carla.uio.no.',300,
	(SELECT hostid FROM hosts WHERE name='priss.uio.no'));
INSERT INTO hosts(name, ttl, contact) VALUES('callisto.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.63',
	(SELECT hostid FROM hosts WHERE name='callisto.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='callisto.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('voip2-sbc2.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.254.68',
	(SELECT hostid FROM hosts WHERE name='voip2-sbc2.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='voip2-sbc2.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('voip1-sbc2.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.254.4',
	(SELECT hostid FROM hosts WHERE name='voip1-sbc2.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='voip1-sbc2.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('ntp.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO cname(cname,ttl,hostid) VALUES('ns1.uio.no.',300,
	(SELECT hostid FROM hosts WHERE name='ntp.uio.no'));
INSERT INTO hosts(name, ttl, contact) VALUES('apollon.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.171.55',
	(SELECT hostid FROM hosts WHERE name='apollon.uio.no'));
INSERT INTO txt(txt,hostid) VALUES('v=spf1 mx ip4:129.240.10.0/25 ip6:2001:700:100:10::/64 ip6:2001:700:100:8210::/64 include:spf.uio.no ?all',
	(SELECT hostid FROM hosts WHERE name='apollon.uio.no'));
INSERT INTO naptr(preference,orderv,flag,service,regex,replacement,hostid)
	VALUES(3, 10, 's', 'SIP+D2U', '', '_sip._udp.sbc2.voip.uio.no.',
	(SELECT hostid FROM hosts WHERE name='apollon.uio.no'));
INSERT INTO naptr(preference,orderv,flag,service,regex,replacement,hostid)
	VALUES(2, 10, 's', 'SIP+D2T', '', '_sip._tcp.sbc2.voip.uio.no.',
	(SELECT hostid FROM hosts WHERE name='apollon.uio.no'));
INSERT INTO naptr(preference,orderv,flag,service,regex,replacement,hostid)
	VALUES(1, 10, 's', 'SIPS+D2T', '', '_sips._tcp.sbc2.voip.uio.no.',
	(SELECT hostid FROM hosts WHERE name='apollon.uio.no'));
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._udp.apollon.uio.no.',10,50,7060,43200,
	'voip1-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._udp.apollon.uio.no.',10,50,7060,43200,
	'voip2-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._tcp.apollon.uio.no.',8,50,7060,43200,
	'voip1-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._tcp.apollon.uio.no.',8,50,7060,43200,
	'voip2-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sips._tcp.apollon.uio.no.',6,50,7061,43200,
	'voip1-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sips._tcp.apollon.uio.no.',6,50,7061,43200,
	'voip2-sbc2.uio.no.');
INSERT INTO hosts(name, ttl, contact) VALUES('math.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.75.234',
	(SELECT hostid FROM hosts WHERE name='math.uio.no'));
INSERT INTO txt(txt,hostid) VALUES('v=spf1 mx ip4:129.240.10.0/25 ip6:2001:700:100:10::/64 ip6:2001:700:100:8210::/64 include:spf.uio.no ?all',
	(SELECT hostid FROM hosts WHERE name='math.uio.no'));
INSERT INTO naptr(preference,orderv,flag,service,regex,replacement,hostid)
	VALUES(3, 10, 's', 'SIP+D2U', '', '_sip._udp.sbc2.voip.uio.no.',
	(SELECT hostid FROM hosts WHERE name='math.uio.no'));
INSERT INTO naptr(preference,orderv,flag,service,regex,replacement,hostid)
	VALUES(2, 10, 's', 'SIP+D2T', '', '_sip._tcp.sbc2.voip.uio.no.',
	(SELECT hostid FROM hosts WHERE name='math.uio.no'));
INSERT INTO naptr(preference,orderv,flag,service,regex,replacement,hostid)
	VALUES(1, 10, 's', 'SIPS+D2T', '', '_sips._tcp.sbc2.voip.uio.no.',
	(SELECT hostid FROM hosts WHERE name='math.uio.no'));
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._udp.math.uio.no.',10,50,7060,43200,
	'voip1-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._udp.math.uio.no.',10,50,7060,43200,
	'voip2-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._tcp.math.uio.no.',8,50,7060,43200,
	'voip1-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sip._tcp.math.uio.no.',8,50,7060,43200,
	'voip2-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sips._tcp.math.uio.no.',6,50,7061,43200,
	'voip1-sbc2.uio.no.');
INSERT INTO srv(service,priority,weight,port,ttl,target)
	VALUES('_sips._tcp.math.uio.no.',6,50,7061,43200,
	'voip2-sbc2.uio.no.');
INSERT INTO hosts(name, ttl, contact) VALUES('hydrolab.math.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO cname(cname,ttl,hostid) VALUES('asklepios.uio.no.',300,
	(SELECT hostid FROM hosts WHERE name='hydrolab.math.uio.no'));
INSERT INTO hosts(name, ttl, contact) VALUES('git.math.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO cname(cname,ttl,hostid) VALUES('asklepios.uio.no.',300,
	(SELECT hostid FROM hosts WHERE name='git.math.uio.no'));
INSERT INTO hosts(name, ttl, contact) VALUES('cvs.math.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO cname(cname,ttl,hostid) VALUES('asklepios.uio.no.',300,
	(SELECT hostid FROM hosts WHERE name='cvs.math.uio.no'));
INSERT INTO hosts(name, ttl, contact) VALUES('asklepios.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.75.233',
	(SELECT hostid FROM hosts WHERE name='asklepios.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='asklepios.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('myrsnipa.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.34',
	(SELECT hostid FROM hosts WHERE name='myrsnipa.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='myrsnipa.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('bac.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('symfoni.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.21',
	(SELECT hostid FROM hosts WHERE name='symfoni.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='symfoni.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('fuge.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.16',
	(SELECT hostid FROM hosts WHERE name='fuge.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='fuge.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('flax.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.98',
	(SELECT hostid FROM hosts WHERE name='flax.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='flax.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('timelord.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.22',
	(SELECT hostid FROM hosts WHERE name='timelord.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='WINDOWS')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='timelord.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('clara.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.118',
	(SELECT hostid FROM hosts WHERE name='clara.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='WINDOWS')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='clara.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('rocinante.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.156',
	(SELECT hostid FROM hosts WHERE name='rocinante.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='rocinante.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('amaterasu.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.187',
	(SELECT hostid FROM hosts WHERE name='amaterasu.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='MAC' AND os='DARWIN')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='amaterasu.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('josefine.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.168',
	(SELECT hostid FROM hosts WHERE name='josefine.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='josefine.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('ladon.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.203',
	(SELECT hostid FROM hosts WHERE name='ladon.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='ladon.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('cassandra.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.143',
	(SELECT hostid FROM hosts WHERE name='cassandra.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='WINDOWS')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='cassandra.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('tux.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.12',
	(SELECT hostid FROM hosts WHERE name='tux.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='tux.uio.no');
INSERT INTO hosts(name, ttl, contact) VALUES('kaffekopp.uio.no', 3600, 'hostmaster@uio.no');
INSERT INTO ipaddress(ipaddress,hostid) VALUES('129.240.202.110',
	(SELECT hostid FROM hosts WHERE name='kaffekopp.uio.no'));
UPDATE hosts SET hinfo=
	(SELECT hinfoid FROM hinfo_presets WHERE cpu='IBM-PC' AND os='LINUX')
	WHERE hostid=(SELECT hostid FROM hosts WHERE name='kaffekopp.uio.no');
