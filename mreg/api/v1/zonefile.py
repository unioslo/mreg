import ipaddress
from collections import defaultdict

from mreg.models import Cname, ForwardZone, Hinfo, Host, Ipaddress, Loc, Mx, Naptr, ReverseZone, Srv, Sshfp, Txt
from mreg.utils import idna_encode, qualify


class ZoneFile:
    def __init__(self, zone):
        if zone.name.endswith('.in-addr.arpa'):
            self.zonetype = IPv4ReverseFile(zone)
        elif zone.name.endswith('.ip6.arpa'):
            self.zonetype = IPv6ReverseFile(zone)
        else:
            self.zonetype = ForwardFile(zone)

    def generate(self):
        return self.zonetype.generate()


class Common:

    def __init__(self, zone):
        self.zone = zone
        self.glue_done = set()

    def get_glue(self, ns):
        """Returns glue for a nameserver. If already used return blank"""
        if ns in self.glue_done:
            return ""
        else:
            self.glue_done.add(ns)
        if not ns.endswith("." + self.zone.name):
            return ""
        try:
            host = Host.objects.get(name=ns)
        except Host.DoesNotExist:
            # XXX: signal hostmaster?
            return f"OPS: missing glue for {ns}\n"
        if not host.ipaddresses.exists():
            # XXX: signal hostmaster?
            return f"OPS: no ipaddress for name server {ns}\n"
        # self's name servers do not need glue, as they will come later
        # in the zonefile.
        if host.zone == self.zone:
            return ""
        data = ""
        idna_name = f'{idna_encode(qualify(host.name, self.zone.name)):24}'
        ttl = prep_ttl(host.ttl)
        for ip in host.ipaddresses.only('ipaddress'):
            ipaddr = ipaddress.ip_address(ip.ipaddress)
            record_type = 'A     ' if ipaddr.version == 4 else 'AAAA  '
            data += self.ip_zf_string(idna_name, ttl, record_type, ip.ipaddress)
        return data

    def get_ns_data(self, qs):
        data = ""
        qs = qs.prefetch_related("nameservers")
        for sub in qs:
            # Only delegations have comments
            if hasattr(sub, 'comment'):
                if sub.comment:
                    data += f'; {sub.comment}\n'
            nameservers = sub.nameservers.all()
            if not nameservers.exists():
                # XXX What to do?
                return f"OPS: NO NS FOR {sub.name}\n"
            for ns in nameservers:
                data += ns.zf_string(self.zone.name, subzone=sub.name)
                data += self.get_glue(ns.name)
        return data

    def get_delegations(self):
        data = ""
        delegations = self.zone.delegations.all().order_by("name")
        if delegations:
            data = ';\n; Delegations\n;\n'
            data += self.get_ns_data(delegations)
        return data


    def get_subreversezones(self):
        data = ""
        subzones = ReverseZone.objects.filter(name__endswith="." + self.zone.name)
        if subzones.exists():
            data += self.get_ns_data(subzones.order_by("name"))
            data = ';\n; Sub zones\n;\n' + data
        return data


class ForwardFile(Common):

    def ip_zf_string(self, name, ttl, record_type, record_data):
        return f'{name} {ttl} IN {record_type} {record_data}\n'

    def loc_zf_string(self, name, ttl, loc):
        record_type = 'LOC   '
        return f'{name} {ttl} IN {record_type} {loc}\n'

    def mx_zf_string(self, name, ttl, priority, mx):
        data = {
            'name': name,
            'ttl': ttl,
            'record_type': "MX",
            'priority': priority,
            'mx': idna_encode(qualify(mx, self.zone.name))
        }
        return '{name} {ttl} IN {record_type} {priority:6} {mx}\n'.format_map(data)

    def sshfp_zf_string(self, name, ttl, algorithm, hash_type, fingerprint):

        data = {
            'name': name,
            'ttl': ttl,
            'record_type': "SSHFP ",
            'algorithm': algorithm,
            'hash_type': hash_type,
            'fingerprint': fingerprint
        }
        return '{name} {ttl} IN {record_type} {algorithm:2} {hash_type:2} {fingerprint}\n'.format_map(data)

    def txt_zf_string(self, name, ttl, txt):
        record_type = 'TXT   '
        record_data = ''
        # Support RFC 4408 section 3.1.3 style TXTs: long strings splitted in 255 character chunks
        for i in range(0, len(txt), 255):
            if i > 0:
                record_data += ' '
            record_data += quote_if_space(txt[i:i+255])
        return f'{name} {ttl} IN {record_type} {record_data}\n'

    def naptr_zf_string(self, name, ttl, order, preference, flag, service, regex, replacement):
        """String representation for zonefile export."""
        if flag in ('a', 's'):
            replacement = idna_encode(qualify(replacement, self.zone.name))

        data = {
            'name': name,
            'ttl': ttl,
            'record_type': 'NAPTR ',
            'order': order,
            'preference': preference,
            'flag': flag,
            'service': service,
            'regex': regex,
            'replacement': replacement,
        }
        return '{name} {ttl} IN {record_type} {order} {preference} ' \
               '\"{flag}\" \"{service}\" \"{regex}\" {replacement}\n'.format_map(data)

    def srv_zf_string(self, name, ttl, priority, weight, port, target):
        """String representation for zonefile export."""
        data = {
            'name': idna_encode(qualify(name, self.zone.name)),
            'ttl': prep_ttl(ttl),
            'record_type': 'SRV   ',
            'priority': priority,
            'weight': weight,
            'port': port,
            'target': target,
        }
        return '{name:24} {ttl} IN {record_type} {priority} {weight} {port} {target}\n'.format_map(data)

    def cname_zf_string(self, alias, ttl, target):
        """String representation for zonefile export."""
        data = {
            'alias': idna_encode(qualify(alias, self.zone.name)),
            'ttl': prep_ttl(ttl),
            'record_type': 'CNAME ',
            'record_data': target,
        }
        return '{alias:24} {ttl} IN {record_type} {record_data}\n'.format_map(data)

    def hinfo_zf_string(self, name, ttl, cpu, os):
        """String representation for zonefile export."""
        record_type = 'HINFO '
        cpu = quote_if_space(cpu)
        os = quote_if_space(os)
        return f'{name} {ttl} IN {record_type} {cpu} {os}\n'

    def host_data(self, host):
        data = ""
        idna_name = idna_encode(qualify(host.name, self.zone.name))
        name = f'{idna_name:24}'
        ttl = prep_ttl(host.ttl)
        for values, func in ((self.ipaddresses, self.ip_zf_string),
                             (self.mxs, self.mx_zf_string),
                             (self.txts, self.txt_zf_string),
                             (self.sshfps, self.sshfp_zf_string),
                             (self.naptrs, self.naptr_zf_string),
                             ):
            if host.name in values:
                for i in values[host.name]:
                    data += func(name, ttl, *i)
                    if data:
                        name = f'{" ":24}'

        # Values only in use once by each host
        for values, func in ((self.hinfos, self.hinfo_zf_string),
                             (self.locs, self.loc_zf_string)
                             ):
            if host.name in values:
                data += func(name, ttl, *values[host.name])
                if data:
                    name = f'{" ":24}'

        # For entries where the host is the resource record
        for values, func in ((self.host_cnames, self.cname_zf_string),
                             (self.srvs, self.srv_zf_string),
                             ):
            if host.name in values:
                for i in values[host.name]:
                    data += func(*i, idna_name)
        return data

    def cache_hostdata(self):
        self.host_cnames = defaultdict(list)
        self.ipaddresses = defaultdict(list)
        self.hinfos = dict()
        self.locs = dict()
        self.mxs = defaultdict(list)
        self.naptrs = defaultdict(list)
        self.srvs = defaultdict(list)
        self.sshfps = defaultdict(list)
        self.txts = defaultdict(list)

        hinfos = Hinfo.objects.filter(host__zone=self.zone)
        for i in hinfos.values_list('host__name', 'cpu', 'os'):
            self.hinfos[i[0]] = i[1:]

        ips = Ipaddress.objects.filter(host__zone=self.zone)
        for network, record_type in (('0.0.0.0/0', 'A     '),
                                     ('::/0', 'AAAA  '),):
            ipfilter = ips.extra(where=["ipaddress << %s"], params=[network])
            for hostname, ip in ipfilter.values_list("host__name", "ipaddress"):
                self.ipaddresses[hostname].append((record_type, ip,))

        locs = Loc.objects.filter(host__zone=self.zone)
        for i in locs.values_list('host__name', 'loc'):
            self.locs[i[0]] = i[1:]

        mxs = Mx.objects.filter(host__zone=self.zone)
        for hostname, priority, mx in mxs.values_list("host__name", "priority", "mx"):
            self.mxs[hostname].append((priority, mx))

        naptrs = Naptr.objects.filter(host__zone=self.zone)
        for i in naptrs.values_list("host__name", "order", "preference", "flag",
                                    "service", "regex", "replacement"):
            self.naptrs[i[0]].append(i[1:])

        sshfps = Sshfp.objects.filter(host__zone=self.zone)
        for i in sshfps.values_list("host__name", "algorithm", "hash_type", "fingerprint"):
            self.sshfps[i[0]].append(i[1:])

        txts = Txt.objects.filter(host__zone=self.zone)
        for hostname, txt in txts.values_list("host__name", "txt"):
            self.txts[hostname].append((txt,))

        # Only CNAMEs and SRVs in this zone, as they are a name in the zone
        cnames = Cname.objects.filter(zone=self.zone).filter(host__zone=self.zone)
        for hostname, alias, ttl, in cnames.values_list('host__name', 'name', 'ttl'):
            self.host_cnames[hostname].append((alias, ttl))

        srvs = Srv.objects.filter(zone=self.zone).filter(host__zone=self.zone)
        for i in srvs.values_list('host__name', 'name', 'ttl', 'priority', 'weight', 'port'):
            self.srvs[i[0]].append(i[1:])


    def get_subdomains(self):
        data = ""
        subzones = ForwardZone.objects.filter(name__endswith="." + self.zone.name)
        if subzones:
            data += self.get_ns_data(subzones.order_by("name"))
            data = ';\n; Subdomains\n;\n' + data
        return data

    def generate(self):
        zone = self.zone
        self.cache_hostdata()
        # Print info about Zone and its nameservers
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)

        data += self.get_delegations()
        data += self.get_subdomains()
        try:
            root = Host.objects.get(name=zone.name)
            root_data = self.host_data(root)
            if root_data:
                data += ";\n"
                data += "@" + root_data
                data += ";\n"
        except Host.DoesNotExist:
            pass
        # Print info about hosts and their corresponding data
        hosts = Host.objects.filter(zone=zone.id).exclude(name=zone.name)
        if hosts.exists():
            data += ';\n; Host addresses\n;\n'
            hosts = hosts.only('name', 'ttl').order_by('name')
            for host in hosts.iterator():
                data += self.host_data(host)
        # Print misc entries
        srvs = Srv.objects.filter(zone=zone.id).exclude(host__zone=zone.id)
        if srvs:
            data += ';\n; Services pointing out of the zone\n;\n'
            for i in srvs.values_list('name', 'ttl', 'priority', 'weight', 'port', 'host__name'):
                host = idna_encode(qualify(i[-1], self.zone.name))
                data += self.srv_zf_string(*i[:-1], host)
        cnames = Cname.objects.filter(zone=zone.id).exclude(host__zone=zone.id)
        if cnames:
            data += ';\n; Cnames pointing out of the zone\n;\n'
            for i in cnames.values_list('name', 'ttl', 'host__name'):
                host = idna_encode(qualify(i[-1], self.zone.name))
                data += self.cname_zf_string(*i[:-1], host)
        return data


class IPv4ReverseFile(Common):

    def generate(self):
        zone = self.zone
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        data += self.get_delegations()
        data += self.get_subreversezones()
        _prev_net = 'z'
        for ip, ttl, hostname in zone.get_ipaddresses():
            rev = ip.reverse_pointer
            # Add $ORIGIN between every new /24 found
            if not rev.endswith(_prev_net):
                _prev_net = rev[rev.find('.'):]
                data += "$ORIGIN {}.\n".format(_prev_net[1::])
            ptrip = rev[:rev.find('.')]
            data += "{} {}\tPTR\t{}.\n".format(ptrip, ttl, idna_encode(hostname))
        return data


class IPv6ReverseFile(Common):

    def generate(self):
        zone = self.zone
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        data += self.get_delegations()
        data += self.get_subreversezones()
        _prev_net = 'z'
        for ip, ttl, hostname in zone.get_ipaddresses():
            rev = ip.reverse_pointer
            # Add $ORIGIN between every new /64 found
            if not rev.endswith(_prev_net):
                _prev_net = rev[32:]
                data += "$ORIGIN {}.\n".format(_prev_net)
            data += "{} {}\tPTR\t{}.\n".format(rev[:31], ttl, idna_encode(hostname))
        return data


def prep_ttl(ttl):
    if ttl is None:
        return '     '
    return f'{ttl:5}'


def quote_if_space(value):
    if ' ' in value:
        return f'"{value}"'
    return value
