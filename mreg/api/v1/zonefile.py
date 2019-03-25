import ipaddress

from collections import defaultdict

from mreg.models import Cname, ForwardZone, Host, Ipaddress, Mx, Naptr, Sshfp, Srv, Txt
from mreg.utils import clear_none, idna_encode, qualify


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
            #XXX: signal hostmaster?
            return f"OPS: missing glue for {ns}\n"
        if not host.ipaddresses.exists():
            #XXX: signal hostmaster?
            return f"OPS: no ipaddress for name server {ns}\n"
        # self's name servers do not need glue, as they will come later
        # in the zonefile.
        if host.zone == self.zone:
            return ""
        data = ""
        for ip in host.ipaddresses.all():
            data += ip.zf_string(self.zone.name)
        return data

    def get_ns_data(self, qs):
        data = ""
        qs = qs.prefetch_related("nameservers")
        for sub in qs:
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
            data += self.get_ns_data(delegations)
            data = ';\n; Delegations\n;\n' + data
        return data


class ForwardFile(Common):

    def ip_zf_string(self, name, ttl, ip):
        if ip.version == 4:
            iptype = "A"
        else:
            iptype = "AAAA"

        data = {
            'name': name,
            'ttl': ttl,
            'record_type': iptype,
            'record_data': str(ip),
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)

    def mx_zf_string(self, name, ttl, priority, mx):

        data = {
            'name': name,
            'ttl': ttl,
            'record_type': "MX",
            'priority': priority,
            'mx': idna_encode(qualify(mx, self.zone.name))
        }
        return '{name:24} {ttl:5} IN {record_type} {priority:6} {mx:39}\n'.format_map(data)

    def sshfp_zf_string(self, name, ttl, algorithm, hash_type, fingerprint):

        data = {
            'name': name,
            'ttl': ttl,
            'record_type': "SSHFP",
            'algorithm': algorithm,
            'hash_type': hash_type,
            'fingerprint': f'{fingerprint}'
        }
        return '{name:24} {ttl:5} IN {record_type:6} {algorithm:2} {hash_type:2} {fingerprint:39}\n'.format_map(data)

    def txt_zf_string(self, name, ttl, txt):

        data = {
            'name': name,
            'ttl': ttl,
            'record_type': "TXT",
            'record_data': f'"{txt}"'
        }
        return '{name:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)

    def naptr_zf_string(self, name, ttl, preference, order, flag, service, regex, replacement):
        """String representation for zonefile export."""
        if flag in ('a', 's'):
            replacement = idna_encode(qualify(replacement, self.zone.name))
        else:
            replacement = replacement

        data = {
            'name': name,
            'ttl': ttl,
            'record_type': 'NAPTR',
            'order': order,
            'preference': preference,
            'flag': flag,
            'service': service,
            'regex': regex,
            'replacement': replacement,
        }
        return '{name:24} {ttl:5} IN {record_type:6} {order} {preference} ' \
               '\"{flag}\" \"{service}\" \"{regex}\" {replacement}\n'.format_map(data)

    def cname_zf_string(self, alias, ttl, target):
        """String representation for zonefile export."""
        data = {
            'alias': idna_encode(qualify(alias, self.zone.name)),
            'ttl': clear_none(ttl),
            'record_type': 'CNAME',
            'record_data': target,
        }
        return '{alias:24} {ttl:5} IN {record_type:6} {record_data:39}\n'.format_map(data)

    def host_data(self, host):
        data = ""
        first = True
        name_idna = idna_encode(qualify(host.name, self.zone.name))
        ttl = clear_none(host.ttl)
        for values, func in ((self.ipaddresses, self.ip_zf_string),
                             (self.mxs, self.mx_zf_string),
                             (self.txts, self.txt_zf_string),
                             (self.sshfps, self.sshfp_zf_string),
                             (self.naptrs, self.naptr_zf_string),
                             ):
            if host.name in values:
                for i in values[host.name]:
                    if first:
                        first = False
                        name = name_idna
                    else:
                        name = ""
                    data += func(name, ttl, *i)


        # XXX: add caching for this one, if we populate it..
        if host.hinfo is not None:
            data += host.hinfo.zf_string
        if host.loc:
            data += host.loc_string(self.zone.name)
        # For entries where the host is the resource record
        if host.name in self.host_cnames:
            for alias, ttl in self.host_cnames[host.name]:
                data += self.cname_zf_string(alias, ttl, name_idna)
        return data

    def cache_hostdata(self):
        self.host_cnames = defaultdict(list)
        self.ipaddresses = defaultdict(list)
        self.mxs = defaultdict(list)
        self.naptrs = defaultdict(list)
        self.sshfps = defaultdict(list)
        self.txts = defaultdict(list)

        cnames = Cname.objects.filter(zone=self.zone).filter(host__zone=self.zone)
        for hostname, alias, ttl, in cnames.values_list('host__name', 'name', 'ttl'):
            self.host_cnames[hostname].append((alias, ttl))

        ips = Ipaddress.objects.filter(host__zone=self.zone)
        for hostname, ip in ips.values_list("host__name", "ipaddress"):
            self.ipaddresses[hostname].append((ipaddress.ip_address(ip),))

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
        hosts = Host.objects.filter(zone=zone.id).order_by('name')
        hosts = hosts.exclude(name=zone.name)
        if hosts:
            data += ';\n; Host addresses\n;\n'
            for host in hosts:
                data += self.host_data(host)
        # Print misc entries
        srvs = Srv.objects.filter(zone=zone.id)
        if srvs:
            data += ';\n; Services\n;\n'
            for srv in srvs:
                data += srv.zf_string(zone.name)
        cnames = Cname.objects.filter(zone=zone.id).exclude(host__zone=zone.id)
        if cnames:
            data += ';\n; Cnames pointing out of the zone\n;\n'
            for cname in cnames:
                data += cname.zf_string(zone.name)
        return data


class IPv4ReverseFile(Common):

    def generate(self):
        zone = self.zone
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        data += self.get_delegations()
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
        _prev_net = 'z'
        for ip, ttl, hostname in zone.get_ipaddresses():
            rev = ip.reverse_pointer
            # Add $ORIGIN between every new /64 found
            if not rev.endswith(_prev_net):
                _prev_net = rev[32:]
                data += "$ORIGIN {}.\n".format(_prev_net)
            data += "{} {}\tPTR\t{}.\n".format(rev[:31], ttl, idna_encode(hostname))
        return data
