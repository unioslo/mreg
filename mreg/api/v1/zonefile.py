import ipaddress

from collections import defaultdict

from mreg.models import Host, Ipaddress, Naptr, Srv, PtrOverride
from mreg.utils import idna_encode, get_network_from_zonename

class ZoneFile(object):
    def __init__(self, zone):
        if zone.name.endswith('.in-addr.arpa'):
            self.zonetype = IPv4ReverseFile(zone)
        elif zone.name.endswith('.ip6.arpa'):
            self.zonetype = IPv6ReverseFile(zone)
        else:
            self.zonetype = ForwardFile(zone)

    def generate(self):
        return self.zonetype.generate()

class ForwardFile(object):

    def __init__(self, zone):
        self.zone = zone

    def host_data(self, host):
        data = ""
        for ip in host.ipaddress.all():
            data += ip.zf_string(self.zone.name)
        if host.hinfo is not None:
            data += host.hinfo.zf_string
        if host.loc is not None:
            data += host.loc_string(self.zone.name)
        for cname in host.cname.all():
            data += cname.zf_string(self.zone.name)
        for txt in host.txt.all():
            data += txt.zf_string(self.zone.name)
        return data


    def generate(self):
        zone = self.zone
        # Print info about Zone and its nameservers
        data = zone.zf_string
        root = Host.objects.filter(name=zone.name)
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        data += ';\n; Subdomains\n;\n'
        data += ';\n; Glue records\n;\n'
        if root:
            data += ";\n"
            data += self.host_data(root[0])
        # Print info about hosts and their corresponding data
        data += ';\n; Host addresses\n;\n'
        hosts = Host.objects.filter(zoneid=zone.zoneid).order_by('name')
        hosts = hosts.exclude(name=zone.name)
        for host in hosts:
            data += self.host_data(host)
        # Print misc entries
        data += ';\n; Name authority pointers\n;\n'
        naptrs = Naptr.objects.filter(zoneid=zone.zoneid)
        for naptr in naptrs:
            data += naptr.zf_string(zone.name)
        data += ';\n; Services\n;\n'
        srvs = Srv.objects.filter(zoneid=zone.zoneid)
        for srv in srvs:
            data += srv.zf_string(zone.name)
        return data

def get_ipaddresses(network):
    from_ip = str(network.network_address)
    to_ip = str(network.broadcast_address)
    ips = Ipaddress.objects.filter(ipaddress__range=(from_ip, to_ip)).order_by("ipaddress")
    override_ips = dict()
    for p in PtrOverride.objects.filter(ipaddress__range=(from_ip, to_ip)):
        override_ips[p.ipaddress] = p

    # XXX: send signal/mail to hostmaster(?) about issues with multiple_ip_no_ptr
    count = defaultdict(int)
    for i in ips:
        if i.ipaddress not in override_ips:
            count[i.ipaddress] += 1
    multiple_ip_no_ptr = {i: count[i] for i in count if count[i] > 1}
    ptr_done = set()
    # Use PtrOverrides when found, but only once. Also skip IPaddresses
    # which have been used multiple times, but lacks a PtrOverride.
    for i in ips:
        ip = i.ipaddress
        if ip in multiple_ip_no_ptr:
            continue
        if ip in override_ips:
            if ip not in ptr_done:
                ptr_done.add(ip)
                yield override_ips[ip]
        else:
            yield i

class IPv4ReverseFile(object):

    def __init__(self, zone):
        self.zone = zone

    def generate(self):
        zone = self.zone
        network = get_network_from_zonename(zone.name)
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        # TODO: delegated entries, if any
        data += ';\n; Delegations \n;\n'
        _prev_net = 'z'
        for ip in get_ipaddresses(network):
            rev = ipaddress.ip_address(ip.ipaddress).reverse_pointer
            # Add $ORIGIN between every new /24 found
            if not rev.endswith(_prev_net):
                _prev_net = rev[rev.find('.'):]
                data += "$ORIGIN {}.\n".format(_prev_net[1::])
            ptrip = rev[:rev.find('.')]
            data += "{}\tPTR\t{}.\n".format(ptrip, idna_encode(ip.hostid.name))
        return data

class IPv6ReverseFile(object):

    def generate(self, zone):
        network = get_network_from_zonename(zone.name)
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        # TODO: delegated entries, if any
        data += ';\n; Delegations\n;\n'
        _prev_net = 'z'
        for ip in get_ipaddresses(network):
            rev = ipaddress.ip_address(ip.ipaddress).reverse_pointer
            # Add $ORIGIN between every new /64 found
            if not rev.endswith(_prev_net):
                _prev_net = rev[32:]
                data += "$ORIGIN {}.\n".format(_prev_net)
            data += "{}\tPTR\t{}.\n".format(rev[:31], idna_encode(ip.hostid.name))
        return data
