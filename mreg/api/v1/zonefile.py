from mreg.models import Host, Ipaddress, Naptr, Srv, PtrOverride
from mreg.utils import idna_encode, get_network_from_zonename
import ipaddress

class ZoneFile(object):
    def __init__(self, zone):
        if zone.name.endswith('.in-addr.arpa'):
            self.zonetype = IPv4ReverseFile()
        elif zone.name.endswith('.ip6.arpa'):
            self.zonetype = IPv6ReverseFile()
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
        # Print info about Zone and its nameservers
        zone = self.zone
        data = zone.zf_string
        root = Host.objects.filter(name=zone.name)
        if root:
            data += ";\n"
            data += self.host_data(root[0])
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
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
        data += ';\n; Pointers\n;\n'
        ptroverrides = PtrOverride.objects.all()
        for ptroverride in ptroverrides:
            data += ptroverride.zf_string
        data += ';\n; Services\n;\n'
        srvs = Srv.objects.filter(zoneid=zone.zoneid)
        for srv in srvs:
            data += srv.zf_string(zone.name)
        return data

class IPv4ReverseFile(object):

    def get_ipaddresses(self, network):
        from_ip = str(network.network_address)
        to_ip = str(network.broadcast_address)
        where_str = "ipaddress BETWEEN '{}' AND '{}'".format(from_ip, to_ip)
        ips = Ipaddress.objects.extra(where=[where_str],
                                       order_by=["ipaddress"])
        # XXX: need to check ptroverrides
        return ips

    def __ip2origin(self, ip):
        tmp = ip.split('.')[:3]
        tmp.reverse()
        return '$ORIGIN %s.in-addr.arpa.\n' % ".".join(tmp)

    def generate(self, zone):
        network = get_network_from_zonename(zone.name)
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        # TODO: delegated entries, if any
        origin = ''
        this_net = 'z'
        for ip in self.get_ipaddresses(network):
            ptrip = ip.ipaddress
            # XXX: simpler as v6?
            if not ptrip.startswith(this_net):
                this_net = ptrip[:ptrip.rfind(".")+1]
                new_origin = self.__ip2origin(ptrip)
                if origin != new_origin:
                    data += new_origin
                    origin = new_origin
            ptrip = ptrip[ptrip.rfind(".")+1:]
            data += "{}\tPTR\t{}.\n".format(ptrip, idna_encode(ip.hostid.name))
        return data

class IPv6ReverseFile(object):

    def get_ipaddresses(self, network):
        from_ip = str(network.network_address)
        to_ip = str(network.broadcast_address)
        where_str = "ipaddress BETWEEN '{}' AND '{}'".format(from_ip, to_ip)
        ips = Ipaddress.objects.extra(where=[where_str],
                                       order_by=["ipaddress"])
        # XXX: need to check ptroverrides
        return ips

    def generate(self, zone):
        network = get_network_from_zonename(zone.name)
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        # TODO: delegated entries, if any
        _prev_net = 'z'
        for ip in self.get_ipaddresses(network):
            rev = ipaddress.ip_address(ip.ipaddress).reverse_pointer
            # Add $ORIGIN between every new /64 found
            if not rev.endswith(_prev_net):
                _prev_net = rev[32:]
                data += "$ORIGIN {}.\n".format(_prev_net)
            data += "{}\tPTR\t{}.\n".format(rev[:31], idna_encode(ip.hostid.name))
        return data
