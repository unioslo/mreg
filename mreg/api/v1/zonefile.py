from mreg.models import Host, Ipaddress, Naptr, Srv, PtrOverride
import ipaddress

class ZoneFile(object):
    def __init__(self, zone):
        self.zone = zone
        if zone.name.endswith('.in-addr.arpa'):
            self.zonetype = IPv4ReverseFile()
        elif zone.name.endswith('.ip6.arpa'):
            self.zonetype = IPv6ReverseFile()
        else:
            self.zonetype = ForwardFile()

    def generate(self):
        return self.zonetype.generate(self.zone)

class ForwardFile(object):
    def generate(self, zone):
        # Print info about Zone and its nameservers
        data = zone.zf_string
        data += ';\n; Name servers\n;\n'
        for ns in zone.nameservers.all():
            data += ns.zf_string(zone.name)
        # Print info about hosts and their corresponding data
        data += ';\n; Host addresses\n;\n'
        hosts = Host.objects.filter(zoneid=zone.zoneid).order_by('name')
        for host in hosts:
            for ip in host.ipaddress.all():
                data += ip.zf_string(zone.name)
            if host.hinfo is not None:
                data += host.hinfo.zf_string(zone.name)
            if host.loc is not None:
                data += host.loc_string(zone.name)
            for cname in host.cname.all():
                data += cname.zf_string(zone.name)
            for txt in host.txt.all():
                data += txt.zf_string(zone.name)
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

    def get_network(self, zone):
        zone = zone.replace('.in-addr.arpa','')
        splitted = list(reversed(zone.split(".")))
        netmask = 8 * len(splitted)
        while len(splitted) < 4:
            splitted.append("0")
        net = ".".join(splitted)
        return ipaddress.ip_network("{}/{}".format(net, netmask))

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
        network = self.get_network(zone.name)
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
            data += "{}\tPTR\t{}\n".format(ptrip, ip.hostid.name)
        return data

class IPv6ReverseFile(object):

    def get_network(self, zone):
        zone = zone.replace('.ip6.arpa','')
        splitted = zone.split(".")
        netmask = 4 * len(splitted)
        net = ""
        it = reversed(splitted)
        for i in it:
            net += "%s%s%s%s:" % (i, next(it, '0'), next(it, '0'), next(it, '0'))
        return ipaddress.ip_network("{}:/{}".format(net, netmask))

    def get_ipaddresses(self, network):
        from_ip = str(network.network_address)
        to_ip = str(network.broadcast_address)
        where_str = "ipaddress BETWEEN '{}' AND '{}'".format(from_ip, to_ip)
        ips = Ipaddress.objects.extra(where=[where_str],
                                       order_by=["ipaddress"])
        # XXX: need to check ptroverrides
        return ips

    def generate(self, zone):
        network = self.get_network(zone.name)
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
            data += "{}\tPTR\t{}\n".format(rev[:31], ip.hostid.name)
        return data
