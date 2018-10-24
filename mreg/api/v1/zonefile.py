from mreg.models import Host, Naptr, Srv, PtrOverride
import ipaddress

class ZoneFile(object):
    def __init__(self, zone):
        self.zone = zone
        if zone.name.endswith('.in-addr.arpa'):
            self.file = IPv4ReverseFile()
        elif zone.name.endswith('.ip6.arpa'):
            self.file = IPv6ReverseFile()
        else:
            self.file = ForwardFile()

    def generate(self):
        return self.file.generate(self.zone)

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
    pass

class IPv6ReverseFile(object):
    pass
