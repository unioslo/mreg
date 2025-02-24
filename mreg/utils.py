import ipaddress
import re
import time

import idna

from django.conf import settings

def get_protected_policy_attribute_names() -> set:
    """
    Returns a set of protected policy attribute names.
    """
    return {attr["name"] for attr in getattr(settings, "MREG_PROTECTED_POLICY_ATTRIBUTES", [])}

def is_protected_policy_attribute(name: str) -> bool:
    """
    Returns True if the given name is in the list of protected attributes.
    """
    return name in get_protected_policy_attribute_names()

def clear_none(value):
    """
    Cleans up potential Nones into empty strings instead
    :param value: Value to check
    :return: Unmodified value or empty string
    """
    if value is None:
        value = ""
    return value


def qualify(name, zone, shortform=True):
    """
    Appends a punctuation mark to fully qualified names within a given zone.
    If the parameter name is in the zone given, it will strip the zone suffix
    and not end with a punctuation mark.
    :param name: Name to check
    :param zone: Zone where name might be
    :param shortform: Wheter to remove zone from name, or not
    :return: String with punctuation appended or unchanged
    """
    if name.endswith(zone) and shortform:
        name = re.sub('(.?%s)$' % zone, '', name)
    elif not name.endswith("."):
        name += '.'
    return name


def idna_encode(entry):
    """
    Encodes the entry to an IDNA entry.
    :param entry: Entry to encode
    :return: String encoded to IDNA and converted to utf-8
    """
    res = []
    # idna encode each label, and only those who needs it, as
    # e.g. the idna module doesn't like to encode "*".
    for label in entry.split("."):
        # convert to label.isascii() in python 3.7
        if not all(ord(char) < 128 for char in label):
            label = idna.encode(label).decode('utf-8')
        res.append(label)
    return ".".join(res)


def encode_mail(mail):
    """
    Encodes an e-mail address as a name by converting '.' to '\\.' and '@' to '.'
    Also appends a punctuation mark after the domain.
    :param mail: E-mail address to encode
    :return: Encoded e-mail address
    """
    user, domain = mail.split('@')
    user = user.replace('.', r'\.')
    mail = '%s.%s.' % (user, domain)
    return mail


def nonify(value):
    """
    Checks if value is -1, return empty string. If not, return original value.
    :param value: Value to check.
    :return: None or original value.
    """
    if value == -1:
        return ""
    else:
        return value


def create_serialno(serialno=0):
    """
    Creates an updated serialnumber based on the provided serialnumber
    :param serialno: 10-digit serialnumber in 3YYMMDDXXX format
    :return: Updated serialnumber
    """
    today = int(time.strftime('3%y%m%d'))
    if today > serialno//1000:
        return today*1000
    else:
        # Each day can only have 1000 serials
        # XXX: maybe send a signal?
        if today*1000 + 999 == serialno:
            return serialno
        else:
            return serialno+1


def get_network_from_zonename(name):
    """
    Returns a ipaddress.ip_network for given zonename
    """
    if name.endswith(".in-addr.arpa"):
        name = name.replace('.in-addr.arpa', '')
        splitted = list(reversed(name.split(".")))
        # RFC 2317. Classless in-addr. E.g: 128/25.0.0.0.in-addr.arpa
        if len(splitted) == 4 and "/" in splitted[3]:
            network = ".".join(splitted)
        else:
            netmask = 8 * len(splitted)
            while len(splitted) < 4:
                splitted.append("0")
            net = ".".join(splitted)
            network = f"{net}/{netmask}"
        return ipaddress.ip_network(network)
    elif name.endswith(".ip6.arpa"):
        name = name.replace('.ip6.arpa', '')
        splitted = name.split(".")
        netmask = 4 * len(splitted)
        net = ""
        it = reversed(splitted)
        for i in it:
            net += "%s%s%s%s:" % (i, next(it, '0'), next(it, '0'), next(it, '0'))
        return ipaddress.ip_network("{}:/{}".format(net, netmask))


# Taken from mreg_cli.util.format_mac.
def normalize_mac(mac: str) -> str:
    """
    Create a strict 'aa:bb:cc:11:22:33' MAC address.
    Replaces any other delimiters with a colon and turns it into all lower
    case.
    """
    mac = re.sub('[.:-]', '', mac).lower()
    return ":".join(["%s" % (mac[i:i+2]) for i in range(0, 12, 2)])
