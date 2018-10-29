import idna
import ipaddress
import re
import time


def clear_none(value):
    """
    Cleans up potential Nones into empty strings instead
    :param value: Value to check
    :return: Unmodified value or empty string
    """
    if value is None:
        value = ""
    return value


def comment(string):
    """
    Turns not-empty string into comments
    :param string: String to check
    :return: Commented or empty string
    """
    if string != "":
        string = ' ; %s' % string
    return string


def reverse_ip(ip):
    """
    Reverses an IP-adddress
    :param ip: IP-address to reverse
    :return: IP-address in reverse
    """
    if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        return ':'.join(reversed(ip.split(':')))
    else:
        return '.'.join(reversed(ip.split('.')))


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
    Encodes an e-mail address as a name by converting '.' to '\.' and '@' to '.'
    Also appends a punctuation mark after the domain.
    :param mail: E-mail address to encode
    :return: Encoded e-mail address
    """
    user, domain = mail.split('@')
    user = user.replace('.', '\.')
    mail = '%s.%s.' % (user, domain)
    return mail


def nonify(value):
    """
    Checks if value is -1 or empty string and return None. If not, return original value.
    :param value: Value to check.
    :return: None or original value.
    """
    if value == -1:
        return None
    elif value == "":
        return None
    else:
        return value


def create_serialno(serialno):
    """
    Creates an updated serialnumber based on the provided serialnumber
    :param serialno: 10-digit serialnumber
    :return: Updated serialnumber
    """
    today = int(time.strftime('%Y%m%d'))
    if today > serialno//100:
        return today*100
    else:
        return serialno+1

def get_network_from_zonename(name):
    """
    Returns a ippadress.ip_network for given zonename
    """
    if name.endswith(".in-addr.arpa"):
        name = name.replace('.in-addr.arpa','')
        splitted = list(reversed(name.split(".")))
        netmask = 8 * len(splitted)
        while len(splitted) < 4:
            splitted.append("0")
        net = ".".join(splitted)
        return ipaddress.ip_network("{}/{}".format(net, netmask))
    elif name.endswith(".ip6.arpa"):
        name = name.replace('.ip6.arpa','')
        splitted = name.split(".")
        netmask = 4 * len(splitted)
        net = ""
        it = reversed(splitted)
        for i in it:
            net += "%s%s%s%s:" % (i, next(it, '0'), next(it, '0'), next(it, '0'))
        return ipaddress.ip_network("{}:/{}".format(net, netmask))
