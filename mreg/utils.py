import ipaddress
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


def qualify(name, zone):
    """
    Appends a punctuation mark to fully qualified names within a given zone
    :param name: Name to check
    :param zone: Zone where name might be
    :return: String with punctuation appended or unchanged
    """
    if name.endswith(zone):
        name += '.'
    return name


def encode_mail(mail):
    """
    Encodes an e-mail address as a name by converting '.' to '\.' and '@' to '.'
    :param mail: E-mail address to encode
    :return: Encoded e-mail address
    """
    user, domain = mail.split('@')
    user = user.replace('.', '\.')
    mail = '%s.%s' % (user, domain)
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
