import re

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator

import idna

from rest_framework import serializers


from .utils import get_network_from_zonename


# TODO: Implement validation for retry, refresh, expire


def _min_max_validator(value, minvalue, maxvalue):
    validator_min = MinValueValidator(minvalue)
    validator_max = MaxValueValidator(maxvalue)
    validator_min(value)
    validator_max(value)


def validate_16bit_uint(value):
    _min_max_validator(value, 0, 2**16-1)


def validate_32bit_uint(value):
    _min_max_validator(value, 0, 2**32-1)


def validate_ttl(value):
    """Ensures a ttl-value is within accepted range."""
    _min_max_validator(value, 300, 86400)


def validate_hexadecimal(value):
    """Ensures a string provided is a hexadecimal number"""
    try:
        int(value, 16)
    except ValueError:
        raise ValidationError("The provided value is not a hexadecimal number")


def validate_hostname(name):
    """ Validate a hostname. """

    if name.endswith("."):
        raise ValidationError("Name must not end with a punctuation mark.")
    # Assume we are not running a tld
    if '.' not in name:
        raise ValidationError("Name must include a tld.")
    # Any label in can be max 63 characters, after idna encoding
    for label in name.split("."):
        if label == '':
            raise ValidationError("Too many punctation marks")
        if label[0] == "-" or label[-1] == "-":
            raise ValidationError("Can not start or end a label with a hyphen '{}'".format(label))
        if len(label) > 63:
            raise ValidationError("Label '{}' is {} characters long, maximum is 63".format(label, len(label)))
        # convert to .isascii in python 3.7
        if all(ord(char) < 128 for char in label):
            if "*" in label:
                if len(label) > 1:
                    raise ValidationError("Wildcard must be standalone")
                continue
            label_regex = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$"
            validator = RegexValidator(label_regex,
                                       message="Label '{}' is not valid. "
                                               "Must be within [a-zA-Z0-9-].".format(label))
            validator(label)
        else:
            try:
                idna.encode(label)
            except idna.core.InvalidCodepoint as e:
                raise ValidationError("Invalid label '{}': {}".format(label, e))
            except idna.core.IDNAError as e:
                raise ValidationError(
                        "Label '{}' could not be idna encoded: {}".format(label, e))


def validate_reverse_zone_name(name):
    """ Validate a reverse zone name."""

    labels = name.split(".")
    if name.endswith(".in-addr.arpa"):
        octets = labels[:-2]
        if len(octets) > 4:
            raise ValidationError("Reverse zone is not valid: too long")
        # RFC 2317 limits the class less to maximum /25 networks.
        if len(octets) == 4 and "/" in octets[0]:
            if int(octets[0].split("/")[1]) < 25:
                raise ValidationError("Maximum CIDR for RFC 2317 is 25")
        else:
            try:
                [int(octet) for octet in octets]
            except ValueError:
                raise ValidationError("Non-integers in the octets in reverse zone")
    elif name.endswith(".ip6.arpa"):
        hexes = labels[:-2]
        if len(hexes) > 32:
            raise ValidationError("Reverse zone is not valid: too long")
        try:
            [int(i, 16) for i in hexes]
        except ValueError:
            raise ValidationError("Non-hex in the reverse zone")
    else:
        raise ValidationError("Not a valid reverse zone")

    try:
        get_network_from_zonename(name)
    except ValueError as error:
        raise ValidationError(f"Invalid network from name: {error}")


def validate_mac_address(address):
    """Validates that the mac address is on a valid form."""
    adr_regex = "^([a-f0-9]{2}:){5}[a-f0-9]{2}$"
    validator = RegexValidator(adr_regex,
                               message="Must be on form: aa:bb:cc:00:11:22")
    validator(address)


def validate_loc(location):
    """Validates that the loc input is on a valid form."""
    loc_regex = r"^\d+( \d+ \d+(\.\d+)?)? [NS] \d+( \d+ \d+(\.\d+)?)? [EW] -?\d+m?( \d+m?( \d+m?)?)?$"
    validator = RegexValidator(loc_regex)
    validator(location)


def validate_naptr_flag(flag):
    """Validates that the naptr model flag input is valid."""
    flag_regex = "^[a-z0-9]$"
    validator = RegexValidator(flag_regex, message="Must match: " + flag_regex)
    validator(flag)


def validate_regex(regex):
    """Validate the regex string"""
    try:
        re.compile(regex)
    except re.error as e:
        raise ValidationError(str(e))


def validate_srv_service_text(servicetext):
    """Validates that the srv service text input is valid."""
    servicetext_regex = r'^_[a-z0-9]+(([a-z0-9][_-]?)+[a-z0-9]+)?._(tcp|tls|udp)\.'
    validator = RegexValidator(servicetext_regex, message="Must match: " + servicetext_regex)
    validator(servicetext)


def validate_keys(obj):
    """
    Filters out unknown keys and raises a ValidationError.
    :param obj: Serializer object whose keys should be checked.
    """
    unknown_keys = set(obj.initial_data.keys()) - set(obj.fields.keys())
    if unknown_keys:
        raise serializers.ValidationError(
                f'invalid keys passed into serializer: {unknown_keys}')
