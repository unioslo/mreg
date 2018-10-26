import idna

from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from rest_framework import serializers

from .utils import get_network_from_zonename, idna_encode


# TODO: Move some validators to client
# TODO: Implement validation for retry, refresh, expire


def validate_ttl(value):
    """Ensures a ttl-value is within accepted range."""
    if value < 300:
        raise serializers.ValidationError("Ensure this value is greater than or equal to 300.")
    if value > 68400:
        raise serializers.ValidationError("Ensure this value is less than or equal to 68400.")

def validate_zonename(name):
    """ Validate a zonename."""
    if name.endswith("."):
        raise ValidationError("Zone name must not end with a punctuation mark.")
    # Assume we are not running a tld
    if not "." in name:
        raise ValidationError("Zone must include a tld.")
    # Any label in can be max 63 characters, after idna encoding
    labels = name.split(".")
    for label in labels:
        if len(label) > 63:
            raise ValidationError("Label '{}' is than the allowed 63 characters".format(label))
        try:
            idna_encode(label)
        except idna.core.IDNAError:
            raise ValidationError(
                    "Label '{}' becomes more than 63 characters when idna encoded".format(label))

    if name.endswith("in-addr.arpa"):
        octets = labels[:-2]
        if len(octets) > 4:
            raise ValidationError("Reverse zone is not valid")
        try:
            [ int(octet) for octet in octets ]
        except ValueError:
            raise ValidationError("Non-integers in the octets in reverse zone")
        try:
            network = get_network_from_zonename(name)
        except ValueError:
            raise ValidationError("Not a valid reverse zone")

    if name.endswith("ip6.arpa"):
        hexes = labels[:-2]
        if len(hexes) > 32:
            raise ValidationError("Reverse zone is not valid")
        #if max(map(len,hexes)) > 1:
        #    raise ValidationError("Reverse zone is not valid2")
        try:
            hexes = [ int(i, 16) for i in hexes ]
        except ValueError:
            raise ValidationError("Non-hex in the reverse zone")
        try:
            network = get_network_from_zonename(name)
        except ValueError:
            raise ValidationError("Not a valid reverse zone")

def validate_mac_address(address):
    """Validates that the mac address is on a valid form."""
    adr_regex = "^([a-fA-F0-9]{2}[-:]?){5}[a-fA-F0-9]{2}$"
    validator = RegexValidator(adr_regex)
    validator(address)


def validate_loc(location):
    """Validates that the loc input is on a valid form."""
    loc_regex = "\d+ \d+ \d+ [NS] \d+ \d+ \d+ [EW] \d+m"
    validator = RegexValidator(loc_regex)
    validator(location)


def validate_naptr_flag(flag):
    """Validates that the naptr model flag input is valid."""
    flag_regex = "^[sAUP]$"
    validator = RegexValidator(flag_regex)
    validator(flag)


def validate_srv_service_text(servicetext):
    """Validates that the srv service text input is valid."""
    servicetext_regex = '^_[a-z]+\._(tcp|udp)\.([\w\-]+\.)+$'
    validator = RegexValidator(servicetext_regex)
    validator(servicetext)


def validate_zones_serialno(serialno):
    """ Validates that the zones serialno is within given parameters."""
    validator_min = MinValueValidator(1000000000)
    validator_max = MaxValueValidator(9999999999)
    validator_min(serialno)
    validator_max(serialno)


def validate_keys(obj):
    """
    Filters out unknown keys and raises a ValidationError.
    :param obj: Serializer object whose keys should be checked.
    """
    unknown_keys = set(obj.initial_data.keys()) - set(obj.fields.keys())
    if unknown_keys:
        raise serializers.ValidationError('invalid keys passed into serializer: {0}'.format(unknown_keys))
