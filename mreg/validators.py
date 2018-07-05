from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator


# TODO: Move some validators to client
# TODO: Implement validation for retry, refresh, expire


def validate_ttl(value):
    """Validates that the ttl value is greater than or equal to a certain value."""
    validator = MinValueValidator(300)
    validator(value)


def validate_mac_address(address):
    """Validates that the mac address is on a valid form."""
    adr_regex = "[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
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
