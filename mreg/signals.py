from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError


def validate_ttl(sender, instance, **kwargs):
    """Validates that the ttl value is greater than or equal to a certain value."""
    # TODO: ttl validation should probably happen in the client, not API.
    ttl_limit = 300
    if instance.ttl < ttl_limit:
        raise ValidationError(
            "ttl value must be greater than or equal to {} ({} given).".format(
                ttl_limit, instance.ttl)
        )


def validate_mac_address(sender, instance, **kwargs):
    """Validates that the mac address is on a valid form."""
    adr_regex = "[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
    validator = RegexValidator(adr_regex)
    validator(instance.macaddress)


def validate_loc(sender, instance, **kwargs):
    """Validates that the loc input is on a valid form."""
    loc_regex = "\d+ \d+ \d+ [NS] \d+ \d+ \d+ [EW] \d+m"
    validator = RegexValidator(loc_regex)
    validator(instance.location)


def validate_naptr_flag(sender, instance, **kwargs):
    """Validates that the naptr model flag input is valid."""
    flag_regex = "^[sAUP]$"
    validator = RegexValidator(flag_regex)
    validator(instance.flag)


def validate_srv_service_text(sender, instance, **kwargs):
    """Validates that the srv service text input is valid."""
    servicetext_regex = '^_[a-z]+\._(tcp|udp)\.([\w\-]+\.)+$'
    validator = RegexValidator(servicetext_regex)
    validator(instance.servicetext)


def validate_zones_serialno(sender, instance, **kwargs):
    """ Validates that the zones serialno is within given parameters."""
    # TODO: Should probably be moved to client.
    validator_min = MinValueValidator(1000000000)
    validator_max = MaxValueValidator(9999999999)
    validator_min(instance.serialno)
    validator_max(instance.serialno)


def validate_zones_refresh_retry_expire(sender, instance, **kwargs):
    """Validates that the refresh, retry, and expire values adhere to constraints."""
    # TODO: Should probaly be moved to client.
    check_refresh = instance.refresh > instance.retry
    check_expire = instance.expire > instance.refresh + instance.retry
    check_retry = instance.retry >= 300

    if not check_refresh:
        raise ValidationError('Refresh may not be less than or equal to retry.')
    if not check_expire:
        raise ValidationError('Expire must be greater than retry + refresh ({}).'.format(self.refresh + self.retry))
    if not check_retry:
        raise ValidationError('Retry may not be less than 300.')
