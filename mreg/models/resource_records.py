from django.db import models

from mreg.fields import DnsNameField, LCICharField
from mreg.validators import (
    validate_16bit_uint,
    validate_hexadecimal,
    validate_loc,
    validate_naptr_flag,
    validate_srv_service_text,
    validate_ttl,
)

from mreg.models.base import BaseModel, ForwardZoneMember
from mreg.models.host import Host 

class Loc(BaseModel):
    host = models.OneToOneField(Host, on_delete=models.CASCADE, primary_key=True)
    loc = models.TextField(validators=[validate_loc])

    class Meta:
        db_table = "loc"

    def __str__(self):
        return f"{self.host.name} -> {self.loc}"


class Sshfp(BaseModel):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, db_column="host")
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    algorithm = models.IntegerField(
        choices=((1, "RSA"), (2, "DSS"), (3, "ECDSA"), (4, "Ed25519"))
    )
    hash_type = models.IntegerField(choices=((1, "SHA-1"), (2, "SHA-256")))
    fingerprint = models.CharField(max_length=64, validators=[validate_hexadecimal])

    class Meta:
        db_table = "sshfp"
        unique_together = (("host", "algorithm", "hash_type", "fingerprint"),)

    def __str__(self):
        return (
            f"{self.host.name} -> {self.algorithm} ({self.get_algorithm_display()}) "
            f"{self.hash_type} ({self.get_hash_type_display()}) {self.fingerprint}"
        )


class Hinfo(BaseModel):
    host = models.OneToOneField(Host, on_delete=models.CASCADE, primary_key=True)
    cpu = models.TextField()
    os = models.TextField()

    class Meta:
        db_table = "hinfo"

    def __str__(self):
        return f"cpu: {self.cpu} os: {self.os}"


class Mx(BaseModel):
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, db_column="host", related_name="mxs"
    )
    priority = models.PositiveIntegerField(validators=[validate_16bit_uint])
    mx = DnsNameField()

    class Meta:
        db_table = "mx"
        unique_together = ("host", "priority", "mx")

    def __str__(self):
        return f"{self.priority} {self.mx}"


class Txt(BaseModel):
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, db_column="host", related_name="txts"
    )
    txt = models.TextField(max_length=4096)

    class Meta:
        db_table = "txt"
        unique_together = ("host", "txt")

    def __str__(self):
        return str(self.txt)


class Cname(ForwardZoneMember):
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, db_column="host", related_name="cnames"
    )
    name = DnsNameField(unique=True)
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])

    class Meta:
        db_table = "cname"
        ordering = ("name",)

    def __str__(self):
        return "{} -> {}".format(str(self.name), str(self.host))


class Naptr(BaseModel):
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, db_column="host", related_name="naptrs"
    )
    preference = models.IntegerField(validators=[validate_16bit_uint])
    order = models.IntegerField(validators=[validate_16bit_uint])
    flag = models.CharField(max_length=1, blank=True, validators=[validate_naptr_flag])
    service = LCICharField(max_length=128, blank=True)
    regex = models.CharField(max_length=128, blank=True)
    replacement = LCICharField(max_length=255)

    class Meta:
        db_table = "naptr"
        unique_together = (
            "host",
            "preference",
            "order",
            "flag",
            "service",
            "regex",
            "replacement",
        )
        ordering = ("preference", "order", "flag", "service", "regex", "replacement")

    def __str__(self):
        return "{} -> {} {} {} {} {} {}".format(
            self.host,
            self.preference,
            self.order,
            self.flag,
            self.service,
            self.regex,
            self.replacement,
        )

class Srv(ForwardZoneMember):
    name = LCICharField(max_length=255, validators=[validate_srv_service_text])
    priority = models.IntegerField(validators=[validate_16bit_uint])
    weight = models.IntegerField(validators=[validate_16bit_uint])
    port = models.IntegerField(validators=[validate_16bit_uint])
    ttl = models.IntegerField(blank=True, null=True, validators=[validate_ttl])
    # This field is called "Target" in the RFC, but to utilize other code we
    # name a field with foreignKey to Host as "host".
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, db_column="host", related_name="srvs"
    )

    class Meta:
        db_table = "srv"
        unique_together = ("name", "priority", "weight", "port", "host")
        ordering = ("name", "priority", "weight", "port", "host")

    def __str__(self):
        return str(self.name)