from django.test import TestCase
from mreg.models.host import Host
from mreg.models.resource_records import Loc

from .base import clean_and_save


class LocTestCase(TestCase):
    def test_validate_loc(self):
        """
        Test that the model can validate and store all examples
        from RFC1876, section 4 "Example data".
        """

        def _test_loc(loc):
            loc_obj = Loc(host=host, loc=loc)
            clean_and_save(loc_obj)
            loc_obj.delete()

        host = Host.objects.create(name="host.example.org")

        _test_loc("42 21 54 N 71 06 18 W -24m 30m")
        _test_loc("42 21 43.952 N 71 5 6.344 W -24m 1m 200m")
        _test_loc("52 14 05 N 00 08 50 E 10m")
        _test_loc("32 7 19 S 116 2 25 E 10m")
        _test_loc("42 21 28.764 N 71 00 51.617 W -44m 2000m")
        # From https://en.wikipedia.org/wiki/LOC_record
        _test_loc("52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m")
