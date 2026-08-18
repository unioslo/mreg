from django.test import SimpleTestCase

from mreg.api.serializers import REPORTED_LIBRARY_VERSION_FIELDS
from mreg.api.views import LIBRARIES_TO_REPORT


class ReportedLibraryVersionsTest(SimpleTestCase):
    def test_legacy_view_constant_remains_compatible(self):
        self.assertIs(LIBRARIES_TO_REPORT, REPORTED_LIBRARY_VERSION_FIELDS)
