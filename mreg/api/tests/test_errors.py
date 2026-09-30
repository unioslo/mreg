from django.test import SimpleTestCase

from mreg.api.errors import ErrorCode



class ErrorCodeTestCase(SimpleTestCase):
    # NOTE: these tests should be redundant on 3.14, but we keep them
    # so we can be completely sure that f-strings and string representations behave as expected.
    def test_error_code_in_f_strings(self):
        """Test that the ErrorCode values behave correctly in f-strings."""
        message = f"Error code is {ErrorCode.REQUIRED}"
        self.assertEqual(message, "Error code is required")

    def test_error_code_is_string(self):
        """Test that the ErrorCode values behave as strings."""
        self.assertEqual(ErrorCode.REQUIRED, "required")
        self.assertEqual(str(ErrorCode.REQUIRED), "required")


    def test_composed_drf_error_codes(self):
        """Test that the ErrorCode values derived from DRF error codes are stable."""
        self.assertEqual(ErrorCode.INVALID, "invalid")
        self.assertEqual(ErrorCode.PARSE_ERROR, "parse_error")
        self.assertEqual(ErrorCode.AUTHENTICATION_FAILED, "authentication_failed")
        self.assertEqual(ErrorCode.NOT_AUTHENTICATED, "not_authenticated")
        self.assertEqual(ErrorCode.PERMISSION_DENIED, "permission_denied")
        self.assertEqual(ErrorCode.NOT_FOUND, "not_found")
        self.assertEqual(ErrorCode.METHOD_NOT_ALLOWED, "method_not_allowed")
        self.assertEqual(ErrorCode.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
        self.assertEqual(ErrorCode.THROTTLED, "throttled")
