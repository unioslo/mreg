from django.test import SimpleTestCase

from mreg.api.errors import ErrorCode



class ErrorCodeTestCase(SimpleTestCase):
    def test_error_code_in_f_strings(self):
        # We need to make sure these behave consistently as strings and f-strings
        # since Python 3.11 brought breaking changes to f-string evaluation of enums.
        # See: https://blog.pecar.me/python-enum/
        message = f"Error code is {ErrorCode.REQUIRED}"
        self.assertEqual(str(ErrorCode.REQUIRED), "required")
        self.assertEqual(message, "Error code is required")


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
