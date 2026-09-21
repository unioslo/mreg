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