def load_tests(loader, standard_tests, pattern):
    """Hide this package from Django/unittest discovery.
    
    Uses the load_tests protocol to hide this package from unittest discovery.
    Source: <https://docs.python.org/3/library/unittest.html#load-tests-protocol>
    """
    return loader.suiteClass()