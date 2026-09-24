from collections.abc import Generator
import importlib
import pkgutil
import unittest

from mreg import models
from hostpolicy import models as hostpolicy_models
from mreg.models.base import BaseModel
from mreg.utils import display_name


def _all_subclasses(cls: type) -> Generator[type, None, None]:
    """Recursively yield all subclasses of a given class."""
    for sub in cls.__subclasses__():
        yield sub
        yield from _all_subclasses(sub)


class TestUtils(unittest.TestCase):
    def test_display_name(self):
        """Test that display_name() works for all models in the project."""
        # import every sub-module in mreg.models so all model classes are loaded
        for mod in pkgutil.iter_modules(models.__path__):
            importlib.import_module(f"{models.__name__}.{mod.name}")

        all_models = list(_all_subclasses(BaseModel))
        all_models.extend(_all_subclasses(hostpolicy_models.HostPolicyComponent))

        # Ensure we actually collected something
        self.assertGreater(len(all_models), 0)

        for model in all_models:
            # NOTE: passing display_name(model) to the subTest message arg is a bit hacky,
            # but it lets us see the display name of the model in the test output
            with self.subTest(display_name(model), model=model.__name__):
                # ensure we can call display_name on all models in the project
                self.assertIsInstance(display_name(model), str)
