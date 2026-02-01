from django.test import TestCase

from mreg.netfields_compat import patch_netfields_for_django52


class NetfieldsCompatTests(TestCase):
    def test_patch_converts_tuple_params_to_list(self):
        from netfields.lookups import NetFieldDecoratorMixin

        original_process_lhs = NetFieldDecoratorMixin.process_lhs

        def tuple_process_lhs(self, qn, connection, lhs=None):
            return "lhs", ("param",)

        try:
            NetFieldDecoratorMixin.process_lhs = tuple_process_lhs

            patch_netfields_for_django52()

            lhs_string, lhs_params = NetFieldDecoratorMixin().process_lhs(None, None)
            self.assertEqual(lhs_string, "lhs")
            self.assertEqual(lhs_params, ["param"])
        finally:
            NetFieldDecoratorMixin.process_lhs = original_process_lhs
