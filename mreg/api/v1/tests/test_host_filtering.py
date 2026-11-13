from urllib.parse import parse_qs, urlsplit

from django.db import connection
from django.test.utils import CaptureQueriesContext

from mreg.models.host import Host, Ipaddress, PtrOverride
from mreg.models.network import Network

from .tests import MregAPITestCase


class HostFilteringTestCase(MregAPITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.alpha = Host.objects.create(name="alpha.example.org", comment="Multihomed host")
        cls.beta = Host.objects.create(name="beta.example.org")
        cls.shared = Host.objects.create(name="shared.example.org")
        cls.outside = Host.objects.create(name="outside.example.org")
        cls.no_ip = Host.objects.create(name="no-ip.example.org")
        cls.ptr_only = Host.objects.create(name="ptr-only.example.org")
        for host, addresses in (
            (cls.alpha, ("158.36.188.0", "158.36.188.10", "158.36.188.11", "192.0.2.10", "2001:db8::1", "2001:db8::2")),
            (cls.beta, ("158.36.189.255", "2001:db8:0:1::ffff")),
            (cls.shared, ("158.36.188.10",)),
            (cls.outside, ("158.36.187.255", "158.36.190.0", "2001:db8:0:2::1")),
        ):
            Ipaddress.objects.bulk_create(Ipaddress(host=host, ipaddress=address) for address in addresses)
        PtrOverride.objects.create(host=cls.ptr_only, ipaddress="158.36.188.20")
        cls.alpha._add_contact("admin@example.org")

    def get_hosts(self, params, expected_status=200):
        response = self.client.get("/api/v1/hosts/", params)
        self.assertEqual(response.status_code, expected_status, response.data)
        return response

    def test_ip_range_matches_any_cidr_without_registered_networks(self):
        self.assertFalse(Network.objects.exists())
        for cidr, hosts in (
            ("158.36.188.0/23", [self.alpha, self.beta, self.shared]),
            ("158.36.188.0/28", [self.alpha, self.shared]),
            ("158.36.188.10/31", [self.alpha, self.shared]),
            ("158.36.188.10/32", [self.alpha, self.shared]),
            ("158.36.188.10", [self.alpha, self.shared]),
            ("158.36.188.10/23", [self.alpha, self.beta, self.shared]),
            ("198.51.100.0/24", []),
            ("0.0.0.0/0", [self.alpha, self.beta, self.shared, self.outside]),
            ("2001:db8::/63", [self.alpha, self.beta]),
            ("2001:db8::/64", [self.alpha]),
            ("2001:db8::/127", [self.alpha]),
            ("2001:db8::1/128", [self.alpha]),
            ("2001:db8::1/63", [self.alpha, self.beta]),
            ("::/0", [self.alpha, self.beta, self.outside]),
        ):
            with self.subTest(cidr=cidr):
                response = self.get_hosts({"ip_range": cidr})
                self.assertEqual(response.data["count"], len(hosts))
                self.assertEqual([host["id"] for host in response.data["results"]], [host.pk for host in hosts])

    def test_ip_range_includes_ipv6_range_edges(self):
        Ipaddress.objects.create(host=self.alpha, ipaddress="2001:db8:abcd::")
        Ipaddress.objects.create(host=self.beta, ipaddress="2001:db8:abcd:0:ffff:ffff:ffff:ffff")
        Ipaddress.objects.create(host=self.outside, ipaddress="2001:db8:abcc:ffff:ffff:ffff:ffff:ffff")
        Ipaddress.objects.create(host=self.outside, ipaddress="2001:db8:abcd:1::")
        response = self.get_hosts({"ip_range": "2001:db8:abcd::/64"})
        self.assertEqual(response.data["count"], 2)
        self.assertEqual([host["id"] for host in response.data["results"]], [self.alpha.pk, self.beta.pk])

    def test_ip_range_accepts_encoded_and_unencoded_cidrs(self):
        for cidr in ("158.36.188.0/23", "2001:db8::/63"):
            with self.subTest(cidr=cidr):
                expected = self.get_hosts({"ip_range": cidr})
                unencoded = self.assert_get(f"/hosts/?ip_range={cidr}")
                self.assertEqual(unencoded.data, expected.data)
        self.assert_get_and_400("/hosts/?ip_range=158.36.188.0%252F23")

    def test_cidr_can_span_registered_networks_or_select_a_subnet(self):
        Network.objects.create(network="158.36.188.0/24")
        Network.objects.create(network="158.36.189.0/24")
        response = self.get_hosts({"ip_range": "158.36.188.0/23"})
        self.assertEqual(response.data["count"], 3)
        response = self.get_hosts({"ip_range": "158.36.188.0/28"})
        self.assertEqual(response.data["count"], 2)

    def test_ip_range_returns_complete_host_records(self):
        with self.temporary_client_as_normal_user():
            response = self.get_hosts({"ip_range": "158.36.188.0/23"})
            detail = self.assert_get(f"/hosts/{self.alpha.name}")
        self.assertEqual(response.data["results"][0], detail.data)
        self.assertEqual(len(response.data["results"][0]["ipaddresses"]), 6)
        self.assertEqual(response.data["results"][0]["contact"], "admin@example.org")

    def test_ip_range_query_count_does_not_grow_with_page_size(self):
        with CaptureQueriesContext(connection) as small:
            self.get_hosts({"ip_range": "158.36.188.0/23", "page_size": 1})
        with CaptureQueriesContext(connection) as full:
            response = self.get_hosts({"ip_range": "158.36.188.0/23"})
        self.assertEqual(len(response.data["results"]), 3)
        self.assertLessEqual(len(full), len(small))

    def test_ip_range_pagination_preserves_filters_and_ordering(self):
        response = self.get_hosts({
            "ip_range": "158.36.188.0/23", "page_size": 1, "ordering": "name", "format": "json",
        })
        names = []
        while True:
            self.assertEqual(response.data["count"], 3)
            self.assertEqual(len(response.data["results"]), 1)
            names.append(response.data["results"][0]["name"])
            next_page = response.data["next"]
            if next_page is None:
                break
            params = parse_qs(urlsplit(next_page).query)
            self.assertEqual(params["ip_range"], ["158.36.188.0/23"])
            response = self.client.get(next_page)
            self.assertEqual(response.status_code, 200)
        self.assertEqual(names, [self.alpha.name, self.beta.name, self.shared.name])

    def test_name_in_is_case_insensitive_and_returns_only_requested_hosts(self):
        response = self.get_hosts({
            "name__in": f"{self.alpha.name.upper()}, {self.no_ip.name},{self.alpha.name},missing.example.org",
        })
        self.assertEqual(response.data["count"], 2)
        self.assertEqual([host["id"] for host in response.data["results"]], [self.alpha.pk, self.no_ip.pk])
        response = self.get_hosts({"name__in": "missing.example.org"})
        self.assertEqual(response.data["count"], 0)

    def test_ip_range_combines_with_other_host_filters(self):
        response = self.get_hosts({
            "ip_range": "158.36.188.0/23", "name__in": f"{self.alpha.name},{self.outside.name}",
        })
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], self.alpha.pk)
        response = self.get_hosts({"ip_range": "158.36.188.0/28", "name__endswith": "a.example.org"})
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], self.alpha.pk)
        # Another IP filter may match an address outside the selected CIDR.
        response = self.get_hosts({
            "ip_range": "158.36.188.0/23", "ipaddresses__ipaddress": "192.0.2.10",
        })
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], self.alpha.pk)

    def test_invalid_cidr_returns_400_with_helpful_message(self):
        for value in ("invalid", "158.36.188.0/33", "2001:db8::/129"):
            with self.subTest(value=value):
                response = self.get_hosts({"ip_range": value}, expected_status=400)
                error = response.data["errors"][0]
                self.assertEqual(error["attr"], "ip_range")
                self.assertIn(f"Invalid CIDR '{value}'", error["detail"])
                self.assertIn("192.0.2.0/24", error["detail"])
                self.assertIn("2001:db8::/64", error["detail"])

    def test_empty_filters_and_unknown_parameters_use_default_behavior(self):
        for params in ({"ip_range": ""}, {"ip_range": " "}, {"name__in": ""}, {"unknown": "anything"}):
            with self.subTest(params=params):
                response = self.get_hosts({"name": self.alpha.name, **params})
                self.assertEqual(response.data["count"], 1)
                self.assertEqual(response.data["results"][0]["id"], self.alpha.pk)

    def test_unfiltered_listing_still_works(self):
        response = self.get_hosts({"page": 1, "page_size": 1000, "search": ""})
        self.assertEqual(response.data["count"], 6)
