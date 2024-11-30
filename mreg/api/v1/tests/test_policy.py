from typing import List, TypeVar

from unittest_parametrize import param, parametrize, ParametrizedTestCase

from enum import Enum

from django.http import HttpResponse

from mreg.models.policy import ApprovedModelForPolicy

from .tests import MregAPITestCase

T = TypeVar("T", bound=Enum)


def sort_enum_list(enum_list: List[T]) -> List[T]:
    """
    Sort a list of Enum members by their value field.

    :param enum_list: List of Enum members to be sorted.
    :returns: Sorted list of Enum members based on their value field.
    """
    return sorted(enum_list, key=lambda enum_item: enum_item.value)

class ModelOkForApproval(Enum):
    """Enum for valid models for approval during testing."""

    HOST = "host"
    NETWORK = "network"
    FORWARDZONE = "forwardzone"
    REVERSEZONE = "reversezone"

    @classmethod
    def values(cls):
        return [item.value for item in cls]
    
class APIApprovedModelTestCase(ParametrizedTestCase, MregAPITestCase):
    """Test API for ApprovedModel"""

    def setUp(self):
        super().setUp()
        self.default_model = ModelOkForApproval.HOST
        self.endpoint = "/policy/approvals/"

    def tearDown(self):
        ApprovedModelForPolicy.objects.all().delete()
        super().tearDown()

    def endpoint_with_id_from_response(self, result: HttpResponse) -> str:
        """Return the endpoint with the id from the response appended.

        :param result: The response object.
        :return: The endpoint with the id appended.

        Example:
        >>> self.endpoint_with_id_from_response(result)
        "/policy/approvals/1"

        Used in the following way:
        >>> self.assert_get(self.endpoint_with_id_from_response(result))
        """
        return f"{self.endpoint}{result.json()['id']}"

    def endpoint_with_content_type(self, content_type: str) -> tuple[str, dict[str, str]]:
        """Return the endpoint and the content_type as a dict.
        
        :param content_type: The content_type to use.
        :return: A tuple containing the endpoint and the content_type.

        Example:

        >>> self.endpoint_with_content_type("Host")
        ("/policy/approvals/", {"content_type": "Host"})

        Used in the following way:
        >>> self.assert_post(*self.endpoint_with_content_type("Host"))

        """
        return self.endpoint, self.content_type(content_type)
    
    def content_type(self, content_type: str) -> dict[str, str]:
        """Return the content_type as a dict.

        :param content_type: The content_type to use.
        :return: The content_type as a dict.

        Example:

        >>> self.content_type("Host")
        {"content_type": "Host"}

        Used in the following way:
        >>> self.assert_post(self.endpoint, self.content_type("Host"))

        """
        return {'content_type': content_type}

    def approve(self, model: ModelOkForApproval) -> HttpResponse:
        """Approve a model, as a superuser."""
        with self.temporary_client_as_superuser():
            return self.assert_post(self.endpoint, self.content_type(model.value))

    @parametrize(("model", "expected_statuscode"), [
            param(ModelOkForApproval.HOST.value, 200, id="Host_200"),
            param(ModelOkForApproval.NETWORK.value, 200, id="Network_200"),
            param(ModelOkForApproval.FORWARDZONE.value, 200, id="ForwardZone_200"),
            param(ModelOkForApproval.REVERSEZONE.value, 200, id="ReverseZone_200"),
            param("BaseModel", 400, id="BaseModel_abstract_400"),
            param("BaseZone", 400, id="BaseZone_abstract_400"),
            param("NotFound", 400, id="NotFound_400"),
        ],
    )
    def test_create_and_get_approval(self, model: str, expected_statuscode: int):
        if expected_statuscode == 200:
            ret = self.assert_post(self.endpoint, self.content_type(model))
            self.assert_get(self.endpoint_with_id_from_response(ret))
        elif expected_statuscode == 400:
            self.assert_post_and_400(self.endpoint, self.content_type(model))

    def test_create_duplicate_409(self):
        self.approve(self.default_model)
        self.assert_post_and_409(self.endpoint, self.content_type(self.default_model.value))

    def test_delete_approval_200(self):
        ret = self.approve(ModelOkForApproval.HOST)
        self.assert_delete(self.endpoint_with_id_from_response(ret))

    def create_and_delete_approval_policy_admin(self):
        with self.temporary_client_as_policy_admin():
            ret = self.assert_post(self.endpoint, self.content_type(ModelOkForApproval.NETWORK.value))
            self.assert_delete(self.endpoint_with_id_from_response(ret))

    def test_create_approval_normal_user_403(self):
        with self.temporary_client_as_normal_user():
            self.assert_post_and_403(self.endpoint, self.content_type(ModelOkForApproval.HOST.value))

    def test_delete_approval_normal_user_403(self):
        ret = self.assert_post(self.endpoint, self.content_type(ModelOkForApproval.HOST.value))
        with self.temporary_client_as_normal_user():
            self.assert_delete_and_403(self.endpoint_with_id_from_response(ret))


    @parametrize(("cased_model"), [
            param("host", id="host"),
            param("Host", id="Host"),
            param("hOsT", id="hOsT"),
            param("HoSt", id="HoSt"),
    ])
    def test_policy_case_insensitive_create_409(self, cased_model: str):
        model = ModelOkForApproval.HOST
        self.approve(model)
        self.assert_post_and_409(self.endpoint, self.content_type(cased_model))
        
    @parametrize(("user"), [
            param("policy_admin", id="policy_admin"),
            param("normal_user", id="normal_user"),
        ])
    def test_list_approvals(self, user: str):
        model_list = sort_enum_list([ModelOkForApproval.HOST,
                                     ModelOkForApproval.FORWARDZONE,
                                     ModelOkForApproval.REVERSEZONE])
        for model in model_list:
            self.approve(model)
    
        if user == "policy_admin":
            kwargs = {"superuser": False, "policyadmin": True}
        else:
            kwargs = {"superuser": False}
        
        with self.temporary_client(**kwargs):
            ret = self.assert_get(self.endpoint).json()['results']
            self.assertEqual(len(ret), len(model_list), f"Expected {len(model_list)} items, got {len(ret)}: {ret}")
            for i in range(len(model_list)):
                self.assertEqual(ret[i]["content_type"], model_list[i].value)
        

    @parametrize(("filter", "expected_hits"), [
        param("content_type=Host", 1, id="Host"),
        param("content_type=host", 1, id="host"),
        param("content_type=forwardzone", 1, id="forwardzone"),
        param("content_type__exact=reversezone", 1, id="reversezone"),
        param("content_type__exact=REVERSEZONE", 1, id="REVERSEZONE"),
        param("content_type__contains=zone", 2, id="contains_zone"),
        param("content_type__contains=reverse", 1, id="contains_reverse"),
        param("content_type__regex=zone.*", 2, id="regex_zone"),
        param("content_type__regex=forward.*", 1, id="regex_forward"),

    ])
    def test_list_approvals_with_filter(self, filter: str, expected_hits: int):
        model_list = sort_enum_list([ModelOkForApproval.HOST,
                                     ModelOkForApproval.FORWARDZONE,
                                     ModelOkForApproval.NETWORK,
                                     ModelOkForApproval.REVERSEZONE])
        for model in model_list:
            self.approve(model)

        url = f"{self.endpoint}?{filter}" 
        target = filter.split("=")[1].lower()
        filter_command = filter.split("=")[0]
        operator = None

        if "__" in filter_command:
            operator = filter_command.split("__")[1]

        ret = self.assert_get(url).json()['results']
        self.assertEqual(len(ret), expected_hits, f"Expected {expected_hits} items, got {len(ret)}: {ret}")

        if not operator or operator == "exact":
            self.assertEqual(ret[0]["content_type"], target)
        elif operator == "contains":
            for item in ret:
                self.assertIn(target, item["content_type"])
            
