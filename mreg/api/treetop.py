from __future__ import annotations
import logging
from typing import Any, Optional, Mapping
import ipaddress
import json

from django.conf import settings
from rest_framework.request import Request
from django.views import View

from mreg.models.auth import User as MregUser  # your request->user wrapper

from treetop_client.client import TreeTopClient
from treetop_client.models import Request as TreeTopRequest, User as TreeTopUser, Action, Resource, ResourceAttribute, ResourceAttributeType

logger = logging.getLogger("mreg.policy.parity")

# Configure these in settings.py
POLICY_PARITY_ENABLED = getattr(settings, "POLICY_PARITY_ENABLED", True)
POLICY_BASE_URL = getattr(settings, "POLICY_BASE_URL", "http://localhost:9999")
POLICY_NAMESPACE = getattr(settings, "POLICY_NAMESPACE", ["MREG"])
POLICY_EXTRA_LOG_FILE_NAME = getattr(settings, "POLICY_EXTRA_LOG_FILE_NAME", "policy_parity.log")
POLICY_TRUNCATE_LOG_FILE = getattr(settings, "POLICY_TRUNCATE_LOG_FILE", True)

if POLICY_TRUNCATE_LOG_FILE:
    with open(POLICY_EXTRA_LOG_FILE_NAME, "w"):
        pass

treetopclient = TreeTopClient(base_url=POLICY_BASE_URL)

def _corr_id(request: Request) -> Optional[str]:
    return request.headers.get("X-Correlation-ID") or request.META.get("HTTP_X_CORRELATION_ID")

def _model_name_from_view(view) -> str:  # type: ignore
    # Best effort: try serializer model, else view class name
    try:
        sc = view.get_serializer_class()
        return sc.Meta.model.__name__
    except Exception:
        return view.__class__.__name__

def policy_parity(
    decision: bool,
    *,
    request: Request,
    view: Optional[View] = None,
    permission_class: Optional[str] = None,
    action: str,
    resource_kind: str,
    resource_id: str,
    resource_attrs: Mapping[str, str],
) -> bool:
    """
    Log legacy-vs-policy parity and return `decision` unchanged.
    Use this anywhere you currently 'return True/False'.
    """
    if not POLICY_PARITY_ENABLED:
        return decision

    # Build policy request
    muser = MregUser.from_request(request)
    principal = TreeTopUser.new(muser.username, POLICY_NAMESPACE, groups=list(muser.group_list))
    pol_action = Action.new(action, POLICY_NAMESPACE)

    attrs = {}

    for k, v in resource_attrs.items():
        try:
            ip = ipaddress.ip_address(v)
            attrs[k] = ResourceAttribute.new(str(ip), ResourceAttributeType.IP)
        except ValueError:
            attrs[k] = ResourceAttribute.new(v, ResourceAttributeType.STRING)
#            if v.isdigit():
#                attrs[k] = ResourceAttribute.new(v, ResourceAttributeType.NUMBER)
#            elif v.lower() in ("true", "false"):
#                attrs[k] = ResourceAttribute.new(v.lower(), ResourceAttributeType.BOOLEAN)
#            else:
#                attrs[k] = ResourceAttribute.new(v, ResourceAttributeType.STRING)

    res = Resource.new(resource_kind, resource_id, attrs=attrs)

    if len(pol_action.id.namespace) > 0:
        fully_qualified_action = "::".join(pol_action.id.namespace) + f"::{pol_action.id.id}"
    else:
        fully_qualified_action = f"{pol_action.id.id}"

    context = {
        "path": request.path,
        "method": request.method,
        "permission": permission_class or (view and view.__class__.__name__),
        "view": view and view.__class__.__name__,
        "model": _model_name_from_view(view),
        "principal": muser.username,
        "groups": list(muser.group_list),
        "action": fully_qualified_action,
        "resource_kind": resource_kind,
        "resource_attrs": resource_attrs,
        "correlation_id": _corr_id(request),
    }

    pol_allowed, error = None, None
    try:
        resp = treetopclient.check(TreeTopRequest(principal=principal, action=pol_action, resource=res))
        pol_allowed = bool(resp.is_allowed())
    except Exception as exc:
        error = repr(exc)

    parity = False
    if bool(decision) and pol_allowed:
        parity = True
    elif not bool(decision) and not pol_allowed:
        parity = True

    payload: dict[str, object] = {
        "parity": parity,
        "legacy_decision": bool(decision),
        "policy_decision": pol_allowed,
        "error": error,
        "context": context,
    }

    if parity:
        logger.warning("policy_parity_mismatch", extra=payload)
        log_policy_parity(payload)
    else:
        logger.info("policy_parity_ok", extra=payload)
        log_policy_parity(payload)

    return decision

# Log data to a file in addition to normal logging
def log_policy_parity(payload: dict[str, Any]):
    with open(POLICY_EXTRA_LOG_FILE_NAME, "a") as log_file:
        log_file.write(f"{json.dumps(payload)}\n")
