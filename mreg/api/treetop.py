from __future__ import annotations
import logging
from typing import Any, Optional

from django.conf import settings
from rest_framework.request import Request
from django.views import View

from mreg.models.auth import User as MregUser  # your request->user wrapper

from treetop_client.client import TreeTopClient
from treetop_client.models import Request as TreeTopRequest, User as TreeTopUser, Action as TreeTopAction, Resource as TreeTopResource

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
    resource_attrs: dict[str, Any],
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
    pol_action = TreeTopAction.new(action, POLICY_NAMESPACE)
    res = TreeTopResource.new(resource_kind, resource_attrs)

    context = {
        "path": request.path,
        "method": request.method,
        "permission": permission_class or (view and view.__class__.__name__),
        "view": view and view.__class__.__name__,
        "resource_kind": resource_kind,
        "action": getattr(pol_action, "name", str(pol_action)),
        "principal": muser.username,
        "groups": list(muser.group_list),
        "model": _model_name_from_view(view),
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
        **context,
        "legacy_decision": bool(decision),
        "policy_decision": pol_allowed,
        "parity": parity,
        "resource_attrs": resource_attrs,
        "error": error,
    }

    if parity:
        logger.warning("policy_parity_mismatch", extra=payload)
        log_policy_parity("OK", payload)
    else:
        logger.info("policy_parity_ok", extra=payload)
        log_policy_parity("MISMATCH", payload)

    return decision

# Log data to a file in addition to normal logging
def log_policy_parity(result: str, payload: dict[str, Any]):
    with open(POLICY_EXTRA_LOG_FILE_NAME, "a") as log_file:
        log_file.write(f"{result}: {payload}\n")
