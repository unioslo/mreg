from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Any, Optional, Mapping, Sequence
import ipaddress
import json
import multiprocessing
import os
import threading
from contextlib import contextmanager
from time import monotonic

from django.conf import settings
from rest_framework.request import Request
from django.views import View
from prometheus_client import Counter, Histogram

from mreg.models.auth import User as MregUser  # your request->user wrapper

from treetop_client.client import TreeTopClient
from treetop_client.models import Request as TreeTopRequest, User as TreeTopUser, Action, Resource, ResourceAttribute, ResourceAttributeType

logger = logging.getLogger("mreg.policy.parity")

# Thread-local storage for parity checking bypass flag
_thread_local = threading.local()

# Configure these in settings.py
POLICY_PARITY_ENABLED = getattr(settings, "POLICY_PARITY_ENABLED", True)
POLICY_BASE_URL = getattr(settings, "POLICY_BASE_URL", "http://localhost:9999")
POLICY_NAMESPACE = getattr(settings, "POLICY_NAMESPACE", ["MREG"])
POLICY_EXTRA_LOG_FILE_NAME = getattr(settings, "POLICY_EXTRA_LOG_FILE_NAME", "policy_parity.log")
POLICY_TRUNCATE_LOG_FILE = getattr(settings, "POLICY_TRUNCATE_LOG_FILE", True)
POLICY_PARITY_BATCH_ENABLED = getattr(settings, "POLICY_PARITY_BATCH_ENABLED", True)
_POLICY_PARITY_LOG_INITIALIZED_ENV = "MREG_POLICY_PARITY_LOG_INITIALIZED"


def _initialize_policy_parity_log_file() -> None:
    """Truncate the parity log once in the main process.

    Parallel test workers import this module too. Guarding on the main process
    and an environment marker prevents workers from re-truncating the file.
    """
    if not POLICY_TRUNCATE_LOG_FILE:
        return
    if multiprocessing.current_process().name != "MainProcess":
        return
    if os.environ.get(_POLICY_PARITY_LOG_INITIALIZED_ENV) == "1":
        return
    with open(POLICY_EXTRA_LOG_FILE_NAME, "w"):
        pass
    os.environ[_POLICY_PARITY_LOG_INITIALIZED_ENV] = "1"


_initialize_policy_parity_log_file()

treetopclient = TreeTopClient(base_url=POLICY_BASE_URL)

POLICY_DECISIONS_TOTAL = Counter(
    "mreg_policy_decisions_total",
    "Total policy decisions from the external policy engine.",
    ["decision"],
)

POLICY_LEGACY_DECISIONS_TOTAL = Counter(
    "mreg_policy_legacy_decisions_total",
    "Total legacy permission decisions used for parity comparison.",
    ["decision"],
)

POLICY_PARITY_RESULTS_TOTAL = Counter(
    "mreg_policy_parity_results_total",
    "Parity comparison outcomes between legacy and external policy decisions.",
    ["result"],
)

POLICY_AUTHORIZE_CALLS_TOTAL = Counter(
    "mreg_policy_authorize_calls_total",
    "Total calls to the policy authorize endpoint.",
    ["status"],
)

POLICY_AUTHORIZE_DURATION_SECONDS = Histogram(
    "mreg_policy_authorize_duration_seconds",
    "Duration of policy authorize endpoint calls in seconds.",
    ["status"],
    buckets=[0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)

POLICY_REQUESTS_PER_AUTHORIZE = Histogram(
    "mreg_policy_requests_per_authorize",
    "Number of policy requests sent in each authorize call.",
    buckets=[0, 1, 2, 3, 5, 8],
)

POLICY_QUERIES_PER_REQUEST = Histogram(
    "mreg_policy_queries_per_request",
    "Number of policy authorize queries made per HTTP request.",
    buckets=[0, 1, 2, 3, 5, 8],
)


@dataclass(slots=True)
class _ParityBatchItem:
    """One queued parity check, to be sent via batch authorize."""

    decision: bool
    policy_request: TreeTopRequest
    context: dict[str, Any]


def _batch_depth() -> int:
    return int(getattr(_thread_local, "batch_depth", 0))


def _batch_queue() -> list[_ParityBatchItem]:
    queue = getattr(_thread_local, "batch_queue", None)
    if queue is None:
        queue = []
        _thread_local.batch_queue = queue
    return queue


def _is_batching() -> bool:
    return _batch_depth() > 0 and POLICY_PARITY_BATCH_ENABLED


def _request_authorize_calls() -> int:
    return int(getattr(_thread_local, "policy_authorize_calls", 0))


def _inc_request_authorize_calls() -> None:
    _thread_local.policy_authorize_calls = _request_authorize_calls() + 1


@contextmanager
def batch_policy_parity():
    """Batch parity checks in the current thread and flush on scope exit."""
    current_depth = _batch_depth()
    if current_depth == 0:
        _thread_local.policy_authorize_calls = 0
        if POLICY_PARITY_BATCH_ENABLED:
            _thread_local.batch_queue = []
    _thread_local.batch_depth = current_depth + 1

    try:
        yield
    finally:
        new_depth = _batch_depth() - 1
        _thread_local.batch_depth = max(new_depth, 0)
        if new_depth <= 0:
            try:
                if POLICY_PARITY_BATCH_ENABLED:
                    flush_policy_parity_batch()
            finally:
                POLICY_QUERIES_PER_REQUEST.observe(float(_request_authorize_calls()))
                _thread_local.batch_queue = []
                _thread_local.batch_depth = 0
                _thread_local.policy_authorize_calls = 0

@contextmanager
def disable_policy_parity():
    """Context manager to temporarily disable policy parity checking.
    
    Useful for tests that modify permissions/state mid-test, which would
    cause the legacy and policy systems to be out of sync.
    
    Example:
        def test_permission_changes(self):
            with disable_policy_parity():
                # Modify permissions here
                user.groups.add(some_group)
                # Make API calls - parity checking will be skipped
    """
    old_value = getattr(_thread_local, "skip_parity", False)
    _thread_local.skip_parity = True
    try:
        yield
    finally:
        _thread_local.skip_parity = old_value

def _is_parity_enabled() -> bool:
    """Check if parity checking should be performed in current context."""
    if not POLICY_PARITY_ENABLED:
        return False
    # Skip parity checking if we're in a disabled context
    return not getattr(_thread_local, "skip_parity", False)

def _corr_id(request: Request) -> Optional[str]:
    """Return request correlation ID from standard header variants."""
    return request.headers.get("X-Correlation-ID") or request.META.get("HTTP_X_CORRELATION_ID")

def _model_name_from_view(view) -> str:  # type: ignore
    """Best-effort view model name, preferring serializer Meta.model."""
    # Best effort: try serializer model, else view class name
    try:
        sc = view.get_serializer_class()
        return sc.Meta.model.__name__
    except Exception:
        return view.__class__.__name__


def _build_resource_attrs(resource_attrs: Mapping[str, str]) -> dict[str, ResourceAttribute]:
    attrs: dict[str, ResourceAttribute] = {}
    for key, value in resource_attrs.items():
        try:
            ip = ipaddress.ip_address(value)
            attrs[key] = ResourceAttribute.new(str(ip), ResourceAttributeType.IP)
        except ValueError:
            attrs[key] = ResourceAttribute.new(value, ResourceAttributeType.STRING)
    return attrs


def _fully_qualified_action(action: Action) -> str:
    if len(action.id.namespace) > 0:
        return "::".join(action.id.namespace) + f"::{action.id.id}"
    return f"{action.id.id}"


def _compute_parity_payload(
    *,
    decision: bool,
    pol_allowed: Optional[bool],
    error: Optional[str],
    context: dict[str, Any],
) -> dict[str, Any]:
    parity = False
    if bool(decision) and pol_allowed:
        parity = True
    elif not bool(decision) and pol_allowed is False:
        parity = True

    return {
        "parity": parity,
        "legacy_decision": bool(decision),
        "policy_decision": pol_allowed,
        "error": error,
        "context": context,
    }


def _log_parity_payload(payload: dict[str, Any]) -> None:
    legacy_decision = payload.get("legacy_decision")
    if legacy_decision is True:
        POLICY_LEGACY_DECISIONS_TOTAL.labels(decision="allow").inc()
    else:
        POLICY_LEGACY_DECISIONS_TOTAL.labels(decision="deny").inc()

    policy_decision = payload.get("policy_decision")
    if policy_decision is True:
        POLICY_DECISIONS_TOTAL.labels(decision="allow").inc()
    elif policy_decision is False:
        POLICY_DECISIONS_TOTAL.labels(decision="deny").inc()
    else:
        POLICY_DECISIONS_TOTAL.labels(decision="error").inc()

    if payload.get("error") is not None or policy_decision is None:
        POLICY_PARITY_RESULTS_TOTAL.labels(result="error").inc()
    elif payload["parity"]:
        POLICY_PARITY_RESULTS_TOTAL.labels(result="match").inc()
    else:
        POLICY_PARITY_RESULTS_TOTAL.labels(result="mismatch").inc()

    if payload["parity"]:
        logger.info("policy_parity_ok", extra=payload)
    else:
        logger.warning("policy_parity_mismatch", extra=payload)
    log_policy_parity(payload)


def _result_to_decision_and_error(
    results: Sequence[Any],
    index: int,
) -> tuple[Optional[bool], Optional[str]]:
    if index >= len(results):
        return None, f"Missing policy result at index {index}"

    result = results[index]
    if hasattr(result, "is_success") and result.is_success():
        return bool(result.is_allowed()), None

    status = getattr(result, "status", "unknown")
    error = getattr(result, "error", None) or f"Authorization failed with status={status}"
    return None, str(error)


def flush_policy_parity_batch() -> None:
    """Flush queued parity checks as one authorize batch call."""
    queue = _batch_queue()
    if not queue:
        return

    correlation_id = queue[0].context.get("correlation_id")
    POLICY_REQUESTS_PER_AUTHORIZE.observe(float(len(queue)))
    _inc_request_authorize_calls()
    pol_allowed_by_index: list[Optional[bool]] = [None] * len(queue)
    error_by_index: list[Optional[str]] = [None] * len(queue)

    call_started = monotonic()
    try:
        response = treetopclient.authorize(
            [item.policy_request for item in queue],
            correlation_id=correlation_id,
        )
        POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="success").inc()
        POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="success").observe(monotonic() - call_started)
        results = list(getattr(response, "results", []))
        for idx in range(len(queue)):
            pol_allowed_by_index[idx], error_by_index[idx] = _result_to_decision_and_error(results, idx)
    except Exception as exc:
        POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="exception").inc()
        POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="exception").observe(monotonic() - call_started)
        error = repr(exc)
        logger.error(
            f"Policy server error: {type(exc).__name__}: {exc}",
            extra={
                "error_type": type(exc).__name__,
                "error_msg": str(exc),
                "path": queue[0].context.get("path"),
                "correlation_id": correlation_id,
                "batch_size": len(queue),
            },
        )
        for idx in range(len(queue)):
            error_by_index[idx] = error

    for idx, item in enumerate(queue):
        payload = _compute_parity_payload(
            decision=item.decision,
            pol_allowed=pol_allowed_by_index[idx],
            error=error_by_index[idx],
            context=item.context,
        )
        _log_parity_payload(payload)

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
    if not _is_parity_enabled():
        return decision

    # Build policy request
    muser = MregUser.from_request(request)
    principal = TreeTopUser.new(str(muser.username), POLICY_NAMESPACE, groups=list(muser.group_list))
    pol_action = Action.new(action, POLICY_NAMESPACE)
    attrs = _build_resource_attrs(resource_attrs)
    res = Resource.new(str(resource_kind), resource_id, attrs=attrs)
    pol_request = TreeTopRequest(principal=principal, action=pol_action, resource=res)
    fully_qualified_action = _fully_qualified_action(pol_action)

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

    if _is_batching():
        _batch_queue().append(
            _ParityBatchItem(
                decision=bool(decision),
                policy_request=pol_request,
                context=context,
            )
        )
        return decision

    pol_allowed, error = None, None
    _inc_request_authorize_calls()
    call_started = monotonic()
    try:
        resp = treetopclient.authorize(pol_request, correlation_id=context["correlation_id"])
        POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="success").inc()
        POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="success").observe(monotonic() - call_started)
        POLICY_REQUESTS_PER_AUTHORIZE.observe(1.0)
        results = list(getattr(resp, "results", []))
        pol_allowed, error = _result_to_decision_and_error(results, 0)
    except Exception as exc:
        POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="exception").inc()
        POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="exception").observe(monotonic() - call_started)
        POLICY_REQUESTS_PER_AUTHORIZE.observe(1.0)
        error = repr(exc)
        # Log policy server errors prominently
        logger.error(
            f"Policy server error: {type(exc).__name__}: {exc}",
            extra={
                "error_type": type(exc).__name__,
                "error_msg": str(exc),
                "path": request.path,
                "correlation_id": _corr_id(request),
            },
        )
        # If policy server fails, we cannot determine parity. Return legacy decision
        # but flag this in the payload for monitoring.

    payload = _compute_parity_payload(
        decision=decision,
        pol_allowed=pol_allowed,
        error=error,
        context=context,
    )
    _log_parity_payload(payload)

    return decision

# Log data to a file in addition to normal logging
def log_policy_parity(payload: dict[str, Any]):
    """Append one JSON parity event to the configured parity log file."""
    with open(POLICY_EXTRA_LOG_FILE_NAME, "a") as log_file:
        log_file.write(f"{json.dumps(payload)}\n")
