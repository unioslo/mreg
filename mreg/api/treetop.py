from __future__ import annotations

import atexit
import asyncio
import ipaddress
import logging
import os
import queue
import threading
from collections.abc import Mapping, Sequence
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from time import monotonic
from typing import Final

from django.conf import settings
from django.views import View
from prometheus_client import Counter, Histogram
from rest_framework.request import Request
import structlog
from treetop_client.client import TreeTopClient
from treetop_client.models import (
    Action,
    AuthorizeResultBrief,
    Request as TreeTopRequest,
    Resource as TreeTopResource,
    ResourceAttribute,
    ResourceAttributeType,
    User as TreeTopUser,
)

from mreg.models.auth import User as MregUser

logger = structlog.get_logger("mreg.policy.parity")

POLICY_PARITY_ENABLED = getattr(settings, "POLICY_PARITY_ENABLED", True)
POLICY_BASE_URL = (getattr(settings, "POLICY_BASE_URL", "") or "").strip()
POLICY_NAMESPACE = getattr(settings, "POLICY_NAMESPACE", ["MREG"])
POLICY_PARITY_BATCH_ENABLED = getattr(settings, "POLICY_PARITY_BATCH_ENABLED", True)
POLICY_PARITY_LOG_DETAILS = getattr(settings, "POLICY_PARITY_LOG_DETAILS", False)
POLICY_PARITY_QUEUE_SIZE = getattr(settings, "POLICY_PARITY_QUEUE_SIZE", 100)
POLICY_TIMEOUT_SECONDS = getattr(settings, "POLICY_TIMEOUT_SECONDS", 5.0)


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

POLICY_PARITY_BATCHES_TOTAL = Counter(
    "mreg_policy_parity_batches_total",
    "Policy parity batches submitted to or dropped by the background worker.",
    ["status"],
)

POLICY_PARITY_FAILURES_TOTAL = Counter(
    "mreg_policy_parity_failures_total",
    "Policy parity instrumentation failures that did not affect the legacy decision.",
    ["stage"],
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
    "Number of policy authorize batches submitted per HTTP request.",
    buckets=[0, 1, 2, 3, 5, 8],
)


@dataclass(frozen=True, slots=True)
class PolicyResource:
    """Explicit resource contract for a policy parity check."""

    kind: str
    id: str
    attrs: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.kind.strip():
            raise ValueError("Policy resource kind cannot be empty")
        if not self.id:
            raise ValueError("Policy resource ID cannot be empty")
        if not self.attrs:
            raise ValueError("Policy resource attributes cannot be empty")


@dataclass(frozen=True, slots=True)
class PolicyCheck:
    """Typed action/resource pair evaluated by TreeTop."""

    action: str
    resource: PolicyResource

    def __post_init__(self) -> None:
        if not self.action.strip():
            raise ValueError("Policy action cannot be empty")


@dataclass(slots=True)
class _ParityBatchItem:
    decision: bool
    policy_request: TreeTopRequest
    context: dict[str, object]


@dataclass(slots=True)
class _RequestParityState:
    items: list[_ParityBatchItem] = field(default_factory=list)
    submitted_queries: int = 0


_request_state: ContextVar[_RequestParityState | None] = ContextVar(
    "policy_parity_request_state",
    default=None,
)
_parity_disabled_depth: ContextVar[int] = ContextVar(
    "policy_parity_disabled_depth",
    default=0,
)

_client: TreeTopClient | None = None
_client_pid: int | None = None
_client_lock = threading.Lock()


def _get_treetop_client() -> TreeTopClient:
    """Return a process-local client, creating it only on first use."""
    global _client, _client_pid

    pid = os.getpid()
    with _client_lock:
        if _client is None or _client_pid != pid:
            if _client is not None:
                _client.close()
            _client = TreeTopClient(
                base_url=POLICY_BASE_URL,
                timeout=float(POLICY_TIMEOUT_SECONDS),
            )
            _client_pid = pid
        return _client


def _close_treetop_client() -> None:
    """Close both transports owned by the process-local TreeTop client."""
    global _client, _client_pid

    with _client_lock:
        client = _client
        _client = None
        _client_pid = None
    if client is None:
        return
    try:
        asyncio.run(client.aclose())
    except Exception:
        client.close()


class _ParityDispatcher:
    """Bounded, process-local worker that keeps parity I/O off request threads."""

    _STOP: Final = object()

    def __init__(self, max_queue_size: int) -> None:
        self._queue: queue.Queue[list[_ParityBatchItem] | object] = queue.Queue(maxsize=max(1, max_queue_size))
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()

    def submit(self, items: Sequence[_ParityBatchItem]) -> bool:
        if not items:
            return False
        self._ensure_started()
        try:
            self._queue.put_nowait(list(items))
        except queue.Full:
            with suppress(Exception):
                POLICY_PARITY_BATCHES_TOTAL.labels(status="dropped").inc()
            _safe_log(
                logging.ERROR,
                "policy_parity_queue_full",
                queue_size=self._queue.maxsize,
                batch_size=len(items),
            )
            return False
        with suppress(Exception):
            POLICY_PARITY_BATCHES_TOTAL.labels(status="submitted").inc()
        return True

    def _ensure_started(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        with self._start_lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=self._run,
                    name="mreg-policy-parity",
                    daemon=True,
                )
                self._thread.start()

    def _run(self) -> None:
        while True:
            items = self._queue.get()
            try:
                if items is self._STOP:
                    return
                _process_policy_parity_batch(items)
            except Exception as exc:
                _record_instrumentation_failure(exc, stage="worker")
            finally:
                self._queue.task_done()

    def shutdown(self) -> None:
        thread = self._thread
        if thread is None or not thread.is_alive():
            return
        with suppress(queue.Full):
            self._queue.put_nowait(self._STOP)
        thread.join(timeout=1.0)


_dispatcher: _ParityDispatcher | None = None
_dispatcher_pid: int | None = None
_dispatcher_lock = threading.Lock()


def _get_dispatcher() -> _ParityDispatcher:
    global _dispatcher, _dispatcher_pid

    pid = os.getpid()
    with _dispatcher_lock:
        if _dispatcher is None or _dispatcher_pid != pid:
            _dispatcher = _ParityDispatcher(int(POLICY_PARITY_QUEUE_SIZE))
            _dispatcher_pid = pid
        return _dispatcher


def _shutdown_policy_runtime() -> None:
    if _dispatcher is not None and _dispatcher_pid == os.getpid():
        _dispatcher.shutdown()
    _close_treetop_client()


atexit.register(_shutdown_policy_runtime)


def _safe_log(level: int, event: str, **context: object) -> None:
    with suppress(Exception):
        logger.log(level, event, **context)


def _record_instrumentation_failure(exc: Exception, *, stage: str) -> None:
    with suppress(Exception):
        POLICY_PARITY_FAILURES_TOTAL.labels(stage=stage).inc()
    _safe_log(
        logging.ERROR,
        "policy_parity_instrumentation_error",
        stage=stage,
        error_type=type(exc).__name__,
        error_msg=str(exc),
    )


def _submit_policy_batch(items: Sequence[_ParityBatchItem]) -> bool:
    try:
        return _get_dispatcher().submit(items)
    except Exception as exc:
        _record_instrumentation_failure(exc, stage="submit")
        return False


@contextmanager
def batch_policy_parity():
    """Collect one request's parity checks and enqueue them as one batch."""
    if _request_state.get() is not None:
        yield
        return

    state = _RequestParityState()
    token = _request_state.set(state)
    try:
        yield
    finally:
        try:
            if POLICY_PARITY_BATCH_ENABLED and state.items:
                if _submit_policy_batch(state.items):
                    state.submitted_queries += 1
            with suppress(Exception):
                POLICY_QUERIES_PER_REQUEST.observe(float(state.submitted_queries))
        except Exception as exc:
            _record_instrumentation_failure(exc, stage="request_exit")
        finally:
            _request_state.reset(token)


@contextmanager
def disable_policy_parity():
    """Temporarily disable parity checks in the current execution context."""
    token = _parity_disabled_depth.set(_parity_disabled_depth.get() + 1)
    try:
        yield
    finally:
        _parity_disabled_depth.reset(token)


def _is_parity_enabled() -> bool:
    return bool(POLICY_PARITY_ENABLED and POLICY_BASE_URL and _parity_disabled_depth.get() == 0)


def _corr_id(request: Request) -> str | None:
    return request.headers.get("X-Correlation-ID") or request.META.get("HTTP_X_CORRELATION_ID")


def _model_name_from_view(view: View | None) -> str | None:
    if view is None:
        return None
    try:
        serializer_class = view.get_serializer_class()  # type: ignore[attr-defined]
        return serializer_class.Meta.model.__name__
    except (AttributeError, TypeError):
        return None


def _build_resource_attrs(
    resource_attrs: Mapping[str, str],
) -> dict[str, ResourceAttribute]:
    attrs: dict[str, ResourceAttribute] = {}
    for key, value in resource_attrs.items():
        try:
            ip = ipaddress.ip_address(value)
            attrs[key] = ResourceAttribute.new(str(ip), ResourceAttributeType.IP)
        except ValueError:
            attrs[key] = ResourceAttribute.new(value, ResourceAttributeType.STRING)
    return attrs


def _fully_qualified_action(action: Action) -> str:
    return str(action)


def _qualified_resource_kind(kind: str) -> str:
    return "::".join([*POLICY_NAMESPACE, kind]) if POLICY_NAMESPACE else kind


def _build_policy_request(muser: MregUser, check: PolicyCheck) -> TreeTopRequest:
    """Build a typed request using the bundle's qualified resource kind."""
    principal = TreeTopUser.new(
        str(muser.username),
        POLICY_NAMESPACE,
        groups=list(muser.group_list),
    )
    action = Action.new(check.action, POLICY_NAMESPACE)
    attrs = _build_resource_attrs(check.resource.attrs)
    return TreeTopRequest(
        principal=principal,
        action=action,
        resource=TreeTopResource.new(
            kind=_qualified_resource_kind(check.resource.kind),
            id=check.resource.id,
            attrs=attrs,
        ),
    )


def _compute_parity_payload(
    *,
    decision: bool,
    policy_allowed: bool | None,
    error: str | None,
    context: dict[str, object],
) -> dict[str, object]:
    parity = policy_allowed is not None and bool(decision) is policy_allowed
    return {
        "parity": parity,
        "legacy_decision": bool(decision),
        "policy_decision": policy_allowed,
        "error": error,
        "context": context,
    }


def _log_parity_payload(payload: dict[str, object]) -> None:
    try:
        legacy_decision = payload["legacy_decision"]
        POLICY_LEGACY_DECISIONS_TOTAL.labels(decision="allow" if legacy_decision is True else "deny").inc()

        policy_decision = payload["policy_decision"]
        if policy_decision is True:
            policy_label = "allow"
        elif policy_decision is False:
            policy_label = "deny"
        else:
            policy_label = "error"
        POLICY_DECISIONS_TOTAL.labels(decision=policy_label).inc()

        if payload["error"] is not None or policy_decision is None:
            result = "error"
        elif payload["parity"] is True:
            result = "match"
        else:
            result = "mismatch"
        POLICY_PARITY_RESULTS_TOTAL.labels(result=result).inc()

        level = logging.INFO if payload["parity"] is True else logging.WARNING
        event = "policy_parity_ok" if payload["parity"] is True else "policy_parity_mismatch"
        _safe_log(level, event, **payload)
    except Exception as exc:
        _record_instrumentation_failure(exc, stage="result_logging")


def _result_to_decision_and_error(
    results: Sequence[AuthorizeResultBrief],
    index: int,
) -> tuple[bool | None, str | None]:
    if index >= len(results):
        return None, f"Missing policy result at index {index}"

    result = results[index]
    if result.is_success():
        return result.is_allowed(), None
    return None, result.error or f"Authorization failed with status={result.status}"


def _authorize_with_metrics(
    *,
    policy_requests: Sequence[TreeTopRequest],
    correlation_id: str | None,
    path: str | None,
) -> tuple[list[AuthorizeResultBrief], str | None]:
    if not policy_requests:
        return [], None

    request_count = len(policy_requests)
    POLICY_REQUESTS_PER_AUTHORIZE.observe(float(request_count))
    started = monotonic()
    try:
        response = _get_treetop_client().authorize(
            policy_requests,
            correlation_id=correlation_id,
        )
    except Exception as exc:
        POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="exception").inc()
        POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="exception").observe(monotonic() - started)
        _safe_log(
            logging.ERROR,
            "policy_server_error",
            error_type=type(exc).__name__,
            error_msg=str(exc),
            path=path,
            correlation_id=correlation_id,
            batch_size=request_count,
        )
        return [], repr(exc)

    POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="success").inc()
    POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="success").observe(monotonic() - started)
    return response.results, None


def _process_policy_parity_batch(items: Sequence[_ParityBatchItem]) -> None:
    """Evaluate and record one batch. This function runs outside request threads."""
    if not items:
        return

    correlation_id = items[0].context.get("correlation_id")
    path = items[0].context.get("path")
    results, authorize_error = _authorize_with_metrics(
        policy_requests=[item.policy_request for item in items],
        correlation_id=correlation_id if isinstance(correlation_id, str) else None,
        path=path if isinstance(path, str) else None,
    )
    for index, item in enumerate(items):
        if authorize_error is None:
            policy_allowed, error = _result_to_decision_and_error(results, index)
        else:
            policy_allowed, error = None, authorize_error
        _log_parity_payload(
            _compute_parity_payload(
                decision=item.decision,
                policy_allowed=policy_allowed,
                error=error,
                context=item.context,
            )
        )


def flush_policy_parity_batch() -> bool:
    """Enqueue and clear the current request batch, if one exists."""
    state = _request_state.get()
    if state is None or not state.items:
        return False
    items = list(state.items)
    state.items.clear()
    submitted = _submit_policy_batch(items)
    if submitted:
        state.submitted_queries += 1
    return submitted


def policy_parity(
    decision: bool,
    *,
    request: Request,
    check: PolicyCheck,
    view: View | None = None,
    permission_class: str | None = None,
) -> bool:
    """Queue a policy comparison and always preserve the legacy decision."""
    if not _is_parity_enabled():
        return decision

    try:
        muser = MregUser.from_request(request)
        policy_request = _build_policy_request(muser, check)
        policy_action = Action.new(check.action, POLICY_NAMESPACE)
        context: dict[str, object] = {
            "path": request.path,
            "method": request.method,
            "permission": permission_class or (view and view.__class__.__name__),
            "view": view and view.__class__.__name__,
            "model": _model_name_from_view(view),
            "action": _fully_qualified_action(policy_action),
            "resource_kind": _qualified_resource_kind(check.resource.kind),
            "correlation_id": _corr_id(request),
        }
        if POLICY_PARITY_LOG_DETAILS:
            context.update(
                {
                    "principal": muser.username,
                    "groups": list(muser.group_list),
                    "resource_id": check.resource.id,
                    "resource_attrs": dict(check.resource.attrs),
                }
            )

        item = _ParityBatchItem(
            decision=bool(decision),
            policy_request=policy_request,
            context=context,
        )
        state = _request_state.get()
        if state is not None and POLICY_PARITY_BATCH_ENABLED:
            state.items.append(item)
        elif _submit_policy_batch([item]) and state is not None:
            state.submitted_queries += 1
    except Exception as exc:
        _record_instrumentation_failure(exc, stage="build")
    return decision
