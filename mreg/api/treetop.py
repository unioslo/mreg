from __future__ import annotations

import atexit
import asyncio
import ipaddress
import logging
import os
import threading
from collections.abc import Mapping, Sequence
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import timedelta
from time import monotonic

from django.conf import settings
from django.db import close_old_connections, transaction
from django.db.models import Q
from django.utils import timezone
from django.views import View
from prometheus_client import Counter, Gauge, Histogram
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
from mreg.models.policy import PolicyParityOutbox
from mreg.policy.config import EnforcementFailureMode, PolicyMode

logger = structlog.get_logger("mreg.policy.parity")

POLICY_MODE = PolicyMode(getattr(settings, "POLICY_MODE", "shadow"))
POLICY_PARITY_ENABLED = getattr(settings, "POLICY_PARITY_ENABLED", POLICY_MODE == PolicyMode.SHADOW)
POLICY_ENFORCEMENT_FAILURE_MODE = EnforcementFailureMode(
    getattr(settings, "POLICY_ENFORCEMENT_FAILURE_MODE", "deny")
)
POLICY_BASE_URL = (getattr(settings, "POLICY_BASE_URL", "") or "").strip()
POLICY_NAMESPACE = getattr(settings, "POLICY_NAMESPACE", ["MREG"])
POLICY_PARITY_BATCH_ENABLED = getattr(settings, "POLICY_PARITY_BATCH_ENABLED", True)
POLICY_PARITY_LOG_DETAILS = getattr(settings, "POLICY_PARITY_LOG_DETAILS", False)
POLICY_TIMEOUT_SECONDS = getattr(settings, "POLICY_TIMEOUT_SECONDS", 5.0)
POLICY_PARITY_MAX_ATTEMPTS = getattr(settings, "POLICY_PARITY_MAX_ATTEMPTS", 8)
POLICY_PARITY_RETRY_BASE_SECONDS = getattr(settings, "POLICY_PARITY_RETRY_BASE_SECONDS", 2.0)
POLICY_PARITY_RETRY_MAX_SECONDS = getattr(settings, "POLICY_PARITY_RETRY_MAX_SECONDS", 300.0)
POLICY_PARITY_LEASE_SECONDS = getattr(settings, "POLICY_PARITY_LEASE_SECONDS", 60.0)
POLICY_PARITY_POLL_SECONDS = getattr(settings, "POLICY_PARITY_POLL_SECONDS", 1.0)
POLICY_PARITY_CIRCUIT_FAILURES = getattr(settings, "POLICY_PARITY_CIRCUIT_FAILURES", 5)
POLICY_PARITY_CIRCUIT_RESET_SECONDS = getattr(settings, "POLICY_PARITY_CIRCUIT_RESET_SECONDS", 30.0)


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
    "Durable policy parity batch lifecycle events.",
    ["status"],
)

POLICY_PARITY_FAILURES_TOTAL = Counter(
    "mreg_policy_parity_failures_total",
    "Policy integration failures by processing stage.",
    ["stage"],
)

POLICY_ENFORCEMENT_RESULTS_TOTAL = Counter(
    "mreg_policy_enforcement_results_total",
    "Synchronous authoritative policy outcomes.",
    ["result"],
)

POLICY_MODE_INFO = Gauge(
    "mreg_policy_mode_info",
    "Configured MREG policy decision mode.",
    ["mode"],
    multiprocess_mode="livemax",
)
POLICY_MODE_INFO.labels(mode=POLICY_MODE.value).set(1)

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

POLICY_PARITY_OUTBOX_ENTRIES = Gauge(
    "mreg_policy_parity_outbox_entries",
    "Current durable policy parity outbox entries.",
    ["status"],
    multiprocess_mode="livemax",
)

POLICY_PARITY_OUTBOX_OLDEST_SECONDS = Gauge(
    "mreg_policy_parity_outbox_oldest_seconds",
    "Age of the oldest pending durable policy parity batch.",
    multiprocess_mode="livemax",
)

POLICY_PARITY_CIRCUIT_OPEN = Gauge(
    "mreg_policy_parity_circuit_open",
    "Whether this worker's TreeTop delivery circuit breaker is open.",
    multiprocess_mode="livemax",
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


def _serialize_policy_batch(items: Sequence[_ParityBatchItem]) -> dict[str, object]:
    """Convert a batch into the versioned JSON outbox representation."""
    return {
        "version": 1,
        "items": [
            {
                "decision": item.decision,
                "policy_request": item.policy_request.to_api(),
                "context": item.context,
            }
            for item in items
        ],
    }


def _deserialize_policy_request(payload: Mapping[str, object]) -> TreeTopRequest:
    principal_payload = payload["principal"]
    if not isinstance(principal_payload, Mapping):
        raise ValueError("Invalid durable policy principal")
    user_payload = principal_payload["User"]
    if not isinstance(user_payload, Mapping):
        raise ValueError("Invalid durable policy user")
    namespace = [str(part) for part in user_payload.get("namespace", [])]
    groups_payload = user_payload.get("groups", [])
    groups = [str(group["id"]) for group in groups_payload if isinstance(group, Mapping)]

    action_payload = payload["action"]
    resource_payload = payload["resource"]
    if not isinstance(action_payload, Mapping) or not isinstance(resource_payload, Mapping):
        raise ValueError("Invalid durable policy action or resource")
    action = Action.new(
        str(action_payload["id"]),
        [str(part) for part in action_payload.get("namespace", [])],
    )
    attrs_payload = resource_payload.get("attrs", {})
    if not isinstance(attrs_payload, Mapping):
        raise ValueError("Invalid durable policy resource attributes")
    attrs: dict[str, ResourceAttribute] = {}
    for key, raw_attribute in attrs_payload.items():
        if not isinstance(raw_attribute, Mapping):
            raise ValueError("Invalid durable policy resource attribute")
        attrs[str(key)] = ResourceAttribute.new(
            str(raw_attribute["value"]),
            ResourceAttributeType(str(raw_attribute["type"])),
        )
    return TreeTopRequest(
        principal=TreeTopUser.new(str(user_payload["id"]), namespace, groups=groups),
        action=action,
        resource=TreeTopResource.new(
            kind=str(resource_payload["kind"]),
            id=str(resource_payload["id"]),
            attrs=attrs,
        ),
    )


def _deserialize_policy_batch(payload: Mapping[str, object]) -> list[_ParityBatchItem]:
    if payload.get("version") != 1:
        raise ValueError(f"Unsupported policy outbox payload version: {payload.get('version')}")
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("Invalid durable policy batch")
    items: list[_ParityBatchItem] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, Mapping):
            raise ValueError("Invalid durable policy batch item")
        request_payload = raw_item.get("policy_request")
        context = raw_item.get("context")
        if not isinstance(request_payload, Mapping) or not isinstance(context, Mapping):
            raise ValueError("Invalid durable policy batch request or context")
        items.append(
            _ParityBatchItem(
                decision=bool(raw_item.get("decision")),
                policy_request=_deserialize_policy_request(request_payload),
                context={str(key): value for key, value in context.items()},
            )
        )
    return items


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


@dataclass(frozen=True, slots=True)
class _ClaimedPolicyBatch:
    id: int
    attempts: int
    payload: Mapping[str, object]


class _CircuitBreaker:
    """Small process-local breaker protecting the shared TreeTop service."""

    def __init__(self, failure_threshold: int, reset_seconds: float) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.reset_seconds = max(0.1, reset_seconds)
        self.consecutive_failures = 0
        self.open_until = 0.0

    def wait_seconds(self) -> float:
        remaining = self.open_until - monotonic()
        if remaining <= 0:
            POLICY_PARITY_CIRCUIT_OPEN.set(0)
            return 0.0
        POLICY_PARITY_CIRCUIT_OPEN.set(1)
        return remaining

    def success(self) -> None:
        self.consecutive_failures = 0
        self.open_until = 0.0
        POLICY_PARITY_CIRCUIT_OPEN.set(0)

    def failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold:
            self.open_until = monotonic() + self.reset_seconds
            POLICY_PARITY_CIRCUIT_OPEN.set(1)
            _safe_log(
                logging.ERROR,
                "policy_parity_circuit_open",
                reset_seconds=self.reset_seconds,
                consecutive_failures=self.consecutive_failures,
            )


def _refresh_outbox_metrics() -> None:
    """Refresh low-cardinality gauges from the durable shared queue."""
    try:
        now = timezone.now()
        pending = PolicyParityOutbox.objects.filter(failed_at__isnull=True)
        POLICY_PARITY_OUTBOX_ENTRIES.labels(status="pending").set(pending.count())
        POLICY_PARITY_OUTBOX_ENTRIES.labels(status="dead_letter").set(
            PolicyParityOutbox.objects.filter(failed_at__isnull=False).count()
        )
        oldest = pending.order_by("created_at").values_list("created_at", flat=True).first()
        POLICY_PARITY_OUTBOX_OLDEST_SECONDS.set(max(0.0, (now - oldest).total_seconds()) if oldest else 0.0)
    except Exception as exc:
        _record_instrumentation_failure(exc, stage="outbox_metrics")


class _ParityDispatcher:
    """Database-outbox worker shared safely by all application processes."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._circuit = _CircuitBreaker(
            int(POLICY_PARITY_CIRCUIT_FAILURES),
            float(POLICY_PARITY_CIRCUIT_RESET_SECONDS),
        )

    def submit(self, items: Sequence[_ParityBatchItem]) -> bool:
        """Persist a batch before waking a worker; no policy I/O occurs here."""
        if not items:
            return False
        self._ensure_started()
        PolicyParityOutbox.objects.create(payload=_serialize_policy_batch(items))
        POLICY_PARITY_BATCHES_TOTAL.labels(status="persisted").inc()
        transaction.on_commit(self.wake)
        _refresh_outbox_metrics()
        return True

    def wake(self) -> None:
        self._wake.set()

    def _ensure_started(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        with self._start_lock:
            if self._thread is None or not self._thread.is_alive():
                self._stop.clear()
                self._thread = threading.Thread(
                    target=self._run,
                    name="mreg-policy-parity-outbox",
                    daemon=True,
                )
                self._thread.start()

    def _claim(self) -> _ClaimedPolicyBatch | None:
        now = timezone.now()
        stale_before = now - timedelta(seconds=float(POLICY_PARITY_LEASE_SECONDS))
        with transaction.atomic():
            row = (
                PolicyParityOutbox.objects.select_for_update(skip_locked=True)
                .filter(failed_at__isnull=True, available_at__lte=now)
                .filter(Q(locked_at__isnull=True) | Q(locked_at__lt=stale_before))
                .order_by("available_at", "id")
                .first()
            )
            if row is None:
                return None
            row.attempts += 1
            row.locked_at = now
            row.save(update_fields=("attempts", "locked_at"))
            return _ClaimedPolicyBatch(id=row.id, attempts=row.attempts, payload=row.payload)

    def _complete(self, claimed: _ClaimedPolicyBatch) -> None:
        PolicyParityOutbox.objects.filter(id=claimed.id).delete()
        POLICY_PARITY_BATCHES_TOTAL.labels(status="processed").inc()
        self._circuit.success()

    def _fail(
        self,
        claimed: _ClaimedPolicyBatch,
        exc: Exception,
        items: Sequence[_ParityBatchItem],
    ) -> None:
        error = f"{type(exc).__name__}: {exc}"
        self._circuit.failure()
        now = timezone.now()
        if claimed.attempts >= int(POLICY_PARITY_MAX_ATTEMPTS):
            PolicyParityOutbox.objects.filter(id=claimed.id).update(
                locked_at=None,
                failed_at=now,
                last_error=error,
            )
            POLICY_PARITY_BATCHES_TOTAL.labels(status="dead_letter").inc()
            for item in items:
                _log_parity_payload(
                    _compute_parity_payload(
                        decision=item.decision,
                        policy_allowed=None,
                        error=error,
                        context=item.context,
                    )
                )
            _safe_log(
                logging.ERROR,
                "policy_parity_dead_letter",
                outbox_id=claimed.id,
                attempts=claimed.attempts,
                error_type=type(exc).__name__,
            )
            return
        delay = min(
            float(POLICY_PARITY_RETRY_MAX_SECONDS),
            float(POLICY_PARITY_RETRY_BASE_SECONDS) * (2 ** (claimed.attempts - 1)),
        )
        PolicyParityOutbox.objects.filter(id=claimed.id).update(
            locked_at=None,
            available_at=now + timedelta(seconds=delay),
            last_error=error,
        )
        POLICY_PARITY_BATCHES_TOTAL.labels(status="retried").inc()
        _safe_log(
            logging.WARNING,
            "policy_parity_retry_scheduled",
            outbox_id=claimed.id,
            attempts=claimed.attempts,
            delay_seconds=delay,
            error_type=type(exc).__name__,
        )

    def _run(self) -> None:
        close_old_connections()
        try:
            while not self._stop.is_set():
                circuit_wait = self._circuit.wait_seconds()
                if circuit_wait > 0:
                    self._wake.wait(timeout=min(circuit_wait, float(POLICY_PARITY_POLL_SECONDS)))
                    self._wake.clear()
                    continue
                close_old_connections()
                try:
                    claimed = self._claim()
                except Exception as exc:
                    _record_instrumentation_failure(exc, stage="outbox_claim")
                    close_old_connections()
                    self._wake.wait(timeout=float(POLICY_PARITY_POLL_SECONDS))
                    self._wake.clear()
                    continue
                if claimed is None:
                    _refresh_outbox_metrics()
                    self._wake.wait(timeout=float(POLICY_PARITY_POLL_SECONDS))
                    self._wake.clear()
                    continue
                items: list[_ParityBatchItem] = []
                try:
                    items = _deserialize_policy_batch(claimed.payload)
                    _process_policy_parity_batch(items)
                    self._complete(claimed)
                except Exception as exc:
                    _record_instrumentation_failure(exc, stage="worker")
                    try:
                        self._fail(claimed, exc, items)
                    except Exception as fail_exc:
                        _record_instrumentation_failure(fail_exc, stage="outbox_retry")
                        close_old_connections()
                finally:
                    _refresh_outbox_metrics()
        finally:
            close_old_connections()

    def shutdown(self) -> None:
        thread = self._thread
        if thread is None or not thread.is_alive():
            return
        self._stop.set()
        self._wake.set()
        thread.join(timeout=max(1.0, float(POLICY_TIMEOUT_SECONDS) + 1.0))


_dispatcher: _ParityDispatcher | None = None
_dispatcher_pid: int | None = None
_dispatcher_lock = threading.Lock()


def _get_dispatcher() -> _ParityDispatcher:
    global _dispatcher, _dispatcher_pid

    pid = os.getpid()
    with _dispatcher_lock:
        if _dispatcher is None or _dispatcher_pid != pid:
            _dispatcher = _ParityDispatcher()
            _dispatcher_pid = pid
        return _dispatcher


def start_policy_parity_dispatcher() -> None:
    """Start the shadow-mode outbox worker after Gunicorn forks."""
    if _is_shadow_enabled():
        _get_dispatcher()._ensure_started()


def stop_policy_parity_dispatcher() -> None:
    """Stop this process's outbox worker without affecting persisted work."""
    if _dispatcher is not None and _dispatcher_pid == os.getpid():
        _dispatcher.shutdown()


def _shutdown_policy_runtime() -> None:
    stop_policy_parity_dispatcher()
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
        with suppress(Exception):
            POLICY_PARITY_BATCHES_TOTAL.labels(status="persist_failed").inc()
        _record_instrumentation_failure(exc, stage="persist")
        return False


@contextmanager
def batch_policy_parity():
    """Track one request's policy work and batch shadow checks."""
    if not _is_policy_enabled():
        yield
        return
    if _request_state.get() is not None:
        yield
        return

    state = _RequestParityState()
    token = _request_state.set(state)
    try:
        yield
    finally:
        try:
            if _current_policy_mode() == PolicyMode.SHADOW and POLICY_PARITY_BATCH_ENABLED and state.items:
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
    """Temporarily disable shadow checks in the current execution context.

    Enforcement deliberately ignores this test helper so production code cannot
    turn an authoritative decision back into a legacy decision accidentally.
    """
    token = _parity_disabled_depth.set(_parity_disabled_depth.get() + 1)
    try:
        yield
    finally:
        _parity_disabled_depth.reset(token)


def _current_policy_mode() -> PolicyMode:
    value = POLICY_MODE
    return value if isinstance(value, PolicyMode) else PolicyMode(value)


def _current_enforcement_failure_mode() -> EnforcementFailureMode:
    value = POLICY_ENFORCEMENT_FAILURE_MODE
    return value if isinstance(value, EnforcementFailureMode) else EnforcementFailureMode(value)


def _is_shadow_enabled() -> bool:
    return bool(
        _current_policy_mode() == PolicyMode.SHADOW
        and POLICY_PARITY_ENABLED
        and POLICY_BASE_URL
        and _parity_disabled_depth.get() == 0
    )


def _is_enforcement_enabled() -> bool:
    return _current_policy_mode() == PolicyMode.ENFORCE


def _is_policy_enabled() -> bool:
    if _is_enforcement_enabled():
        return True
    return _is_shadow_enabled()


def _is_parity_enabled() -> bool:
    """Compatibility alias for callers that mean shadow parity."""
    return _is_shadow_enabled()


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
    """Evaluate and record one durable batch outside request threads.

    Delivery-level errors raise so the outbox can retry them.  Successful
    responses are recorded only after a successful authorize call and before
    deleting the durable row. Delivery is at-least-once across process crashes.
    """
    if not items:
        return

    correlation_id = items[0].context.get("correlation_id")
    path = items[0].context.get("path")
    results, authorize_error = _authorize_with_metrics(
        policy_requests=[item.policy_request for item in items],
        correlation_id=correlation_id if isinstance(correlation_id, str) else None,
        path=path if isinstance(path, str) else None,
    )
    if authorize_error is not None:
        raise RuntimeError(authorize_error)
    parsed_results = [_result_to_decision_and_error(results, index) for index in range(len(items))]
    result_error = next((error for _, error in parsed_results if error is not None), None)
    if result_error is not None:
        raise RuntimeError(result_error)
    for index, item in enumerate(items):
        policy_allowed, error = parsed_results[index]
        _log_parity_payload(
            _compute_parity_payload(
                decision=item.decision,
                policy_allowed=policy_allowed,
                error=error,
                context=item.context,
            )
        )


def flush_policy_parity_batch() -> bool:
    """Persist and clear the current request batch, if one exists."""
    state = _request_state.get()
    if state is None or not state.items:
        return False
    items = list(state.items)
    state.items.clear()
    submitted = _submit_policy_batch(items)
    if submitted:
        state.submitted_queries += 1
    return submitted


def _build_policy_context(
    *,
    request: Request,
    check: PolicyCheck,
    view: View | None,
    permission_class: str | None,
) -> dict[str, object]:
    policy_action = Action.new(check.action, POLICY_NAMESPACE)
    return {
        "path": request.path,
        "method": request.method,
        "permission": permission_class or (view and view.__class__.__name__),
        "view": view and view.__class__.__name__,
        "model": _model_name_from_view(view),
        "action": _fully_qualified_action(policy_action),
        "resource_kind": _qualified_resource_kind(check.resource.kind),
        "correlation_id": _corr_id(request),
        "mode": _current_policy_mode().value,
    }


def _record_enforcement_result(result: str) -> None:
    with suppress(Exception):
        POLICY_ENFORCEMENT_RESULTS_TOTAL.labels(result=result).inc()


def _enforcement_failure(
    *,
    decision: bool,
    error: str,
    context: dict[str, object],
    stage: str,
) -> bool:
    """Apply the configured fail-closed or transitional legacy fallback."""
    _record_instrumentation_failure(RuntimeError(error), stage=stage)
    _log_parity_payload(
        _compute_parity_payload(
            decision=decision,
            policy_allowed=None,
            error=error,
            context=context,
        )
    )
    failure_mode = _current_enforcement_failure_mode()
    if failure_mode == EnforcementFailureMode.LEGACY:
        result = "error_legacy"
        enforced_decision = bool(decision)
    else:
        result = "error_deny"
        enforced_decision = False
    _record_enforcement_result(result)
    _safe_log(
        logging.CRITICAL,
        "policy_enforcement_failure",
        failure_mode=failure_mode.value,
        enforced_decision=enforced_decision,
        error=error,
        **context,
    )
    return enforced_decision


def _enforce_policy_decision(
    *,
    decision: bool,
    policy_request: TreeTopRequest,
    context: dict[str, object],
) -> bool:
    """Synchronously return the authoritative TreeTop decision."""
    if not POLICY_BASE_URL:
        return _enforcement_failure(
            decision=decision,
            error="MREG_POLICY_BASE_URL is not configured",
            context=context,
            stage="enforce_configuration",
        )

    state = _request_state.get()
    if state is not None:
        state.submitted_queries += 1
    try:
        results, authorize_error = _authorize_with_metrics(
            policy_requests=[policy_request],
            correlation_id=context.get("correlation_id")
            if isinstance(context.get("correlation_id"), str)
            else None,
            path=context.get("path") if isinstance(context.get("path"), str) else None,
        )
    except Exception as exc:
        return _enforcement_failure(
            decision=decision,
            error=f"{type(exc).__name__}: {exc}",
            context=context,
            stage="enforce_instrumentation",
        )
    if authorize_error is not None:
        return _enforcement_failure(
            decision=decision,
            error=authorize_error,
            context=context,
            stage="enforce_authorize",
        )

    policy_allowed, result_error = _result_to_decision_and_error(results, 0)
    if result_error is not None or policy_allowed is None:
        return _enforcement_failure(
            decision=decision,
            error=result_error or "TreeTop returned no decision",
            context=context,
            stage="enforce_result",
        )

    _log_parity_payload(
        _compute_parity_payload(
            decision=decision,
            policy_allowed=policy_allowed,
            error=None,
            context=context,
        )
    )
    _record_enforcement_result("allow" if policy_allowed else "deny")
    return policy_allowed


def policy_parity(
    decision: bool,
    *,
    request: Request,
    check: PolicyCheck,
    view: View | None = None,
    permission_class: str | None = None,
) -> bool:
    """Apply the configured off, shadow, or enforce policy behavior."""
    mode = _current_policy_mode()
    if mode == PolicyMode.OFF:
        return decision
    if mode == PolicyMode.SHADOW and not _is_shadow_enabled():
        return decision

    context: dict[str, object] = {
        "path": request.path,
        "method": request.method,
        "action": check.action,
        "resource_kind": check.resource.kind,
        "mode": mode.value,
    }
    try:
        context = _build_policy_context(
            request=request,
            check=check,
            view=view,
            permission_class=permission_class,
        )
        muser = MregUser.from_request(request)
        policy_request = _build_policy_request(muser, check)
        if POLICY_PARITY_LOG_DETAILS:
            context.update(
                {
                    "principal": muser.username,
                    "groups": list(muser.group_list),
                    "resource_id": check.resource.id,
                    "resource_attrs": dict(check.resource.attrs),
                }
            )
    except Exception as exc:
        if mode == PolicyMode.ENFORCE:
            return _enforcement_failure(
                decision=decision,
                error=f"{type(exc).__name__}: {exc}",
                context=context,
                stage="enforce_build",
            )
        _record_instrumentation_failure(exc, stage="shadow_build")
        return decision

    if mode == PolicyMode.ENFORCE:
        return _enforce_policy_decision(
            decision=decision,
            policy_request=policy_request,
            context=context,
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
    return decision
