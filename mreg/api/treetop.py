"""Synchronous TreeTop authorization for endpoint permission stacks."""

from __future__ import annotations

import atexit
import asyncio
import ipaddress
import logging
import os
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from time import monotonic
from typing import TypeAlias

from django.conf import settings
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
from mreg.policy.config import PolicyMode


logger = structlog.get_logger("mreg.policy.parity")

POLICY_MODE = PolicyMode(getattr(settings, "POLICY_MODE", "shadow"))
POLICY_PARITY_ENABLED = getattr(settings, "POLICY_PARITY_ENABLED", POLICY_MODE == PolicyMode.SHADOW)
POLICY_BASE_URL = (getattr(settings, "POLICY_BASE_URL", "") or "").strip()
POLICY_NAMESPACE = getattr(settings, "POLICY_NAMESPACE", ["MREG"])
POLICY_PARITY_LOG_DETAILS = getattr(settings, "POLICY_PARITY_LOG_DETAILS", False)
POLICY_TIMEOUT_SECONDS = getattr(settings, "POLICY_TIMEOUT_SECONDS", 5.0)
POLICY_CIRCUIT_FAILURES = getattr(settings, "POLICY_CIRCUIT_FAILURES", 5)
POLICY_CIRCUIT_RESET_SECONDS = getattr(settings, "POLICY_CIRCUIT_RESET_SECONDS", 30.0)


POLICY_DECISIONS_TOTAL = Counter(
    "mreg_policy_decisions_total",
    "Composite decisions returned by TreeTop.",
    ["decision"],
)
POLICY_LEGACY_DECISIONS_TOTAL = Counter(
    "mreg_policy_legacy_decisions_total",
    "Composite legacy decisions evaluated for policy comparison.",
    ["decision"],
)
POLICY_PARITY_RESULTS_TOTAL = Counter(
    "mreg_policy_parity_results_total",
    "Composite comparison outcomes between legacy and TreeTop.",
    ["result"],
)
POLICY_AUTHORIZE_CALLS_TOTAL = Counter(
    "mreg_policy_authorize_calls_total",
    "Synchronous calls to the TreeTop authorize endpoint.",
    ["status"],
)
POLICY_FAILURES_TOTAL = Counter(
    "mreg_policy_failures_total",
    "Policy integration failures by stage.",
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
    "Duration of synchronous policy authorize calls.",
    ["status"],
    buckets=[0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)
POLICY_STACK_SIZE = Histogram(
    "mreg_policy_stack_size",
    "Number of Cedar checks in one endpoint policy stack.",
    buckets=[1, 2, 3, 5, 8, 13, 21],
)
POLICY_CALLS_PER_REQUEST = Histogram(
    "mreg_policy_authorize_calls_per_request",
    "Number of TreeTop authorize HTTP calls made by one MREG request.",
    buckets=[0, 1, 2],
)
POLICY_CIRCUIT_OPEN = Gauge(
    "mreg_policy_circuit_open",
    "Whether this worker's synchronous TreeTop circuit is open.",
    multiprocess_mode="livemax",
)


@dataclass(frozen=True, slots=True)
class PolicyResource:
    """One typed Cedar resource."""

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
    """One action/resource leaf evaluated by Cedar."""

    action: str
    resource: PolicyResource

    def __post_init__(self) -> None:
        if not self.action.strip():
            raise ValueError("Policy action cannot be empty")


@dataclass(frozen=True, slots=True)
class PolicyLeaf:
    """Leaf in an endpoint permission tree."""

    check: PolicyCheck


@dataclass(frozen=True, slots=True)
class PolicyAll:
    """Require every child policy node to allow."""

    children: tuple[PolicyNode, ...]

    def __post_init__(self) -> None:
        if not self.children:
            raise ValueError("PolicyAll requires at least one child")


@dataclass(frozen=True, slots=True)
class PolicyAny:
    """Require at least one child policy node to allow."""

    children: tuple[PolicyNode, ...]

    def __post_init__(self) -> None:
        if not self.children:
            raise ValueError("PolicyAny requires at least one child")


PolicyNode: TypeAlias = PolicyLeaf | PolicyAll | PolicyAny


def policy_leaf(
    *,
    action: str,
    resource_kind: str,
    resource_id: str,
    resource_attrs: Mapping[str, str],
) -> PolicyLeaf:
    """Build one validated leaf without exposing wire-model details."""
    return PolicyLeaf(
        PolicyCheck(
            action=action,
            resource=PolicyResource(
                kind=resource_kind,
                id=str(resource_id),
                attrs=resource_attrs,
            ),
        )
    )


def policy_all(*nodes: PolicyNode) -> PolicyAll:
    return PolicyAll(tuple(nodes))


def policy_any(*nodes: PolicyNode) -> PolicyAny:
    return PolicyAny(tuple(nodes))


@dataclass(slots=True)
class _RequestPolicyState:
    calls: int = 0
    fingerprint: tuple[object, ...] | None = None
    policy_decision: bool | None = None
    error: str | None = None


_request_state: ContextVar[_RequestPolicyState | None] = ContextVar(
    "mreg_policy_request_state",
    default=None,
)
_shadow_disabled_depth: ContextVar[int] = ContextVar(
    "mreg_policy_shadow_disabled_depth",
    default=0,
)


class _SynchronousCircuitBreaker:
    """Thread-safe closed/open/half-open circuit for request-path calls."""

    def __init__(self, failure_threshold: int, reset_seconds: float) -> None:
        self.failure_threshold = max(1, int(failure_threshold))
        self.reset_seconds = max(0.1, float(reset_seconds))
        self._lock = threading.Lock()
        self._failures = 0
        self._open_until = 0.0
        self._probe_in_flight = False

    def allow_call(self) -> bool:
        now = monotonic()
        with self._lock:
            if self._open_until == 0.0:
                POLICY_CIRCUIT_OPEN.set(0)
                return True
            if now < self._open_until or self._probe_in_flight:
                POLICY_CIRCUIT_OPEN.set(1)
                return False
            self._probe_in_flight = True
            POLICY_CIRCUIT_OPEN.set(1)
            return True

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._open_until = 0.0
            self._probe_in_flight = False
            POLICY_CIRCUIT_OPEN.set(0)

    def failure(self) -> None:
        now = monotonic()
        with self._lock:
            self._probe_in_flight = False
            self._failures += 1
            if self._open_until or self._failures >= self.failure_threshold:
                self._open_until = now + self.reset_seconds
                POLICY_CIRCUIT_OPEN.set(1)
                _safe_log(
                    logging.ERROR,
                    "policy_circuit_open",
                    reset_seconds=self.reset_seconds,
                    consecutive_failures=self._failures,
                )


_circuit = _SynchronousCircuitBreaker(POLICY_CIRCUIT_FAILURES, POLICY_CIRCUIT_RESET_SECONDS)
_client: TreeTopClient | None = None
_client_pid: int | None = None
_client_lock = threading.Lock()


def _get_treetop_client() -> TreeTopClient:
    global _client, _client_pid
    pid = os.getpid()
    with _client_lock:
        if _client is None or _client_pid != pid:
            if _client is not None:
                with suppress(Exception):
                    _client.close()
            _client = TreeTopClient(
                base_url=POLICY_BASE_URL,
                timeout=float(POLICY_TIMEOUT_SECONDS),
            )
            _client_pid = pid
        return _client


def close_policy_client() -> None:
    """Close transports owned by this process."""
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
        with suppress(Exception):
            client.close()


atexit.register(close_policy_client)


def _safe_log(level: int, event: str, **context: object) -> None:
    with suppress(Exception):
        logger.log(level, event, **context)


def _record_failure(stage: str, error: str, **context: object) -> None:
    with suppress(Exception):
        POLICY_FAILURES_TOTAL.labels(stage=stage).inc()
    _safe_log(logging.ERROR, "policy_integration_error", stage=stage, error=error, **context)


@contextmanager
def policy_request_scope():
    """Record and enforce the one-authorize-call-per-request invariant."""
    if _request_state.get() is not None:
        yield
        return
    state = _RequestPolicyState()
    token = _request_state.set(state)
    try:
        yield
    finally:
        with suppress(Exception):
            POLICY_CALLS_PER_REQUEST.observe(float(state.calls))
        _request_state.reset(token)


@contextmanager
def disable_policy_parity():
    """Disable synchronous shadow comparisons in a narrow test scope."""
    token = _shadow_disabled_depth.set(_shadow_disabled_depth.get() + 1)
    try:
        yield
    finally:
        _shadow_disabled_depth.reset(token)


def _current_policy_mode() -> PolicyMode:
    return POLICY_MODE if isinstance(POLICY_MODE, PolicyMode) else PolicyMode(POLICY_MODE)


def policy_enforcement_enabled() -> bool:
    """Return whether TreeTop decisions are authoritative."""
    return _current_policy_mode() == PolicyMode.ENFORCE


def policy_shadow_enabled() -> bool:
    """Return whether synchronous shadow evaluation is active in this scope."""
    return bool(
        _current_policy_mode() == PolicyMode.SHADOW and POLICY_PARITY_ENABLED and POLICY_BASE_URL and _shadow_disabled_depth.get() == 0
    )


def _policy_is_configured() -> bool:
    mode = _current_policy_mode()
    if mode == PolicyMode.OFF:
        return False
    if mode == PolicyMode.SHADOW:
        return policy_shadow_enabled()
    return True


def _corr_id(request: Request) -> str | None:
    return request.headers.get("X-Correlation-ID") or request.META.get("HTTP_X_CORRELATION_ID")


def _qualified_resource_kind(kind: str) -> str:
    return "::".join([*POLICY_NAMESPACE, kind]) if POLICY_NAMESPACE else kind


def _build_resource_attrs(resource_attrs: Mapping[str, str]) -> dict[str, ResourceAttribute]:
    attrs: dict[str, ResourceAttribute] = {}
    for key, value in resource_attrs.items():
        normalized = str(value)
        if normalized.lower() in {"true", "false"}:
            attrs[key] = ResourceAttribute.new(normalized.lower(), ResourceAttributeType.BOOLEAN)
            continue
        try:
            ip = ipaddress.ip_address(normalized)
            attrs[key] = ResourceAttribute.new(str(ip), ResourceAttributeType.IP)
        except ValueError:
            attrs[key] = ResourceAttribute.new(normalized, ResourceAttributeType.STRING)
    return attrs


def _build_policy_request(
    user: MregUser,
    check: PolicyCheck,
    *,
    request_id: str,
) -> TreeTopRequest:
    return TreeTopRequest(
        id=request_id,
        principal=TreeTopUser.new(
            str(user.username),
            POLICY_NAMESPACE,
            groups=list(user.group_list),
        ),
        action=Action.new(check.action, POLICY_NAMESPACE),
        resource=TreeTopResource.new(
            kind=_qualified_resource_kind(check.resource.kind),
            id=check.resource.id,
            attrs=_build_resource_attrs(check.resource.attrs),
        ),
    )


def _iter_leaves(node: PolicyNode) -> Iterator[PolicyLeaf]:
    if isinstance(node, PolicyLeaf):
        yield node
        return
    for child in node.children:
        yield from _iter_leaves(child)


def _evaluate_tree(node: PolicyNode, decisions: Iterator[bool]) -> bool:
    if isinstance(node, PolicyLeaf):
        return next(decisions)
    values = tuple(_evaluate_tree(child, decisions) for child in node.children)
    if isinstance(node, PolicyAll):
        return all(values)
    return any(values)


def _node_fingerprint(node: PolicyNode) -> tuple[object, ...]:
    if isinstance(node, PolicyLeaf):
        resource = node.check.resource
        return (
            "leaf",
            node.check.action,
            resource.kind,
            resource.id,
            tuple(sorted((str(key), str(value)) for key, value in resource.attrs.items())),
        )
    return (
        "all" if isinstance(node, PolicyAll) else "any",
        tuple(_node_fingerprint(child) for child in node.children),
    )


def _result_decision(result: AuthorizeResultBrief, index: int) -> bool:
    if result.index != index:
        raise RuntimeError(f"Authorization result index {result.index} does not match {index}")
    if result.id != f"mreg-{index}":
        raise RuntimeError(f"Authorization result {index} has unexpected id={result.id!r}")
    if not result.is_success():
        raise RuntimeError(result.error or f"Authorization result {index} failed with status={result.status}")
    return result.is_allowed()


def _authorize_stack(
    *,
    request: Request,
    root: PolicyNode,
    context: dict[str, object],
) -> bool:
    leaves = tuple(_iter_leaves(root))
    if not leaves:
        raise RuntimeError("Endpoint policy stack is empty")
    fingerprint = _node_fingerprint(root)
    state = _request_state.get()
    if state is not None and state.fingerprint is not None:
        if state.fingerprint != fingerprint:
            raise RuntimeError("A second different endpoint policy stack was evaluated in one request")
        if state.error is not None:
            raise RuntimeError(state.error)
        if state.policy_decision is None:
            raise RuntimeError("Cached endpoint policy stack has no decision")
        return state.policy_decision

    if not POLICY_BASE_URL:
        raise RuntimeError("MREG_POLICY_BASE_URL is not configured")
    if not _circuit.allow_call():
        raise RuntimeError("TreeTop circuit breaker is open")

    user = MregUser.from_request(request)
    policy_requests = [_build_policy_request(user, leaf.check, request_id=f"mreg-{index}") for index, leaf in enumerate(leaves)]
    POLICY_STACK_SIZE.observe(float(len(policy_requests)))
    started = monotonic()
    if state is not None:
        state.calls += 1
        state.fingerprint = fingerprint
    try:
        response = _get_treetop_client().authorize(
            policy_requests,
            correlation_id=_corr_id(request),
        )
        if len(response.results) != len(leaves):
            raise RuntimeError(f"TreeTop returned {len(response.results)} results for {len(leaves)} checks")
        ordered_results = sorted(response.results, key=lambda result: result.index)
        decisions = tuple(_result_decision(result, index) for index, result in enumerate(ordered_results))
    except Exception as exc:
        _circuit.failure()
        POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="exception").inc()
        POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="exception").observe(monotonic() - started)
        error = f"{type(exc).__name__}: {exc}"
        if state is not None:
            state.error = error
        raise RuntimeError(error) from exc

    _circuit.success()
    POLICY_AUTHORIZE_CALLS_TOTAL.labels(status="success").inc()
    POLICY_AUTHORIZE_DURATION_SECONDS.labels(status="success").observe(monotonic() - started)
    policy_decision = _evaluate_tree(root, iter(decisions))
    if state is not None:
        state.policy_decision = policy_decision
    if POLICY_PARITY_LOG_DETAILS:
        context["checks"] = [
            {
                "action": leaf.check.action,
                "resource_kind": leaf.check.resource.kind,
                "resource_id": leaf.check.resource.id,
                "resource_attrs": dict(leaf.check.resource.attrs),
                "decision": decisions[index],
            }
            for index, leaf in enumerate(leaves)
        ]
    return policy_decision


def authorize_policy_stack(
    legacy_decision: bool,
    *,
    request: Request,
    root: PolicyNode,
    view: View | None = None,
    permission_class: str | None = None,
) -> bool:
    """Synchronously evaluate one endpoint stack and apply the configured mode."""
    mode = _current_policy_mode()
    legacy_decision = bool(legacy_decision)
    if not _policy_is_configured():
        return legacy_decision

    context: dict[str, object] = {
        "path": request.path,
        "method": request.method,
        "permission": permission_class or (view and view.__class__.__name__),
        "view": view and view.__class__.__name__,
        "correlation_id": _corr_id(request),
        "mode": mode.value,
    }
    try:
        policy_decision = _authorize_stack(request=request, root=root, context=context)
    except Exception as exc:
        error = str(exc)
        _record_failure("authorize", error, **context)
        _record_parity(legacy_decision, None, error, context)
        if mode == PolicyMode.ENFORCE:
            with suppress(Exception):
                POLICY_ENFORCEMENT_RESULTS_TOTAL.labels(result="error_deny").inc()
            _safe_log(logging.CRITICAL, "policy_enforcement_failure", enforced_decision=False, error=error, **context)
            return False
        return legacy_decision

    _record_parity(legacy_decision, policy_decision, None, context)
    if mode == PolicyMode.ENFORCE:
        with suppress(Exception):
            POLICY_ENFORCEMENT_RESULTS_TOTAL.labels(result="allow" if policy_decision else "deny").inc()
        return policy_decision
    return legacy_decision


def _record_parity(
    legacy_decision: bool,
    policy_decision: bool | None,
    error: str | None,
    context: dict[str, object],
) -> None:
    with suppress(Exception):
        POLICY_LEGACY_DECISIONS_TOTAL.labels(decision="allow" if legacy_decision else "deny").inc()
        policy_label = "error" if policy_decision is None else "allow" if policy_decision else "deny"
        POLICY_DECISIONS_TOTAL.labels(decision=policy_label).inc()
        if error is not None or policy_decision is None:
            result = "error"
        elif legacy_decision == policy_decision:
            result = "match"
        else:
            result = "mismatch"
        POLICY_PARITY_RESULTS_TOTAL.labels(result=result).inc()
        _safe_log(
            logging.INFO if result == "match" else logging.WARNING,
            "policy_stack_result",
            parity=result == "match",
            legacy_decision=legacy_decision,
            policy_decision=policy_decision,
            error=error,
            context=context,
        )


def policy_parity(
    decision: bool,
    *,
    request: Request,
    check: PolicyCheck,
    view: View | None = None,
    permission_class: str | None = None,
) -> bool:
    """Compatibility wrapper for a single-leaf endpoint stack."""
    return authorize_policy_stack(
        decision,
        request=request,
        root=PolicyLeaf(check),
        view=view,
        permission_class=permission_class,
    )
