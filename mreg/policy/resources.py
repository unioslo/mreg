"""Typed adapters from Django/DRF objects to policy resource contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar

from mreg.policy.contracts import RESOURCE_CONTRACT_BY_KIND, ResourceContract, snake_case


SourceT = TypeVar("SourceT")


class ResourceAdapter(Protocol[SourceT]):
    """Contract implemented by policy resource adapters."""

    contract: ResourceContract

    def identifier(self, *sources: SourceT | Mapping[str, Any] | None, default: str = "any") -> str: ...

    def attributes(self, data: Mapping[str, Any] | None) -> dict[str, str]: ...


def stringify_attribute(value: Any) -> str:
    """Convert an attribute value to the client wire representation."""
    return "" if value is None else str(value)


@dataclass(frozen=True, slots=True)
class ModelResourceAdapter:
    """Default adapter for one explicitly registered resource kind."""

    contract: ResourceContract

    def identifier(self, *sources: Any, default: str = "any") -> str:
        for source in sources:
            if source is None:
                continue
            for field_name in self.contract.identifier_fields:
                value = source.get(field_name) if isinstance(source, Mapping) else getattr(source, field_name, None)
                if value is not None:
                    return str(value)
        return default

    def attributes(self, data: Mapping[str, Any] | None) -> dict[str, str]:
        attrs: dict[str, str] = {}
        for key, value in (data or {}).items():
            model_fields = getattr(getattr(value, "_meta", None), "fields", None)
            if model_fields is not None:
                for field in model_fields:
                    attrs[f"{key}_{field.name}"] = stringify_attribute(getattr(value, field.name, ""))
            else:
                attrs[str(key)] = stringify_attribute(value)
        # Request data cannot spoof the policy resource kind.
        attrs["kind"] = snake_case(self.contract.kind)
        return attrs


@dataclass(frozen=True, slots=True)
class HostResourceAdapter(ModelResourceAdapter):
    """Host adapter, named explicitly because host policy attributes are typed."""


@dataclass(frozen=True, slots=True)
class IpaddressResourceAdapter(ModelResourceAdapter):
    """IP-address adapter with its IP-oriented identifier precedence."""


def _build_registry() -> dict[str, ModelResourceAdapter]:
    registry: dict[str, ModelResourceAdapter] = {}
    for kind, contract in RESOURCE_CONTRACT_BY_KIND.items():
        adapter_type: type[ModelResourceAdapter]
        if kind == "Host":
            adapter_type = HostResourceAdapter
        elif kind == "Ipaddress":
            adapter_type = IpaddressResourceAdapter
        else:
            adapter_type = ModelResourceAdapter
        registry[kind] = adapter_type(contract)
    return registry


RESOURCE_ADAPTERS = _build_registry()


def adapter_for_kind(kind: str) -> ModelResourceAdapter:
    """Return the registered adapter; unknown resources must be explicit."""
    try:
        return RESOURCE_ADAPTERS[kind]
    except KeyError as exc:
        raise ValueError(f"No policy resource adapter registered for {kind}") from exc


def resource_kind_from_view(*, view: Any, validated_serializer: Any = None, obj: Any = None) -> str:
    """Resolve a registered kind without relying on a view class name."""
    candidates = (
        obj.__class__.__name__ if obj is not None else None,
        getattr(getattr(getattr(validated_serializer, "Meta", None), "model", None), "__name__", None),
        getattr(getattr(validated_serializer, "instance", None), "__class__", type(None)).__name__
        if getattr(validated_serializer, "instance", None) is not None
        else None,
        getattr(view, "policy_resource_kind", None),
    )
    kind = next((candidate for candidate in candidates if isinstance(candidate, str) and candidate.strip()), None)
    if kind is None:
        try:
            serializer_class = view.get_serializer_class()
        except (AttributeError, TypeError) as exc:
            raise ValueError(f"{view.__class__.__name__} must declare an explicit policy resource kind") from exc
        kind = getattr(getattr(getattr(serializer_class, "Meta", None), "model", None), "__name__", None)
    if not kind:
        raise ValueError(f"{view.__class__.__name__} serializer must declare Meta.model for policy parity")
    adapter_for_kind(kind)
    return kind


def resource_id_from_view(
    *,
    view: Any,
    kind: str,
    validated_serializer: Any = None,
    obj: Any = None,
    data: Mapping[str, Any] | None = None,
    default: str = "any",
) -> str:
    """Resolve a stable identifier with adapter-defined precedence."""
    adapter = adapter_for_kind(kind)
    serializer_instance = getattr(validated_serializer, "instance", None)
    return adapter.identifier(obj, data, serializer_instance, getattr(view, "kwargs", None), default=default)


CRUD_METHOD_TO_OPERATION = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}


def crud_operation_from_method(method: str) -> str:
    try:
        return CRUD_METHOD_TO_OPERATION[method.upper()]
    except KeyError as exc:
        raise ValueError(f"Unsupported HTTP method for policy parity: {method}") from exc


def policy_action_from_view(*, view: Any, resource_kind: str, operation: str) -> str:
    """Resolve an explicit custom action or a registered CRUD action."""
    explicit_actions = getattr(view, "policy_actions", None)
    if isinstance(explicit_actions, Mapping):
        explicit_action = explicit_actions.get(operation)
        if isinstance(explicit_action, str) and explicit_action.strip():
            return explicit_action
    contract = adapter_for_kind(resource_kind).contract
    if operation not in contract.operations:
        raise ValueError(f"{resource_kind} does not declare the {operation} policy operation")
    return f"{snake_case(resource_kind)}_{operation}"
