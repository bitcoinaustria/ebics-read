"""Immutable values used by the download-only API."""

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


def _frozen_mapping(values: Mapping[str, str]) -> Mapping[str, str]:
    return MappingProxyType(dict(values))


class RetrievalKind(str, Enum):
    """Semantic, read-only capabilities exposed by the public API."""

    ACCOUNT_INFORMATION = "account_information"
    BANK_METADATA = "bank_metadata"


@dataclass(frozen=True, slots=True)
class DownloadRequest:
    """A bank-to-customer retrieval request approved elsewhere by policy."""

    kind: RetrievalKind
    parameters: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RetrievalKind):
            raise TypeError("kind must be a RetrievalKind")
        object.__setattr__(self, "parameters", _frozen_mapping(self.parameters))


@dataclass(frozen=True, slots=True)
class DownloadResult:
    """Opaque bytes returned by a future download transport."""

    content: bytes
    content_type: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", bytes(self.content))
        object.__setattr__(self, "metadata", _frozen_mapping(self.metadata))
