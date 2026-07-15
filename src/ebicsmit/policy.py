"""Fail-closed retrieval policy for the read-only client."""

from dataclasses import dataclass
from typing import Iterable, Protocol

from .errors import OrderNotAllowedError
from .models import RetrievalKind


class ReadOnlyPolicy(Protocol):
    """Policy contract used before any transport receives a request."""

    def ensure_download_allowed(self, kind: RetrievalKind) -> None:
        """Raise when the retrieval capability is not explicitly approved."""


@dataclass(frozen=True, slots=True)
class ExplicitReadOnlyPolicy:
    """Allow only caller-supplied, reviewed retrieval capabilities.

    Concrete EBICS order-type mapping is deliberately absent from the public
    API. An empty policy denies all requests.
    """

    allowed_kinds: frozenset[RetrievalKind] = frozenset()

    def __post_init__(self) -> None:
        if not all(isinstance(kind, RetrievalKind) for kind in self.allowed_kinds):
            raise TypeError("allowed_kinds must contain only RetrievalKind values")

    @classmethod
    def from_kinds(cls, kinds: Iterable[RetrievalKind]) -> "ExplicitReadOnlyPolicy":
        return cls(allowed_kinds=frozenset(kinds))

    def ensure_download_allowed(self, kind: RetrievalKind) -> None:
        if kind not in self.allowed_kinds:
            raise OrderNotAllowedError(
                f"retrieval kind {kind.value!r} is not in the explicit read-only policy"
            )
