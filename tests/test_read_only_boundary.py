from __future__ import annotations

import unittest
from dataclasses import dataclass, field

import ebicsmit
from ebicsmit import (
    DownloadRequest,
    DownloadResult,
    ExplicitReadOnlyPolicy,
    OrderNotAllowedError,
    ReadOnlyClient,
    RetrievalKind,
)


@dataclass
class RecordingDownloadTransport:
    requests: list[DownloadRequest] = field(default_factory=list)

    def download(self, request: DownloadRequest) -> DownloadResult:
        self.requests.append(request)
        return DownloadResult(content=b"original-test-fixture")


class ReadOnlyBoundaryTests(unittest.TestCase):
    def test_default_policy_denies_every_order(self) -> None:
        transport = RecordingDownloadTransport()
        client = ReadOnlyClient(transport, ExplicitReadOnlyPolicy())

        with self.assertRaises(OrderNotAllowedError):
            client.download(DownloadRequest(RetrievalKind.ACCOUNT_INFORMATION))

        self.assertEqual(transport.requests, [])

    def test_explicit_policy_allows_download(self) -> None:
        transport = RecordingDownloadTransport()
        policy = ExplicitReadOnlyPolicy.from_kinds([RetrievalKind.ACCOUNT_INFORMATION])
        client = ReadOnlyClient(transport, policy)

        result = client.download(DownloadRequest(RetrievalKind.ACCOUNT_INFORMATION))

        self.assertEqual(result.content, b"original-test-fixture")
        self.assertEqual(transport.requests[0].kind, RetrievalKind.ACCOUNT_INFORMATION)

    def test_raw_order_type_cannot_be_requested(self) -> None:
        with self.assertRaises(TypeError):
            DownloadRequest("BTU")  # type: ignore[arg-type]

    def test_raw_order_type_cannot_be_added_to_policy(self) -> None:
        with self.assertRaises(TypeError):
            ExplicitReadOnlyPolicy(frozenset({"BTU"}))  # type: ignore[arg-type]

    def test_public_api_has_no_write_operations(self) -> None:
        forbidden_names = {"upload", "submit", "send_payment", "btu"}

        self.assertTrue(forbidden_names.isdisjoint(ebicsmit.__all__))
        for name in forbidden_names:
            self.assertFalse(hasattr(ReadOnlyClient, name))

        self.assertNotIn("BTU", RetrievalKind.__members__)


if __name__ == "__main__":
    unittest.main()
