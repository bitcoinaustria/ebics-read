"""Explicitly gated live BTD smoke contract; never enabled in public CI."""

from __future__ import annotations

import importlib
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from ebics_read import DownloadedDocument, ReadOnlyClient

_LIVE_ACKNOWLEDGEMENT = "I_ACCEPT_LIVE_READ_ONLY_BANK_IO"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("EBICS_READ_LIVE") != _LIVE_ACKNOWLEDGEMENT,
        reason="live bank smoke test is explicitly disabled",
    ),
]


def test_live_btd_through_external_untracked_provider() -> None:
    module_name = os.environ.get("EBICS_READ_LIVE_PROVIDER")
    if not module_name:
        pytest.fail("EBICS_READ_LIVE_PROVIDER must name an external provider module")
    previous_cwd = Path.cwd()
    with TemporaryDirectory(prefix="ebics-read-live-") as temporary_cwd:
        Path(temporary_cwd).chmod(0o700)
        try:
            os.chdir(temporary_cwd)
            with Path(os.devnull).open("w", encoding="utf-8") as discarded_output:
                with (
                    redirect_stdout(discarded_output),
                    redirect_stderr(discarded_output),
                ):
                    provider = importlib.import_module(module_name)
                    module_file = getattr(provider, "__file__", None)
                    if module_file is None or Path(
                        module_file
                    ).resolve().is_relative_to(Path(__file__).parents[1].resolve()):
                        pytest.fail(
                            "live provider module must remain outside this repository"
                        )
                    factory = getattr(provider, "make_live_btd_case", None)
                    if not callable(factory):
                        pytest.fail("live provider must define make_live_btd_case()")
                    client, session_id, descriptor, sink, control, options = factory()
                    if not isinstance(client, ReadOnlyClient):
                        pytest.fail("live provider did not return a ReadOnlyClient")
                    documents = client.download(
                        session_id, descriptor, sink, control, options
                    )
        finally:
            os.chdir(previous_cwd)

    assert documents
    assert all(isinstance(document, DownloadedDocument) for document in documents)
