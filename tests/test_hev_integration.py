from __future__ import annotations

import ipaddress
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ebics_read import (
    Bank,
    DeadlineControl,
    EbicsBackend,
    HttpsTransport,
    NegotiatedProtocol,
    SystemClock,
)

_HEV_RESPONSE = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<ebics:ebicsHEVResponse xmlns:ebics="http://www.ebics.org/H000" '
    b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    b'xsi:schemaLocation="http://www.ebics.org/H000 ebics_hev.xsd">'
    b"<ebics:SystemReturnCode><ebics:ReturnCode>000000</ebics:ReturnCode>"
    b"<ebics:ReportText>EBICS_OK</ebics:ReportText></ebics:SystemReturnCode>"
    b'<ebics:VersionNumber ProtocolVersion="H005">03.00</ebics:VersionNumber>'
    b"</ebics:ebicsHEVResponse>"
)


class _SyntheticHevHandler(BaseHTTPRequestHandler):
    received: ClassVar[list[bytes]] = []

    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        type(self).received.append(self.rfile.read(length))
        self.send_response(200)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(_HEV_RESPONSE)))
        self.end_headers()
        self.wfile.write(_HEV_RESPONSE)

    def log_message(self, format_: str, *args: object) -> None:
        return None


def _write_local_tls_identity(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    server = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    certificate_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(server.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, certificate_path, key_path


def test_complete_hev_exchange_over_verified_local_tls(
    tmp_path: Path, monkeypatch
) -> None:
    ca_path, certificate_path, key_path = _write_local_tls_identity(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    _SyntheticHevHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), _SyntheticHevHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        bank = Bank(f"https://127.0.0.1:{server.server_port}/ebics", "HOST")
        clock = SystemClock()
        backend = EbicsBackend(HttpsTransport(clock=clock))

        discovered = backend.probe_versions(
            bank, DeadlineControl.after(10, clock)
        ).select_h005()

        assert discovered == NegotiatedProtocol()
        assert len(_SyntheticHevHandler.received) == 1
        assert b"ebicsHEVRequest" in _SyntheticHevHandler.received[0]
        assert b"<HostID>HOST</HostID>" in _SyntheticHevHandler.received[0]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
