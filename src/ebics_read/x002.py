"""Exact EBICS X002 response authentication verification."""

from __future__ import annotations

import base64
import binascii
import hmac
from dataclasses import dataclass, field
from hashlib import sha256

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree

from .errors import SecurityError, XmlSecurityError
from .h005 import (
    H005_NAMESPACE,
    H005ReturnCodes,
    ParsedH005Response,
    parse_h005_response,
)
from .models import TrustedBankKeys

_DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_REFERENCE = "#xpointer(//*[@authenticate='true'])"
_VERIFICATION_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedH005Response:
    """An H005 response whose X002 digest and bank signature were verified."""

    document: bytes = field(repr=False, init=False)
    return_codes: H005ReturnCodes = field(init=False)

    def __init__(
        self,
        document: bytes,
        return_codes: H005ReturnCodes,
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _VERIFICATION_TOKEN:
            raise TypeError("authenticated responses require X002 verification")
        object.__setattr__(self, "document", bytes(document))
        object.__setattr__(self, "return_codes", return_codes)


def verify_x002_response(
    parsed: ParsedH005Response, trusted_bank_keys: TrustedBankKeys
) -> AuthenticatedH005Response:
    """Verify the one fixed X002 structure using the pinned bank authentication key."""

    if not isinstance(parsed, ParsedH005Response):
        raise TypeError("parsed must be a ParsedH005Response")
    if not isinstance(trusted_bank_keys, TrustedBankKeys):
        raise TypeError("trusted_bank_keys must be TrustedBankKeys")
    if parsed.root.tag != f"{{{H005_NAMESPACE}}}ebicsResponse":
        raise XmlSecurityError("X002 is not present on key-management responses")
    parsed = parse_h005_response(parsed.document, limits=parsed.limits)

    signature = list(parsed.root)[1]
    if signature.tag != f"{{{H005_NAMESPACE}}}AuthSignature" or signature.attrib:
        raise XmlSecurityError("H005 AuthSignature container is invalid")
    signed_info, signature_value = _exact_children(
        signature,
        ("SignedInfo", "SignatureValue"),
        namespace=_DS_NAMESPACE,
    )
    canonicalization, signature_method, reference = _exact_children(
        signed_info,
        ("CanonicalizationMethod", "SignatureMethod", "Reference"),
        namespace=_DS_NAMESPACE,
    )
    _algorithm(canonicalization, _C14N)
    _algorithm(signature_method, _RSA_SHA256)
    transforms, digest_method, digest_value = _exact_children(
        reference,
        ("Transforms", "DigestMethod", "DigestValue"),
        namespace=_DS_NAMESPACE,
        attributes={"URI": _REFERENCE},
    )
    (transform,) = _exact_children(
        transforms,
        ("Transform",),
        namespace=_DS_NAMESPACE,
    )
    _algorithm(transform, _C14N)
    _algorithm(digest_method, _SHA256)

    expected_digest = _decode_base64(digest_value, "digest")
    if len(expected_digest) != 32 or not hmac.compare_digest(
        expected_digest, sha256(_canonical_authenticated_nodes(parsed.root)).digest()
    ):
        raise SecurityError("X002 authenticated-data digest verification failed")

    supplied_signature = _decode_base64(signature_value, "signature")
    certificate = x509.load_der_x509_certificate(
        trusted_bank_keys.authentication.certificate_der
    )
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SecurityError("trusted X002 bank key is not RSA")
    key_bytes = (public_key.key_size + 7) // 8
    if not supplied_signature or len(supplied_signature) > key_bytes:
        raise SecurityError("X002 signature length is invalid")
    try:
        # EBICS 3.0.2 §11.1.2 permits omitted zero octets; RSA needs k bytes.
        public_key.verify(
            supplied_signature.rjust(key_bytes, b"\0"),
            _canonical(signed_info),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SecurityError("X002 bank signature verification failed") from exc
    return AuthenticatedH005Response(
        parsed.document,
        parsed.return_codes,
        _token=_VERIFICATION_TOKEN,
    )


def _exact_children(
    parent: etree._Element,
    local_names: tuple[str, ...],
    *,
    namespace: str,
    attributes: dict[str, str] | None = None,
) -> tuple[etree._Element, ...]:
    expected_attributes = {} if attributes is None else attributes
    if (
        set(parent.attrib) != set(expected_attributes)
        or any(parent.get(name) != value for name, value in expected_attributes.items())
        or (parent.text is not None and parent.text.strip())
    ):
        raise XmlSecurityError("X002 structure contains unexpected content")
    children = tuple(parent)
    if len(children) != len(local_names) or any(
        child.tag != f"{{{namespace}}}{local_name}"
        or (child.tail is not None and child.tail.strip())
        for child, local_name in zip(children, local_names, strict=True)
    ):
        raise XmlSecurityError("X002 structure or element order is invalid")
    return children


def _algorithm(element: etree._Element, expected: str) -> None:
    if (
        set(element.attrib) != {"Algorithm"}
        or element.get("Algorithm") != expected
        or list(element)
        or (element.text is not None and element.text.strip())
    ):
        raise XmlSecurityError("X002 contains an unsupported algorithm structure")


def _decode_base64(element: etree._Element, field_name: str) -> bytes:
    if element.attrib or list(element) or element.text is None:
        raise XmlSecurityError(f"X002 {field_name} value has an invalid shape")
    try:
        compact = (
            element.text.replace(" ", "")
            .replace("\t", "")
            .replace("\r", "")
            .replace("\n", "")
            .encode("ascii")
        )
        if not compact:
            raise ValueError
        return base64.b64decode(compact, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise XmlSecurityError(f"X002 {field_name} value is not strict base64") from exc


def _canonical_authenticated_nodes(root: etree._Element) -> bytes:
    marked = [element for element in root.iter() if "authenticate" in element.attrib]
    if any(node.get("authenticate") != "true" for node in marked):
        raise XmlSecurityError("X002 authentication marker is not lexical true")
    selected = [node for node in marked if node.get("authenticate") == "true"]
    if not selected:
        raise XmlSecurityError("X002 authenticated node selection is empty or invalid")
    outermost = [
        node
        for node in selected
        if not any(
            ancestor.get("authenticate") == "true" for ancestor in node.iterancestors()
        )
    ]
    return b"".join(_canonical(node) for node in outermost)


def _canonical(element: etree._Element) -> bytes:
    try:
        return etree.tostring(
            element,
            method="c14n",
            exclusive=False,
            with_comments=False,
        )
    except (etree.C14NError, ValueError) as exc:
        raise XmlSecurityError("X002 canonicalization failed") from exc
