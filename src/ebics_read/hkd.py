"""Strict H005 HKD customer and subscriber order data."""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal, InvalidOperation

from lxml import etree

from .errors import ConfigurationError, XmlSecurityError
from .h005 import H005_NAMESPACE
from .haa import (
    _build_haa_receipt_request_xml,
    _build_haa_transfer_request_xml,
    _build_metadata_initialization_request_xml,
    _decode_metadata_order_data,
    _HaaInitialResponse,
    _HaaOrderDataFragment,
    _parse_btf_descriptor,
    _parse_haa_initial_response,
    _parse_haa_receipt_response,
    _parse_haa_transfer_response,
)
from .interfaces import KeyProvider
from .models import (
    Bank,
    BtfDescriptor,
    CustomerInformation,
    DiscoveredAccount,
    DiscoveredUser,
    DownloadPermission,
    NegotiatedProtocol,
    ProtocolLimits,
    ReceiptKind,
    ServiceCapability,
    Subscriber,
    TransactionId,
    TrustedBankKeys,
)
from .orders import OrderType
from .xml import XmlLimits

_XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
_SCHEMA_LOCATION = f"{{{_XSI_NAMESPACE}}}schemaLocation"
_ORDER = re.compile(r"[A-Z0-9]{3}")
_USER = re.compile(r"[A-Za-z0-9,=]{1,35}")
_ACCOUNT_NUMBER = re.compile(r"(?:[0-9]{3,10}|[A-Z]{2}[0-9]{2}[A-Za-z0-9]{3,30})")
_BANK_CODE = re.compile(r"(?:[0-9]{8}|[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)")
_NCNAME = re.compile(r"[A-Za-z_][A-Za-z0-9._-]*")
_AMOUNT = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]{0,4})?|\.[0-9]{1,4})")


def _build_hkd_initialization_request_xml(
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    trusted_bank_keys: TrustedBankKeys,
    nonce: bytes,
    timestamp: datetime,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    return _build_metadata_initialization_request_xml(
        "HKD",
        bank,
        subscriber,
        protocol,
        trusted_bank_keys,
        nonce,
        timestamp,
        key_provider,
        authentication_certificate_der,
    )


def _build_hkd_transfer_request_xml(
    bank: Bank,
    protocol: NegotiatedProtocol,
    transaction_id: TransactionId,
    segment_number: int,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    return _build_haa_transfer_request_xml(
        bank,
        protocol,
        transaction_id,
        segment_number,
        key_provider,
        authentication_certificate_der,
    )


def _build_hkd_receipt_request_xml(
    bank: Bank,
    protocol: NegotiatedProtocol,
    transaction_id: TransactionId,
    receipt: ReceiptKind,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    return _build_haa_receipt_request_xml(
        bank,
        protocol,
        transaction_id,
        receipt,
        key_provider,
        authentication_certificate_der,
    )


def _parse_hkd_initial_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    subscriber_encryption_certificate_der: bytes,
    key_provider: KeyProvider,
    xml_limits: XmlLimits,
    protocol_limits: ProtocolLimits,
) -> _HaaInitialResponse:
    return _parse_haa_initial_response(
        response_xml,
        trusted_bank_keys,
        subscriber_encryption_certificate_der,
        key_provider,
        xml_limits,
        protocol_limits,
    )


def _parse_hkd_transfer_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    transaction_id: TransactionId,
    segment_number: int,
    total_segments: int,
    xml_limits: XmlLimits,
) -> _HaaOrderDataFragment:
    return _parse_haa_transfer_response(
        response_xml,
        trusted_bank_keys,
        transaction_id,
        segment_number,
        total_segments,
        xml_limits,
    )


def _parse_hkd_receipt_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    transaction_id: TransactionId,
    receipt: ReceiptKind,
    xml_limits: XmlLimits,
) -> None:
    _parse_haa_receipt_response(
        response_xml, trusted_bank_keys, transaction_id, receipt, xml_limits
    )


def _decode_hkd_information(
    fragments: list[str],
    transaction_key: bytes,
    expected_host_id: str,
    expected_user_id: str,
    xml_limits: XmlLimits,
    protocol_limits: ProtocolLimits,
) -> CustomerInformation:
    return _parse_hkd_information(
        _decode_metadata_order_data(
            fragments, transaction_key, xml_limits, protocol_limits
        ),
        expected_host_id,
        expected_user_id,
    )


def _parse_hkd_information(
    root: etree._Element, expected_host_id: str, expected_user_id: str
) -> CustomerInformation:
    return _parse_customer_information(
        root, expected_host_id, expected_user_id, OrderType.HKD
    )


def _parse_customer_information(
    root: etree._Element,
    expected_host_id: str,
    expected_user_id: str,
    source_order: OrderType,
) -> CustomerInformation:
    if source_order not in {OrderType.HKD, OrderType.HTD}:
        raise AssertionError("customer-data order is not fixed and allowlisted")
    _root(root, source_order)
    children = _children(root, attributes_allowed=True)
    if (
        len(children) < 2
        or _name(children[0]) != "PartnerInfo"
        or any(_name(child) != "UserInfo" for child in children[1:])
        or (source_order is OrderType.HTD and len(children) != 2)
    ):
        raise XmlSecurityError("HKD root structure or element order is invalid")
    accounts, services, host_id = _partner(children[0], expected_host_id, source_order)
    account_ids = {account.account_id for account in accounts}
    users = tuple(_user(child, account_ids) for child in children[1:])
    if expected_user_id not in {user.user_id for user in users}:
        raise XmlSecurityError("HKD response omits the requesting subscriber")
    try:
        return CustomerInformation(source_order, host_id, accounts, services, users)
    except (ConfigurationError, TypeError) as exc:
        raise XmlSecurityError(
            "HKD order data contains inconsistent information"
        ) from exc


def _root(root: etree._Element, source_order: OrderType) -> None:
    if root.tag != f"{{{H005_NAMESPACE}}}{source_order.value}ResponseOrderData":
        raise XmlSecurityError("HKD order-data root is invalid")
    if set(root.attrib) - {_SCHEMA_LOCATION}:
        raise XmlSecurityError("HKD order-data root has an unknown attribute")
    location = root.get(_SCHEMA_LOCATION)
    if location is not None:
        tokens = location.split()
        if (
            len(tokens) != 2
            or tokens[0] != H005_NAMESPACE
            or len(tokens[1].encode("utf-8")) > 1024
        ):
            raise XmlSecurityError("HKD schemaLocation is invalid")


def _partner(
    element: etree._Element, expected_host_id: str, source_order: OrderType
) -> tuple[tuple[DiscoveredAccount, ...], tuple[ServiceCapability, ...], str]:
    children = _children(element)
    if len(children) < 3 or [_name(child) for child in children[:2]] != [
        "AddressInfo",
        "BankInfo",
    ]:
        raise XmlSecurityError("HKD PartnerInfo structure is invalid")
    _address(children[0])
    host_id = _bank(children[1])
    if host_id != expected_host_id:
        raise XmlSecurityError("HKD HostID does not match the requested bank")
    index = 2
    accounts: list[DiscoveredAccount] = []
    while index < len(children) and _name(children[index]) == "AccountInfo":
        accounts.append(_account(children[index]))
        index += 1
    order_elements = children[index:]
    if not order_elements or any(
        _name(child) != "OrderInfo" for child in order_elements
    ):
        raise XmlSecurityError("HKD PartnerInfo requires OrderInfo last")
    order_information = tuple(_order_info(child) for child in order_elements)
    full_catalog = {
        descriptor for _, descriptor in order_information if descriptor is not None
    }
    services = tuple(
        ServiceCapability(descriptor, source_order)
        for order, descriptor in order_information
        if order == "BTD" and descriptor is not None
    )
    if len(services) != len(set(services)):
        raise XmlSecurityError("HKD PartnerInfo contains duplicate BTD services")
    btd_catalog = {service.descriptor for service in services}
    projected_accounts: list[DiscoveredAccount] = []
    for account in accounts:
        restrictions = account.restricted_services
        if restrictions is not None:
            if any(descriptor not in full_catalog for descriptor in restrictions):
                raise XmlSecurityError(
                    "HKD account restriction is absent from customer services"
                )
            restrictions = tuple(
                descriptor for descriptor in restrictions if descriptor in btd_catalog
            )
        projected_accounts.append(
            DiscoveredAccount(
                account.account_id, account.iban, account.currency, restrictions
            )
        )
    return tuple(projected_accounts), services, host_id


def _address(element: etree._Element) -> None:
    names = ("Name", "Street", "PostCode", "City", "Region", "Country")
    children = _children(element)
    index = 0
    for name in names:
        if index < len(children) and _name(children[index]) == name:
            _discarded_text(children[index], name, token=name == "PostCode")
            index += 1
    if index != len(children):
        raise XmlSecurityError("HKD AddressInfo structure is invalid")


def _bank(element: etree._Element) -> str:
    children = _children(element)
    if not children or _name(children[0]) != "HostID":
        raise XmlSecurityError("HKD BankInfo requires HostID first")
    host_id = _token_leaf(children[0], "HostID", 35, nonempty=True)
    names: set[str] = set()
    for child in children[1:]:
        if _name(child) != "Parameter":
            raise XmlSecurityError("HKD BankInfo contains an unsupported extension")
        parameter_name = _parameter(child)
        if parameter_name in names:
            raise XmlSecurityError("HKD BankInfo contains duplicate parameters")
        names.add(parameter_name)
    return host_id


def _parameter(element: etree._Element) -> str:
    name, value = _exact(element, ("Name", "Value"))
    parameter_name = _token_leaf(name, "Parameter Name", 256)
    if set(value.attrib) != {"Type"} or list(value) or value.text is None:
        raise XmlSecurityError("HKD Parameter Value has an invalid shape")
    kind = value.get("Type")
    if kind is None or len(kind) > 128 or _NCNAME.fullmatch(kind) is None:
        raise XmlSecurityError("HKD Parameter Value type is invalid")
    _bounded_normalized(value.text, "Parameter Value", 1024)
    return parameter_name


def _account(element: etree._Element) -> DiscoveredAccount:
    if (
        set(element.attrib) - {"ID", "Currency", "Description"}
        or element.get("ID") is None
    ):
        raise XmlSecurityError("HKD AccountInfo attributes are invalid")
    account_id = _token(element.get("ID") or "", "AccountInfo ID", 64, nonempty=True)
    currency = _currency(element.get("Currency", "EUR"), "AccountInfo Currency")
    description = element.get("Description")
    if description is not None:
        _bounded_normalized(description, "AccountInfo Description", 1024)
    children = _children(element, attributes_allowed=True)
    index = 0
    account_branches: set[str] = set()
    iban = None
    while index < len(children) and _name(children[index]) in {
        "AccountNumber",
        "NationalAccountNumber",
    }:
        name = _name(children[index])
        if name in account_branches or len(account_branches) == 2:
            raise XmlSecurityError("HKD AccountInfo has ambiguous account numbers")
        account_branches.add(name)
        value = children[index]
        if name == "AccountNumber":
            international, number = _account_number(value)
            if international:
                iban = number
        else:
            _formatted_text(value, "NationalAccountNumber", 40)
        index += 1
    if not account_branches:
        raise XmlSecurityError("HKD AccountInfo requires an account number")
    bank_branches: set[str] = set()
    while index < len(children) and _name(children[index]) in {
        "BankCode",
        "NationalBankCode",
    }:
        name = _name(children[index])
        if name in bank_branches or len(bank_branches) == 2:
            raise XmlSecurityError("HKD AccountInfo has ambiguous bank codes")
        bank_branches.add(name)
        if name == "BankCode":
            _bank_code(children[index])
        else:
            _formatted_text(children[index], "NationalBankCode", 30)
        index += 1
    if index < len(children) and _name(children[index]) == "AccountHolder":
        _discarded_text(children[index], "AccountHolder")
        index += 1
    restrictions = None
    if index < len(children) and _name(children[index]) == "UsageOrderTypes":
        usage = _children(children[index])
        if any(_name(child) != "Service" for child in usage):
            raise XmlSecurityError("HKD UsageOrderTypes structure is invalid")
        restrictions = tuple(_parse_btf_descriptor(child) for child in usage)
        if len(restrictions) != len(set(restrictions)):
            raise XmlSecurityError(
                "HKD account contains duplicate service restrictions"
            )
        index += 1
    if index != len(children):
        raise XmlSecurityError("HKD AccountInfo structure or element order is invalid")
    try:
        return DiscoveredAccount(account_id, iban, currency, restrictions)
    except (ConfigurationError, TypeError) as exc:
        raise XmlSecurityError("HKD account information is invalid") from exc


def _account_number(element: etree._Element) -> tuple[bool, str]:
    if set(element.attrib) - {"international"}:
        raise XmlSecurityError("HKD AccountNumber has an unknown attribute")
    number = _token_leaf(
        element, "AccountNumber", 40, attributes_allowed=True, nonempty=True
    )
    if _ACCOUNT_NUMBER.fullmatch(number) is None:
        raise XmlSecurityError("HKD AccountNumber is invalid")
    international = _boolean(element.get("international", "false"), "AccountNumber")
    if (
        international
        and re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{3,30}", number) is None
    ):
        raise XmlSecurityError(
            "HKD international AccountNumber is not an uppercase IBAN"
        )
    return international, number


def _bank_code(element: etree._Element) -> None:
    if set(element.attrib) - {"international", "Prefix"}:
        raise XmlSecurityError("HKD BankCode has an unknown attribute")
    value = _token_leaf(element, "BankCode", 11, attributes_allowed=True, nonempty=True)
    if _BANK_CODE.fullmatch(value) is None:
        raise XmlSecurityError("HKD BankCode is invalid")
    _boolean(element.get("international", "false"), "BankCode")
    prefix = element.get("Prefix")
    if prefix is not None:
        _token(prefix, "BankCode Prefix", 2, nonempty=True)
        if len(prefix) != 2:
            raise XmlSecurityError("HKD BankCode Prefix is invalid")


def _formatted_text(element: etree._Element, name: str, maximum: int) -> None:
    if set(element.attrib) != {"format"}:
        raise XmlSecurityError(f"HKD {name} format is required")
    _token(element.get("format") or "", f"{name} format", 128, nonempty=True)
    _normalized_leaf(element, name, maximum, attributes_allowed=True)


def _order_info(element: etree._Element) -> tuple[str, BtfDescriptor | None]:
    children = _children(element)
    if not children or _name(children[0]) != "AdminOrderType":
        raise XmlSecurityError("HKD OrderInfo requires AdminOrderType first")
    order = _order_type(children[0])
    index = 1
    descriptor = None
    if index < len(children) and _name(children[index]) == "Service":
        descriptor = _parse_btf_descriptor(children[index])
        index += 1
    if index >= len(children) or _name(children[index]) != "Description":
        raise XmlSecurityError("HKD OrderInfo requires Description")
    _normalized_leaf(children[index], "OrderInfo Description", 128)
    index += 1
    if index < len(children) and _name(children[index]) == "NumSigRequired":
        _nonnegative(children[index], "NumSigRequired")
        index += 1
    if index != len(children):
        raise XmlSecurityError("HKD OrderInfo structure is invalid")
    if order == "BTD" and descriptor is None:
        raise XmlSecurityError("HKD BTD OrderInfo requires a Service")
    return order, descriptor


def _user(element: etree._Element, known_accounts: set[str]) -> DiscoveredUser:
    children = _children(element)
    if not children or _name(children[0]) != "UserID":
        raise XmlSecurityError("HKD UserInfo requires UserID first")
    user = children[0]
    if set(user.attrib) != {"Status"}:
        raise XmlSecurityError("HKD UserID Status is required")
    user_id = _token_leaf(user, "UserID", 35, attributes_allowed=True, nonempty=True)
    if _USER.fullmatch(user_id) is None:
        raise XmlSecurityError("HKD UserID is invalid")
    status = _status(user.get("Status") or "")
    index = 1
    if index < len(children) and _name(children[index]) == "Name":
        _discarded_text(children[index], "User Name")
        index += 1
    permission_elements = children[index:]
    if not permission_elements or any(
        _name(child) != "Permission" for child in permission_elements
    ):
        raise XmlSecurityError("HKD UserInfo requires Permission last")
    parsed_permissions = tuple(_permission(child) for child in permission_elements)
    if any(
        account_id is not None and account_id not in known_accounts
        for _, account_id in parsed_permissions
    ):
        raise XmlSecurityError("HKD Permission references an unknown account")
    permissions = tuple(
        permission for permission, _ in parsed_permissions if permission is not None
    )
    try:
        return DiscoveredUser(user_id, status, permissions)
    except (ConfigurationError, TypeError) as exc:
        raise XmlSecurityError("HKD user information is invalid") from exc


def _permission(
    element: etree._Element,
) -> tuple[DownloadPermission | None, str | None]:
    if set(element.attrib) - {"AuthorisationLevel"}:
        raise XmlSecurityError("HKD Permission has an unknown attribute")
    level = element.get("AuthorisationLevel")
    if level is not None and level not in {"E", "A", "B", "T"}:
        raise XmlSecurityError("HKD Permission AuthorisationLevel is invalid")
    children = _children(element, attributes_allowed=True)
    if not children or _name(children[0]) != "AdminOrderType":
        raise XmlSecurityError("HKD Permission requires AdminOrderType first")
    order = _order_type(children[0])
    index = 1
    descriptor = None
    if index < len(children) and _name(children[index]) == "Service":
        descriptor = _parse_btf_descriptor(children[index])
        index += 1
    account_id = None
    if index < len(children) and _name(children[index]) == "AccountID":
        account_id = _token_leaf(children[index], "AccountID", 64, nonempty=True)
        index += 1
    if index < len(children) and _name(children[index]) == "MaxAmount":
        _max_amount(children[index])
        index += 1
    if index != len(children):
        raise XmlSecurityError("HKD Permission structure is invalid")
    if order != "BTD":
        return None, account_id
    if descriptor is None:
        raise XmlSecurityError("HKD BTD Permission requires a Service")
    return DownloadPermission(descriptor, account_id), account_id


def _max_amount(element: etree._Element) -> None:
    if set(element.attrib) - {"Currency"}:
        raise XmlSecurityError("HKD MaxAmount has an unknown attribute")
    _currency(element.get("Currency", "EUR"), "MaxAmount Currency")
    value = _normalized_leaf(element, "MaxAmount", 32, attributes_allowed=True)
    if _AMOUNT.fullmatch(value) is None:
        raise XmlSecurityError("HKD MaxAmount is invalid")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise XmlSecurityError("HKD MaxAmount is invalid") from exc
    digits = number.as_tuple().digits
    exponent = number.as_tuple().exponent
    if not isinstance(exponent, int) or len(digits) > 24 or max(0, -exponent) > 4:
        raise XmlSecurityError("HKD MaxAmount exceeds its decimal bounds")


def _order_type(element: etree._Element) -> str:
    value = _token_leaf(element, "AdminOrderType", 3, nonempty=True)
    if _ORDER.fullmatch(value) is None:
        raise XmlSecurityError("HKD AdminOrderType is invalid")
    return value


def _status(value: str) -> int:
    if (
        not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise XmlSecurityError("HKD user status is invalid")
    result = int(value)
    if result > 99:
        raise XmlSecurityError("HKD user status is invalid")
    return result


def _nonnegative(element: etree._Element, name: str) -> int:
    value = _token_leaf(element, name, 16, nonempty=True)
    if (
        not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise XmlSecurityError(f"HKD {name} is invalid")
    return int(value)


def _currency(value: str, name: str) -> str:
    if re.fullmatch(r"[A-Z]{3}", value) is None:
        raise XmlSecurityError(f"HKD {name} is invalid")
    return value


def _boolean(value: str, name: str) -> bool:
    if value in {"true", "1"}:
        return True
    if value in {"false", "0"}:
        return False
    raise XmlSecurityError(f"HKD {name} boolean is invalid")


def _discarded_text(element: etree._Element, name: str, *, token: bool = False) -> None:
    if token:
        _token_leaf(element, name, 1024)
    else:
        _normalized_leaf(element, name, 1024)


def _normalized_leaf(
    element: etree._Element,
    name: str,
    maximum: int,
    *,
    attributes_allowed: bool = False,
) -> str:
    if (
        (element.attrib and not attributes_allowed)
        or list(element)
        or element.text is None
    ):
        raise XmlSecurityError(f"HKD {name} has an invalid shape")
    return _bounded_normalized(element.text, name, maximum)


def _token_leaf(
    element: etree._Element,
    name: str,
    maximum: int,
    *,
    attributes_allowed: bool = False,
    nonempty: bool = False,
) -> str:
    value = _normalized_leaf(
        element, name, maximum, attributes_allowed=attributes_allowed
    )
    return _token(value, name, maximum, nonempty=nonempty)


def _token(value: str, name: str, maximum: int, *, nonempty: bool = False) -> str:
    _bounded_normalized(value, name, maximum)
    if value != " ".join(value.split()) or (nonempty and not value):
        raise XmlSecurityError(f"HKD {name} is not a normalized token")
    return value


def _bounded_normalized(value: str, name: str, maximum: int) -> str:
    if len(value) > maximum or any(character in value for character in "\r\n\t"):
        raise XmlSecurityError(f"HKD {name} exceeds normalized text bounds")
    return value


def _exact(
    parent: etree._Element, names: tuple[str, ...]
) -> tuple[etree._Element, ...]:
    children = _children(parent)
    if len(children) != len(names) or any(
        _name(child) != name for child, name in zip(children, names, strict=True)
    ):
        raise XmlSecurityError("HKD structure or element order is invalid")
    return tuple(children)


def _children(
    parent: etree._Element, *, attributes_allowed: bool = False
) -> list[etree._Element]:
    if (parent.attrib and not attributes_allowed) or (
        parent.text is not None and parent.text.strip()
    ):
        raise XmlSecurityError("HKD structure contains unexpected content")
    children = list(parent)
    if any(
        not isinstance(child.tag, str)
        or (child.tail is not None and child.tail.strip())
        for child in children
    ):
        raise XmlSecurityError("HKD structure contains text, comments, or instructions")
    return children


def _name(element: etree._Element) -> str:
    if not isinstance(element.tag, str):
        raise XmlSecurityError("HKD order data contains a comment or instruction")
    name = etree.QName(element)
    if name.namespace != H005_NAMESPACE:
        raise XmlSecurityError("HKD order data contains a foreign element")
    return name.localname
