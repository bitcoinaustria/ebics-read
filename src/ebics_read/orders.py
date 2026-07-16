"""The complete fixed EBICS operation allowlist."""

from enum import Enum


class OrderType(str, Enum):
    """Only operations that may exist in EBICS Read."""

    HEV = "HEV"
    INI = "INI"
    HIA = "HIA"
    HPB = "HPB"
    HPD = "HPD"
    HAA = "HAA"
    HKD = "HKD"
    HTD = "HTD"
    BTD = "BTD"


DISCOVERY_ORDERS = frozenset(
    {OrderType.HPD, OrderType.HAA, OrderType.HKD, OrderType.HTD}
)
INITIALIZATION_ORDERS = frozenset({OrderType.INI, OrderType.HIA, OrderType.HPB})
DOWNLOAD_ORDERS = frozenset({OrderType.BTD})
