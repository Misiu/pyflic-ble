"""Flic device protocol handlers."""

from __future__ import annotations

from typing import assert_never

from ..const import FLIC1_STALE_EVENT_AGE, DeviceType, PushTwistMode
from .base import ButtonEvent, DeviceCapabilities, DeviceProtocolHandler, RotateEvent
from .duo import DuoProtocolHandler
from .flic1 import Flic1ProtocolHandler, FlicCloudUnlock
from .flic2 import Flic2ProtocolHandler
from .twist import TwistProtocolHandler

__all__ = [
    "ButtonEvent",
    "DeviceCapabilities",
    "DeviceProtocolHandler",
    "DuoProtocolHandler",
    "Flic1ProtocolHandler",
    "Flic2ProtocolHandler",
    "FlicCloudUnlock",
    "RotateEvent",
    "TwistProtocolHandler",
    "create_handler",
]


def create_handler(
    device_type: DeviceType,
    push_twist_mode: PushTwistMode = PushTwistMode.DEFAULT,
    *,
    address: str = "",
    cloud_unlock: FlicCloudUnlock | None = None,
    stale_event_age: float | None = FLIC1_STALE_EVENT_AGE,
) -> DeviceProtocolHandler:
    """Create the appropriate protocol handler for a device type.

    ``address``, ``cloud_unlock`` and ``stale_event_age`` are only used by Flic 1.
    """
    match device_type:
        case DeviceType.FLIC1:
            return Flic1ProtocolHandler(
                address=address,
                cloud_unlock=cloud_unlock,
                stale_event_age=stale_event_age,
            )
        case DeviceType.TWIST:
            return TwistProtocolHandler(push_twist_mode=push_twist_mode)
        case DeviceType.DUO:
            return DuoProtocolHandler()
        case DeviceType.FLIC2:
            return Flic2ProtocolHandler()
        case _:
            assert_never(device_type)
