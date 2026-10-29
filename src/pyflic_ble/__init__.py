"""pyflic-ble: Python library for Flic smart button BLE communication."""

from .client import (
    FlicAuthenticationError,
    FlicClient,
    FlicFirmwareUpdateError,
    FlicPairingError,
    FlicProtocolError,
    FlicState,
)
from .const import DeviceType, PushTwistMode
from .handlers import FlicCloudUnlock
from .handlers.base import DeviceCapabilities
from .protocol import Flic1UnlockRequest

__all__ = [
    "DeviceCapabilities",
    "DeviceType",
    "Flic1UnlockRequest",
    "FlicAuthenticationError",
    "FlicClient",
    "FlicCloudUnlock",
    "FlicFirmwareUpdateError",
    "FlicPairingError",
    "FlicProtocolError",
    "FlicState",
    "PushTwistMode",
]
