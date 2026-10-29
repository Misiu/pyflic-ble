"""Flic 1 protocol handler implementation.

Flic 1 (first generation) does not use the Flic 2 framing, Chaskey MACs or Ed25519, so the
handler owns its transport (``DeviceCapabilities.raw_transport``): it listens on two
characteristics, signs the packets it writes with SHA-256 MACs and verifies every event it
receives. Pairing needs the Flic cloud once; the application provides that call.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import logging
import re
import secrets
import time
from typing import TYPE_CHECKING

from ..const import (
    COMMAND_TIMEOUT,
    FLIC1_AUTO_DISCONNECT_NEVER,
    FLIC1_BATTERY_ENTRY_OFFSET,
    FLIC1_BATTERY_ENTRY_SCALE,
    FLIC1_BATTERY_LOG_AVERAGED_ENTRIES,
    FLIC1_BATTERY_LOG_BLOCK_SIZE,
    FLIC1_BATTERY_LOG_CHUNK_SIZE,
    FLIC1_BATTERY_LOG_TIMEOUT,
    FLIC1_CONFIG_CHAR_UUID,
    FLIC1_CONN_PARAM_INTERVAL_MAX,
    FLIC1_CONN_PARAM_INTERVAL_MIN,
    FLIC1_CONN_PARAM_LATENCY,
    FLIC1_CONN_PARAM_TIMEOUT,
    FLIC1_EVENT_CHAR_UUID,
    FLIC1_EVENT_SIZE,
    FLIC1_EVENT_STATUS_BYTES,
    FLIC1_HELLO_FLAG_PAIRING,
    FLIC1_HELLO_FLAG_PAIRING_WITH_BOND,
    FLIC1_HELLO_FLAG_QUICK_VERIFY_OR_PAIRING,
    FLIC1_MANUFACTURER_ID,
    FLIC1_OPCODE_BATTERY_LOG_DATA,
    FLIC1_OPCODE_BATTERY_LOG_HEADER,
    FLIC1_OPCODE_FULL_VERIFY_RESPONSE_1,
    FLIC1_OPCODE_FULL_VERIFY_RESPONSE_2,
    FLIC1_OPCODE_FULL_VERIFY_RESPONSE_3,
    FLIC1_PROBE_TIMEOUT,
    FLIC1_READY_FRAME_BYTE,
    FLIC1_SERVICE_UUID,
    FLIC1_STALE_EVENT_AGE,
    FLIC1_WRITE_REQUEST_ADDRESS_FIRST,
    FLIC1_WRITE_REQUEST_ADDRESS_LAST,
    GAP_DEVICE_NAME_CHAR_UUID,
    PAIRING_TIMEOUT,
)
from ..protocol import (
    Flic1AckEventsRequest,
    Flic1AdvertisedData,
    Flic1BatteryLogFromRequest,
    Flic1BatteryLogHeader,
    Flic1BatteryLogRequest,
    Flic1ConfigRequest,
    Flic1EventNotification,
    Flic1FullVerifyRequest1,
    Flic1FullVerifyRequest2,
    Flic1FullVerifyResponse1,
    Flic1FullVerifyResponse2,
    Flic1Hello,
    Flic1QuickVerifyRequest,
    Flic1UnlockResponse,
)
from ..security import (
    flic1_event_mac_valid,
    flic1_hello_mac_valid,
    flic1_packet_mac,
    flic1_ready_hash,
)
from .base import ButtonEvent, DeviceCapabilities, DeviceProtocolHandler, RotateEvent

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice

_LOGGER = logging.getLogger(__name__)

# Calls the Flic cloud for a pairing: (button uuid as hex, the 8 random bytes sent to the
# button, the button's nonce) -> text of the reply. Build the request body with
# Flic1UnlockRequest; the application owns the app credentials and the HTTP client.
FlicCloudUnlock = Callable[[str, bytes, bytes], Awaitable[str]]

# The advertised name is F|f + the 3 digit firmware revision + 4 characters
_FIRMWARE_NAME_PATTERN = re.compile(r"^[Ff](\d{3})")


def _needs_write_response(address: str) -> bool:
    """Return True for the buttons of the first production batch, by Bluetooth address."""
    try:
        value = int(address.replace(":", ""), 16)
    except ValueError:
        # Not a MAC address: CoreBluetooth identifies a device by a UUID
        return False
    return (
        FLIC1_WRITE_REQUEST_ADDRESS_FIRST <= value <= FLIC1_WRITE_REQUEST_ADDRESS_LAST
    )


class _Flic1Credentials:
    """Pairing secrets and the position up to which events were received."""

    def __init__(
        self, h1: bytes, h3: bytes, counter: int = 0, boot_id: int = 0, mask: int = 0
    ) -> None:
        """Initialize the credentials."""
        if len(h1) != 8 or len(h3) != 12:
            msg = "h1 must be 8 bytes and h3 12 bytes"
            raise ValueError(msg)
        self.h1 = h1
        self.h3 = h3
        self.counter = counter
        self.boot_id = boot_id
        self.mask = mask

    @classmethod
    def from_pairing(
        cls, pairing_id: int, pairing_key: bytes, sig_bits: int
    ) -> _Flic1Credentials:
        """Rebuild the credentials from what the application stored."""
        if len(pairing_key) != 20:
            msg = "A Flic 1 pairing key is 20 bytes (h1 + h3)"
            raise ValueError(msg)
        return cls(
            pairing_key[:8],
            pairing_key[8:],
            counter=pairing_id & 0xFFFFFF,
            boot_id=(pairing_id >> 24) & 0xFFFFFF,
            mask=sig_bits & 0xFF,
        )

    @property
    def pairing_key(self) -> bytes:
        """Return h1 + h3, the secret the application stores."""
        return self.h1 + self.h3

    @property
    def pairing_id(self) -> int:
        """Return the boot id and the event counter as one integer."""
        return (self.boot_id & 0xFFFFFF) << 24 | (self.counter & 0xFFFFFF)

    def accept(self, event: Flic1EventNotification) -> bool:
        """Return True and move the position if this event was not seen before."""
        if self.boot_id < event.boot_id:
            self.mask = 0
        elif self.boot_id > event.boot_id:
            return False
        elif self.counter < event.counter:
            self.mask = 0
        elif self.counter > event.counter or self.mask & (1 << event.event_kind):
            return False
        self.boot_id, self.counter = event.boot_id, event.counter
        self.mask |= 1 << event.event_kind
        return True


class Flic1ProtocolHandler(DeviceProtocolHandler):
    """Protocol handler for Flic 1 buttons."""

    _CAPABILITIES = DeviceCapabilities(
        button_count=1,
        has_rotation=False,
        has_selector=False,
        has_gestures=False,
        has_frame_header=False,
        raw_transport=True,
    )

    def __init__(
        self,
        address: str,
        cloud_unlock: FlicCloudUnlock | None = None,
        stale_event_age: float | None = FLIC1_STALE_EVENT_AGE,
    ) -> None:
        """Initialize the Flic 1 handler.

        ``stale_event_age`` is the age in seconds above which a press that the button
        queued while there was no link is acknowledged but not reported (None reports
        every queued press).
        """
        super().__init__()
        self._address = address
        self._cloud_unlock = cloud_unlock
        self._stale_event_age = stale_event_age
        # Buttons of the first production batch need acknowledged writes
        self._write_with_response = _needs_write_response(address)
        self._credentials: _Flic1Credentials | None = None
        self._nonce = b""
        self._packet_counter = 0
        self._send_lock = asyncio.Lock()
        self._ready = asyncio.Event()
        self._expected_ready_hash = b""
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._device_name: str | None = None
        self._advertised_battery: int | None = None
        self._logged_battery: int | None = None

    @property
    def service_uuid(self) -> str:
        """Return the BLE service UUID."""
        return FLIC1_SERVICE_UUID

    @property
    def write_char_uuid(self) -> str:
        """Return the BLE write characteristic UUID."""
        return FLIC1_CONFIG_CHAR_UUID

    @property
    def notify_char_uuid(self) -> str:
        """Return the BLE notify characteristic UUID that carries the button events."""
        return FLIC1_EVENT_CHAR_UUID

    @property
    def notify_char_uuids(self) -> tuple[str, ...]:
        """Return both notify characteristics: command replies and button events."""
        return (FLIC1_CONFIG_CHAR_UUID, FLIC1_EVENT_CHAR_UUID)

    @property
    def ed25519_public_key(self) -> bytes:
        """Return an empty key: Flic 1 does not use Ed25519."""
        return b""

    @property
    def capabilities(self) -> DeviceCapabilities:
        """Return the device capabilities."""
        return self._CAPABILITIES

    @property
    def connection_parameters(self) -> tuple[int, int, int, int]:
        """Return the connection parameters to request from the Bluetooth proxy."""
        return (
            FLIC1_CONN_PARAM_INTERVAL_MIN,
            FLIC1_CONN_PARAM_INTERVAL_MAX,
            FLIC1_CONN_PARAM_LATENCY,
            FLIC1_CONN_PARAM_TIMEOUT,
        )

    @property
    def connection_parameters_after_verify(self) -> bool:
        """Verify on the proxy's fast parameters, then relax them to save battery."""
        return True

    @property
    def advertises_when_disconnected_only(self) -> bool:
        """Return True: a connected Flic 1 does not advertise."""
        return True

    @property
    def supports_battery_log(self) -> bool:
        """Return True: the battery log can be read in the background."""
        return True

    def on_ble_device(self, ble_device: BLEDevice) -> None:
        """Remember the advertised name, it carries the firmware revision."""
        if ble_device.name and _FIRMWARE_NAME_PATTERN.match(ble_device.name):
            self._device_name = ble_device.name

    def on_advertisement(self, manufacturer_data: dict[int, bytes]) -> None:
        """Take the live battery value from the manufacturer data."""
        data = manufacturer_data.get(FLIC1_MANUFACTURER_ID)
        if data is None:
            return
        try:
            advertised = Flic1AdvertisedData.from_bytes(bytes(data))
        except ValueError:
            return
        if advertised.battery:
            self._advertised_battery = advertised.battery

    def reset_state(self) -> None:
        """Reset the session state (the pairing keys are kept by the client)."""
        super().reset_state()
        self._ready.clear()
        self._credentials = None
        self._nonce = b""
        self._packet_counter = 0
        for task in self._background_tasks:
            task.cancel()
        self._background_tasks.clear()

    async def _write_authenticated(
        self, request: bytes, response: bool = False
    ) -> None:
        """Write a request with the packet counter and a MAC appended."""
        if self._credentials is None:
            msg = "No pairing credentials available"
            raise ValueError(msg)
        # The counter, the MAC and the write have to stay in order
        async with self._send_lock:
            mac = flic1_packet_mac(
                request, self._packet_counter, self._nonce, self._credentials.h3
            )
            packet = request + bytes([self._packet_counter & 0xFF]) + mac
            self._packet_counter += 1
            await self._write_gatt(
                FLIC1_CONFIG_CHAR_UUID, packet, response or self._write_with_response
            )

    async def _send_ack(self) -> None:
        """Acknowledge the events received so far (written with response, like the Flic app)."""
        if self._credentials is None:
            return
        ack = Flic1AckEventsRequest(
            counter=self._credentials.counter,
            boot_id=self._credentials.boot_id,
            mask=self._credentials.mask,
        )
        await self._write_authenticated(ack.to_bytes(), response=True)

    async def _send_config(self) -> None:
        """Tell the button to keep the link instead of disconnecting after a while."""
        config = Flic1ConfigRequest(auto_disconnect_time=FLIC1_AUTO_DISCONNECT_NEVER)
        await self._write_authenticated(config.to_bytes())

    async def _read_hello(self) -> Flic1Hello:
        """Read and parse the hello of the button."""
        return Flic1Hello.from_bytes(
            bytes(await self._read_gatt(FLIC1_CONFIG_CHAR_UUID))
        )

    async def full_verify_pairing(
        self,
    ) -> tuple[int, bytes, str, int, int, bytes, int]:
        """Perform full pairing verification for Flic 1."""
        if self._cloud_unlock is None:
            msg = "Pairing a Flic 1 needs a cloud_unlock callback"
            raise ValueError(msg)

        hello = await self._read_hello()
        if hello.flag not in (
            FLIC1_HELLO_FLAG_QUICK_VERIFY_OR_PAIRING,
            FLIC1_HELLO_FLAG_PAIRING,
            FLIC1_HELLO_FLAG_PAIRING_WITH_BOND,
        ):
            msg = (
                f"The button is not in pairing mode (hello flag 0x{hello.flag:02x}), "
                "hold it for 7 seconds"
            )
            raise ValueError(msg)
        if hello.flag == FLIC1_HELLO_FLAG_PAIRING_WITH_BOND:
            _LOGGER.warning(
                "%s asks for a Bluetooth bond (hello flag 0x%02x), which is not done: "
                "pairing may fail",
                self._address,
                hello.flag,
            )

        random_bytes = secrets.token_bytes(8)
        _LOGGER.debug("Sending Flic1FullVerifyRequest1")
        await self._write_gatt(
            FLIC1_CONFIG_CHAR_UUID,
            Flic1FullVerifyRequest1(random_bytes=random_bytes).to_bytes(),
            self._write_with_response,
        )

        response1 = Flic1FullVerifyResponse1.from_bytes(
            await asyncio.wait_for(
                self._wait_for_opcode(FLIC1_OPCODE_FULL_VERIFY_RESPONSE_1),
                timeout=PAIRING_TIMEOUT,
            )
        )
        response2 = Flic1FullVerifyResponse2.from_bytes(
            await asyncio.wait_for(
                self._wait_for_opcode(FLIC1_OPCODE_FULL_VERIFY_RESPONSE_2),
                timeout=PAIRING_TIMEOUT,
            )
        )

        _LOGGER.debug("Asking the Flic cloud to unlock the button")
        cloud = Flic1UnlockResponse.from_json(
            await self._cloud_unlock(
                response2.button_uuid.hex(), random_bytes, response1.nonce
            )
        )
        if cloud.mac_address.lower() != self._address.lower():
            msg = "The Flic cloud answered for another Bluetooth address"
            raise ValueError(msg)
        if cloud.h2 != response1.h2:
            msg = "The Flic cloud's proof does not match the button's"
            raise ValueError(msg)

        _LOGGER.debug("Sending Flic1FullVerifyRequest2")
        await self._write_gatt(
            FLIC1_CONFIG_CHAR_UUID,
            Flic1FullVerifyRequest2(
                cloud_random=cloud.cloud_random, h1=cloud.h1
            ).to_bytes(),
            self._write_with_response,
        )
        await asyncio.wait_for(
            self._wait_for_opcode(FLIC1_OPCODE_FULL_VERIFY_RESPONSE_3),
            timeout=PAIRING_TIMEOUT,
        )

        self._credentials = _Flic1Credentials(cloud.h1, cloud.h3)
        self._nonce = response1.nonce
        self._packet_counter = 0
        await self._send_ack()
        await self._send_config()
        self._ready.set()

        _LOGGER.info("Pairing successful (serial=%s)", cloud.serial_number)

        return (
            self._credentials.pairing_id,
            self._credentials.pairing_key,
            cloud.serial_number,
            self._advertised_battery or 0,
            self._credentials.mask,
            response2.button_uuid,
            self._firmware_from_name() or 0,
        )

    async def quick_verify(
        self,
        pairing_id: int,
        pairing_key: bytes,
        sig_bits: int = 0,
    ) -> tuple[bytes, list[int]]:
        """Perform quick verification for Flic 1."""
        credentials = _Flic1Credentials.from_pairing(pairing_id, pairing_key, sig_bits)
        hello = await self._read_hello()
        if not flic1_hello_mac_valid(hello.raw, credentials.h3):
            msg = "The hello MAC does not match: wrong pairing key or the button was paired again"
            raise ValueError(msg)

        self._credentials = credentials
        self._nonce = hello.nonce
        self._packet_counter = 0
        random_bytes = secrets.token_bytes(6)
        self._expected_ready_hash = flic1_ready_hash(
            hello.nonce, random_bytes, credentials.h3
        )
        self._ready.clear()

        _LOGGER.debug("Sending Flic1QuickVerifyRequest")
        request = Flic1QuickVerifyRequest(h1=credentials.h1, random_bytes=random_bytes)
        await self._write_authenticated(request.to_bytes())
        await self._send_ack()
        await self._send_config()

        # The button confirms with a frame on the event characteristic
        await asyncio.wait_for(self._ready.wait(), timeout=COMMAND_TIMEOUT)
        # There are no session or Chaskey keys: the MACs use the pairing secret
        return b"", []

    async def init_button_events(
        self,
        session_key: bytes | None,
        chaskey_keys: list[int] | None,
    ) -> None:
        """Do nothing: events are delivered as soon as the quick verify succeeded."""

    def handle_notification(
        self,
        data: bytes,
    ) -> tuple[list[ButtonEvent], list[RotateEvent], int | None]:
        """Do nothing: Flic 1 notifications arrive through handle_raw_notification."""
        return [], [], None

    def handle_raw_notification(
        self, char_uuid: str, data: bytes
    ) -> tuple[list[ButtonEvent], bytes | None]:
        """Route a notification: replies to the client's queue, event frames to the parser."""
        char_uuid = char_uuid.lower()
        if char_uuid == FLIC1_CONFIG_CHAR_UUID:
            return [], data
        if char_uuid == FLIC1_EVENT_CHAR_UUID:
            return self._parse_event_frame(data), None
        return [], None

    def _parse_event_frame(self, frame: bytes) -> list[ButtonEvent]:
        """Parse a frame of the event characteristic."""
        if not self._ready.is_set():
            if (
                len(frame) >= FLIC1_EVENT_SIZE
                and frame[0] == FLIC1_READY_FRAME_BYTE
                and frame[1:FLIC1_EVENT_SIZE] == self._expected_ready_hash
            ):
                _LOGGER.debug("Flic 1 quick verify confirmed")
                self._ready.set()
            return []

        credentials = self._credentials
        if credentials is None or not frame or frame[0] in FLIC1_EVENT_STATUS_BYTES:
            return []
        if not flic1_event_mac_valid(frame, credentials.h3):
            _LOGGER.warning("Flic 1 event with an invalid MAC ignored")
            return []

        try:
            event = Flic1EventNotification.from_bytes(frame)
        except ValueError as err:
            _LOGGER.debug("Failed to parse Flic 1 button event: %s", err)
            return []
        if not credentials.accept(event):
            _LOGGER.debug("Flic 1 event 0x%02x already received", event.event_byte)
            return []

        if self._credentials_callback:
            self._credentials_callback(
                credentials.pairing_id, credentials.pairing_key, credentials.mask
            )
        if event.needs_ack:
            task = asyncio.get_running_loop().create_task(self._send_ack())
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

        _LOGGER.debug(
            "Flic 1 button event: byte=0x%02x, age=%d, was_queued=%s",
            event.event_byte,
            event.age,
            event.was_queued,
        )
        if (
            event.was_queued
            and self._stale_event_age is not None
            and event.age > self._stale_event_age
        ):
            _LOGGER.debug("Dropping stale queued Flic 1 event (age %d s)", event.age)
            return []

        # The button reports how long ago the press happened, not a clock: estimate it
        timestamp_ms = int(time.time() * 1000) - event.age * 1000
        return [
            ButtonEvent(
                event_type=event_type,
                button_index=None,
                timestamp_ms=timestamp_ms,
                was_queued=event.was_queued,
                extra_data={},
            )
            for event_type in event.event_types
        ]

    async def liveness_probe(self) -> None:
        """Read the hello: a dead link does not answer."""
        await asyncio.wait_for(
            self._read_gatt(FLIC1_CONFIG_CHAR_UUID), timeout=FLIC1_PROBE_TIMEOUT
        )

    async def get_battery_level(self) -> int:
        """Return the raw battery value (advertised, otherwise from the battery log)."""
        raw = self._advertised_battery or self._logged_battery
        if raw is None:
            msg = "No battery value available yet"
            raise ValueError(msg)
        return raw

    async def read_battery_log(self) -> int | None:
        """Read the battery log and return the raw value of its newest entries."""
        samples = bytearray()
        try:
            async with asyncio.timeout(FLIC1_BATTERY_LOG_TIMEOUT):
                await self._write_authenticated(Flic1BatteryLogRequest().to_bytes())
                header = Flic1BatteryLogHeader.from_bytes(
                    await self._wait_for_opcode(FLIC1_OPCODE_BATTERY_LOG_HEADER)
                )
                start = max(0, header.entries - header.available_entries)
                wanted = header.entries - start
                if wanted:
                    await self._write_authenticated(
                        Flic1BatteryLogFromRequest(position=start).to_bytes()
                    )
                while len(samples) < wanted:
                    frame = await self._wait_for_opcode(FLIC1_OPCODE_BATTERY_LOG_DATA)
                    count = min(FLIC1_BATTERY_LOG_CHUNK_SIZE, wanted - len(samples))
                    samples += frame[1 : 1 + count]
                    # The button sends one block per request, ask for the next one
                    if (
                        len(samples) < wanted
                        and len(samples) % FLIC1_BATTERY_LOG_BLOCK_SIZE == 0
                    ):
                        await self._write_authenticated(
                            Flic1BatteryLogFromRequest(
                                position=start + len(samples)
                            ).to_bytes()
                        )
        except TimeoutError as err:
            msg = "The button did not answer the battery log request"
            raise TimeoutError(msg) from err

        raw = self._battery_from_log(bytes(samples))
        if raw is not None:
            self._logged_battery = raw
        return raw

    @staticmethod
    def _battery_from_log(samples: bytes) -> int | None:
        """Return the raw battery value of the newest log entries.

        A 0 entry separates two batteries: older entries belong to the cell that was
        replaced, so the scan stops there. A log that ends with that marker is unknown.
        """
        total = count = 0
        for sample in reversed(samples):
            if sample == 0:
                break
            total += FLIC1_BATTERY_ENTRY_OFFSET + FLIC1_BATTERY_ENTRY_SCALE * sample
            count += 1
            if count == FLIC1_BATTERY_LOG_AVERAGED_ENTRIES:
                break
        return total // count if count else None

    def _firmware_from_name(self) -> int | None:
        """Return the firmware revision from the advertised name."""
        if self._device_name and (
            match := _FIRMWARE_NAME_PATTERN.match(self._device_name)
        ):
            return int(match.group(1))
        return None

    async def start_firmware_update(self, firmware_binary: bytes) -> int:
        """Raise NotImplementedError: Flic 1 has no firmware update over Bluetooth."""
        msg = "Firmware updates are not supported by Flic 1"
        raise NotImplementedError(msg)

    async def send_firmware_data(
        self,
        firmware_binary: bytes,
        start_pos: int,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> bool:
        """Raise NotImplementedError: Flic 1 has no firmware update over Bluetooth."""
        msg = "Firmware updates are not supported by Flic 1"
        raise NotImplementedError(msg)

    async def send_force_disconnect(self, restart_adv: bool = True) -> None:
        """Raise NotImplementedError: Flic 1 has no force disconnect command."""
        msg = "Force disconnect is not supported by Flic 1"
        raise NotImplementedError(msg)

    async def get_name(self) -> tuple[str, int]:
        """Raise NotImplementedError: the name of a Flic 1 cannot be read."""
        msg = "The name cannot be read from a Flic 1"
        raise NotImplementedError(msg)

    async def set_name(self, name: str) -> tuple[str, int]:
        """Raise NotImplementedError: the name of a Flic 1 cannot be changed."""
        msg = "The name cannot be changed on a Flic 1"
        raise NotImplementedError(msg)

    async def get_firmware_version(self) -> int:
        """Return the firmware revision: the digits of the advertised or GAP device name."""
        if (firmware := self._firmware_from_name()) is not None:
            return firmware
        name = bytes(await self._read_gatt(GAP_DEVICE_NAME_CHAR_UUID)).decode(
            "utf-8", errors="ignore"
        )
        if match := _FIRMWARE_NAME_PATTERN.match(name):
            return int(match.group(1))
        msg = "The firmware revision is not part of the device name"
        raise ValueError(msg)
