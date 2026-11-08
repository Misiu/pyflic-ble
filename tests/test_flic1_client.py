"""Test FlicClient with a Flic 1 against a fake button."""

import asyncio
from collections.abc import Callable, Iterator
import contextlib
import hashlib
import json
import logging
from typing import Any
from unittest.mock import AsyncMock, patch

from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
import pytest

from pyflic_ble import (
    DeviceType,
    FlicAuthenticationError,
    FlicClient,
    FlicPairingError,
)
from pyflic_ble.const import (
    EVENT_TYPE_CLICK,
    EVENT_TYPE_DOUBLE_CLICK,
    EVENT_TYPE_DOWN,
    EVENT_TYPE_UP,
    FLIC1_CONFIG_CHAR_UUID,
    FLIC1_EVENT_CHAR_UUID,
    FLIC1_MANUFACTURER_ID,
)
from pyflic_ble.handlers import Flic1ProtocolHandler, create_handler

ADDRESS = "80:E4:DA:12:34:56"
H1 = bytes(range(1, 9))
H3 = bytes(range(0xA0, 0xAC))
BUTTON_UUID = bytes(range(0x30, 0x40))
SERIAL_NUMBER = "AH25-D00214"
CLOUD_RANDOM = 77
# Event counter 4 of boot 2
PAIRING_ID = 2 << 24 | 4
# Manufacturer data of an advertisement with the raw battery value 1577
ADVERTISED_BATTERY = bytes.fromhex("0002ec052f2700002906020000dae480")


def _sha(*parts: bytes) -> bytes:
    """Return the SHA-256 of the concatenated parts."""
    return hashlib.sha256(b"".join(parts)).digest()


class FakeButton:
    """Play a Flic 1 and the Bluetooth link to it, and record what the host writes.

    The button side is written from the protocol, not from the library: it checks the
    counter and the MAC of every packet it receives.
    """

    def __init__(
        self,
        flag: int = 0x41,
        nonce: bytes = b"N" * 8,
        h2: bytes = b"\x22" * 8,
    ) -> None:
        """Initialize the button, with the hello flag, its nonce and its pairing proof."""
        self.flag = flag
        self.nonce = nonce
        self.h2 = h2
        self.is_connected = False
        self.mtu_size = 185
        self.connections = 0
        self.disconnected_callback: Callable[[Any], None] | None = None
        self.notify: dict[str, Callable[[Any, bytearray], None]] = {}
        self.connection_params: list[tuple[tuple[int, ...], int]] = []
        # (opcode, payload, written with response) of the signed packets
        self.auth: list[tuple[int, bytes, bool]] = []
        self.random_bytes = b""
        self.reads = 0
        # A silent button ignores writes, a frozen link never answers a read
        self.silent = False
        self.frozen = False
        # The battery log, one byte per entry, and how many entries the button can send
        self.log = b""
        self.log_available = 10**6
        self._counter = 0

    def connect(self, disconnected_callback: Callable[[Any], None]) -> "FakeButton":
        """Open a link."""
        self.is_connected = True
        self.connections += 1
        self.disconnected_callback = disconnected_callback
        self._counter = 0
        return self

    def drop(self) -> None:
        """Lose the link."""
        if self.is_connected:
            self.is_connected = False
            if self.disconnected_callback:
                self.disconnected_callback(self)

    async def disconnect(self) -> None:
        """Close the link (a real Bluetooth stack takes a moment)."""
        await asyncio.sleep(0)
        self.drop()

    def hello(self) -> bytes:
        """Return the hello of the button."""
        body = bytes([self.flag]) + self.nonce + bytes(8)
        return body + _sha(body, H3)[:3]

    async def read_gatt_char(self, char_uuid: str) -> bytearray:
        """Read the hello."""
        assert char_uuid == FLIC1_CONFIG_CHAR_UUID
        self.reads += 1
        if self.frozen:
            await asyncio.Event().wait()
        return bytearray(self.hello())

    async def start_notify(
        self, char_uuid: str, callback: Callable[[Any, bytearray], None]
    ) -> None:
        """Remember the notification callback."""
        self.notify[char_uuid] = callback

    async def set_connection_params(self, *params: int) -> None:
        """Remember the connection parameters and how far the session was."""
        self.connection_params.append((params, len(self.auth)))

    def push(self, char_uuid: str, data: bytes) -> None:
        """Send a notification."""
        asyncio.get_running_loop().call_soon(
            self.notify[char_uuid], None, bytearray(data)
        )

    def event(self, event_byte: int, counter: int, boot_id: int, age: int = 0) -> None:
        """Send a signed button event."""
        body = (
            bytes([event_byte])
            + counter.to_bytes(3, "little")
            + boot_id.to_bytes(3, "little")
            + age.to_bytes(4, "little")
        )
        self.push(FLIC1_EVENT_CHAR_UUID, body + _sha(body, H3)[:4])

    async def write_gatt_char(
        self, char_uuid: str, data: bytes, response: bool = False
    ) -> None:
        """Answer a write like the button does."""
        assert char_uuid == FLIC1_CONFIG_CHAR_UUID
        data = bytes(data)
        if self.silent:
            return
        if data[:2] == b"\x07\x00":
            self.random_bytes = data[2:10]
            self.push(FLIC1_CONFIG_CHAR_UUID, b"\x00" + self.nonce + self.h2 + bytes(3))
            self.push(FLIC1_CONFIG_CHAR_UUID, b"\x01" + BUTTON_UUID + bytes(3))
        elif data[:2] == b"\x07\x01":
            assert data[2:10] == CLOUD_RANDOM.to_bytes(8, "little")
            assert data[10:18] == H1
            self.push(FLIC1_CONFIG_CHAR_UUID, b"\x02" + bytes(19))
        else:
            self._handle_signed(data, response)

    def _handle_signed(self, data: bytes, response: bool) -> None:
        """Check the counter and the MAC of a packet and answer it."""
        opcode, payload, counter, mac = data[0], data[1:-5], data[-5], data[-4:]
        assert counter == self._counter & 0xFF
        assert (
            mac
            == _sha(data[:-5], self._counter.to_bytes(4, "little"), self.nonce, H3)[:4]
        )
        self._counter += 1
        self.auth.append((opcode, payload, response))

        if opcode == 0x09:
            assert payload[:8] == H1
            self.push(
                FLIC1_EVENT_CHAR_UUID,
                b"\x40" + _sha(self.nonce, payload[8:14], H3)[:14],
            )
        elif opcode == 0x18:
            header = (
                b"\x05"
                + len(self.log).to_bytes(2, "little")
                + (1000).to_bytes(4, "little")
                + min(len(self.log), self.log_available).to_bytes(4, "little")
            )
            self.push(FLIC1_CONFIG_CHAR_UUID, header.ljust(20, b"\x00"))
        elif opcode == 0x19:
            start = int.from_bytes(payload[:4], "little")
            end = min(len(self.log), start + 285)
            for position in range(start, end, 19):
                chunk = self.log[position : min(position + 19, end)]
                self.push(FLIC1_CONFIG_CHAR_UUID, (b"\x06" + chunk).ljust(20, b"\x00"))


@contextlib.contextmanager
def _link(button: FakeButton) -> Iterator[None]:
    """Connect FlicClient to the fake button instead of a Bluetooth adapter."""

    async def establish_connection(
        _client_class: Any,
        _device: BLEDevice,
        _name: str,
        disconnected_callback: Callable[[Any], None],
        **_kwargs: Any,
    ) -> FakeButton:
        return button.connect(disconnected_callback)

    with (
        patch("pyflic_ble.client.establish_connection", establish_connection),
        patch("pyflic_ble.client.close_stale_connections_by_address", AsyncMock()),
    ):
        yield


def _device(address: str = ADDRESS) -> BLEDevice:
    """Return the Bluetooth device of a Flic 1 with firmware 23."""
    return BLEDevice(address, "f023abcd", {})


def _client(
    address: str = ADDRESS, pairing_key: bytes = H1 + H3, **kwargs: Any
) -> FlicClient:
    """Return the client of a paired Flic 1."""
    return FlicClient(
        address,
        _device(address),
        pairing_id=PAIRING_ID,
        pairing_key=pairing_key,
        device_type=DeviceType.FLIC1,
        **kwargs,
    )


def _collect(client: FlicClient) -> list[tuple[str, bool]]:
    """Return a list that receives (event type, was queued) of every button event."""
    events: list[tuple[str, bool]] = []
    client.register_button_event_callback(
        lambda event_type, data: events.append((event_type, data["was_queued"]))
    )
    return events


def _opcodes(button: FakeButton) -> list[int]:
    """Return the opcodes of the signed packets the host wrote."""
    return [opcode for opcode, _, _ in button.auth]


async def _until(condition: Callable[[], bool], timeout: float = 5) -> None:
    """Wait until the condition holds."""
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


def test_quick_verify_sequence() -> None:
    """Test the packets of a session start: verify, acknowledge, config."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            await client.start()

            assert client.state.connected
            assert client.state.firmware_version == 23
            assert _opcodes(button) == [0x09, 0x25, 0x06]
            # Only the acknowledgement is written with response
            assert [response for _, _, response in button.auth] == [False, True, False]
            assert button.auth[1][1] == (
                (4).to_bytes(4, "little") + (2).to_bytes(4, "little") + b"\x00"
            )
            # The button must not disconnect on its own
            assert button.auth[2][1] == bytes(6) + (511).to_bytes(2, "little")
            await client.stop()

    asyncio.run(scenario())


def test_connection_parameters_are_requested_after_the_verify() -> None:
    """Test that the slow link parameters are only set once the session works."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            await client.start()

            assert button.connection_params == [((70, 80, 19, 2000), 3)]
            await client.stop()

    asyncio.run(scenario())


def test_writes_with_response_for_the_first_production_batch() -> None:
    """Test that buttons of the first batch get acknowledged writes only."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client(address="80:E4:DA:70:10:00")
            await client.start()

            assert [response for _, _, response in button.auth] == [True] * 3
            await client.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("address", "with_response"),
    [
        ("80:E4:DA:70:00:00", True),
        ("80:E4:DA:70:72:54", True),
        ("80:E4:DA:70:72:55", False),
        ("80:E4:DA:6F:FF:FF", False),
        # CoreBluetooth identifies a device by a UUID, and a handler may have no address
        ("6F2A8C1E-3B4D-4E5F-9A7B-1C2D3E4F5A6B", False),
        ("", False),
    ],
)
def test_first_production_batch_is_recognised_by_address(
    address: str, with_response: bool
) -> None:
    """Test the address range, and that an address which is not a MAC is no error."""
    handler = Flic1ProtocolHandler(address)

    assert handler._write_with_response is with_response  # noqa: SLF001
    assert isinstance(
        create_handler(DeviceType.FLIC1, address=address), Flic1ProtocolHandler
    )


class RejectingButton(FakeButton):
    """A button behind a Bluetooth backend that fails to set connection parameters."""

    async def set_connection_params(self, *params: int) -> None:
        """Fail like a backend with an error of its own."""
        msg = "proxy error"
        raise RuntimeError(msg)


def test_failing_connection_parameters_do_not_end_the_session(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that an error of the Bluetooth backend only costs the link parameters."""

    async def scenario() -> None:
        button = RejectingButton()
        with _link(button):
            client = _client()
            await client.start()

            assert client.is_connected
            assert client.state.connected
            await client.stop()

    with caplog.at_level(logging.WARNING, logger="pyflic_ble"):
        asyncio.run(scenario())
    assert "Failed to request connection parameters" in caplog.text


def test_events_are_reported_once_acknowledged_and_saved() -> None:
    """Test the replay filter, the acknowledgements and the credentials callback."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            events = _collect(client)
            saved: list[tuple[int, int, int]] = []
            client.register_credentials_callback(
                lambda pairing_id, pairing_key, sig_bits: saved.append(
                    (pairing_id >> 24, pairing_id & 0xFFFFFF, sig_bits)
                )
            )
            await client.start()

            button.event(0x01, 5, 2)  # down
            button.event(0x1A, 5, 2, age=3)  # queued release with a single click
            button.event(0x1A, 5, 2)  # the same event once more
            button.event(0x0B, 6, 2)  # release with a double click
            button.event(0x0B, 3, 2)  # older than the last one
            await asyncio.sleep(0.05)

            assert events == [
                (EVENT_TYPE_DOWN, False),
                (EVENT_TYPE_UP, True),
                (EVENT_TYPE_CLICK, True),
                (EVENT_TYPE_UP, False),
                (EVENT_TYPE_DOUBLE_CLICK, False),
            ]
            assert saved == [(2, 5, 0b10), (2, 5, 0b11), (2, 6, 0b01)]
            # The initial one, the single click and the double click
            acknowledgements = [
                payload for opcode, payload, _ in button.auth if opcode == 0x25
            ]
            assert len(acknowledgements) == 3
            assert acknowledgements[-1] == (
                (6).to_bytes(4, "little") + (2).to_bytes(4, "little") + b"\x01"
            )
            await client.stop()

    asyncio.run(scenario())


def test_unauthentic_frames_are_ignored() -> None:
    """Test status frames, a wrong MAC and a short frame."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            events = _collect(client)
            await client.start()

            button.push(FLIC1_EVENT_CHAR_UUID, b"\x70" + bytes(14))
            button.push(FLIC1_EVENT_CHAR_UUID, b"\x60" + bytes(14))
            button.push(
                FLIC1_EVENT_CHAR_UUID, b"\x01\x05\x00\x00\x02\x00\x00" + bytes(8)
            )
            button.push(FLIC1_EVENT_CHAR_UUID, b"\x01\x05")
            await asyncio.sleep(0.05)

            assert events == []
            assert _opcodes(button) == [0x09, 0x25, 0x06]
            await client.stop()

    asyncio.run(scenario())


def test_old_queued_press_is_acknowledged_but_not_reported() -> None:
    """Test that a press from before the link was up does not trigger anything."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            events = _collect(client)
            await client.start()

            button.event(0x92, 5, 2, age=60)  # a click from a minute ago
            button.event(0x92, 6, 2, age=3)
            await asyncio.sleep(0.05)

            assert events == [(EVENT_TYPE_CLICK, True)]
            assert _opcodes(button).count(0x25) == 3
            await client.stop()

    asyncio.run(scenario())


def test_old_queued_press_is_reported_when_the_age_filter_is_off() -> None:
    """Test stale_event_age=None."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client(stale_event_age=None)
            events = _collect(client)
            await client.start()

            button.event(0x92, 5, 2, age=60)
            await asyncio.sleep(0.05)

            assert events == [(EVENT_TYPE_CLICK, True)]
            await client.stop()

    asyncio.run(scenario())


def test_wrong_pairing_key_drops_the_link(caplog: pytest.LogCaptureFixture) -> None:
    """Test that a button which was paired again is reported and not kept connected."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client(pairing_key=H1 + bytes(12))
            with pytest.raises(FlicAuthenticationError, match="hello MAC"):
                await client.start()

            assert not client.is_connected
            assert not client.state.connected

    with caplog.at_level(logging.ERROR, logger="pyflic_ble"):
        asyncio.run(scenario())
    assert "Failed to start session" in caplog.text


def test_failed_start_can_be_retried() -> None:
    """Test that a link without a verified session is closed, so that a retry works.

    The reconnect loop only runs while the client is disconnected, so a link left up
    after a failed start would never be used again.
    """

    async def scenario() -> None:
        button = FakeButton()
        button.silent = True
        with _link(button):
            client = _client()
            with (
                patch("pyflic_ble.handlers.flic1.COMMAND_TIMEOUT", 0.05),
                pytest.raises(FlicAuthenticationError, match="Quick verify timeout"),
            ):
                await client.start()
            assert not client.is_connected

            button.silent = False
            await client.start()
            assert client.is_connected
            assert client.state.connected
            assert button.connections == 2
            await client.stop()

    asyncio.run(scenario())


def test_reconnects_after_the_link_is_lost() -> None:
    """Test that the client connects again when the link drops."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            events = _collect(client)
            disconnects: list[bool] = []
            client.on_disconnect = lambda: disconnects.append(True)
            await client.start()

            button.drop()
            assert disconnects == [True]
            assert not client.state.connected

            await _until(lambda: client.state.connected)
            assert button.connections == 2
            button.event(0x02, 5, 2)
            await asyncio.sleep(0.05)
            assert events == [(EVENT_TYPE_CLICK, False)]
            await client.stop()

    asyncio.run(scenario())


def test_reconnect_is_not_attempted_on_every_advertisement() -> None:
    """Test that a failing connect is not repeated at the pace of the advertisements."""

    async def scenario() -> None:
        attempts = 0

        async def establish_connection(*_args: Any, **_kwargs: Any) -> None:
            nonlocal attempts
            attempts += 1
            msg = "no connection"
            raise BleakError(msg)

        with (
            patch("pyflic_ble.client.establish_connection", establish_connection),
            patch("pyflic_ble.client.close_stale_connections_by_address", AsyncMock()),
        ):
            client = _client()
            for _ in range(25):
                client.set_ble_device(_device())
                await asyncio.sleep(0.05)

            # One attempt at once, the next one after about a second
            assert 1 <= attempts <= 2
            await client.stop()

    asyncio.run(scenario())


def test_advertisement_of_a_connected_button_probes_the_link() -> None:
    """Test that a link which still answers is kept, and probed only now and then."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            await client.start()
            assert button.reads == 1  # the hello of the verify

            client.set_ble_device(_device())
            client.set_ble_device(_device())
            await asyncio.sleep(0.05)

            assert button.reads == 2
            assert client.is_connected
            assert client.state.connected
            await client.stop()

    asyncio.run(scenario())


def test_advertisement_of_a_connected_button_rebuilds_a_dead_link() -> None:
    """Test that a Flic 1 which advertises although the link seems up is reconnected.

    A Flic 1 does not advertise while it is connected, so the link is probably gone,
    for example because the Bluetooth proxy hung without reporting it.
    """

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            disconnects: list[bool] = []

            def on_disconnect() -> None:
                disconnects.append(True)
                button.frozen = False

            client.on_disconnect = on_disconnect
            await client.start()

            button.frozen = True
            with patch("pyflic_ble.handlers.flic1.FLIC1_PROBE_TIMEOUT", 0.05):
                client.set_ble_device(_device())
                await _until(lambda: bool(disconnects))
            assert not client.state.connected

            await _until(lambda: client.state.connected)
            assert button.connections == 2
            await client.stop()

    asyncio.run(scenario())


def test_battery_from_the_advertisement() -> None:
    """Test the live battery value of the manufacturer data."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            await client.start()
            with pytest.raises(ValueError, match="No battery value"):
                await client.get_battery_level()

            client.set_ble_device(
                _device(), {FLIC1_MANUFACTURER_ID: ADVERTISED_BATTERY}
            )

            assert await client.get_battery_level() == 1577
            assert await client.get_battery_voltage() == pytest.approx(
                1577 * 3.6 / 2048
            )
            await client.stop()

    asyncio.run(scenario())


def test_battery_log_is_read_in_the_background() -> None:
    """Test that the voltage of the state comes from the battery log."""

    async def scenario() -> None:
        button = FakeButton()
        button.log = bytes([0] * 5 + [100] * 12 + [158] * 8)
        with _link(button), patch("pyflic_ble.client.FLIC1_BATTERY_LOG_DELAY", 0.01):
            client = _client()
            await client.start()
            assert client.state.battery_voltage is None

            await _until(lambda: client.state.battery_voltage is not None)

            assert client.state.battery_voltage == pytest.approx(1574 * 3.6 / 2048)
            assert _opcodes(button)[3:] == [0x18, 0x19]
            assert button.auth[4][1] == (0).to_bytes(4, "little")
            await client.stop()

    asyncio.run(scenario())


def test_stale_responses_do_not_disturb_the_battery_log() -> None:
    """Test that frames left by an earlier request that timed out are discarded."""

    async def scenario() -> None:
        button = FakeButton()
        button.log = bytes([0] * 5 + [100] * 12 + [158] * 8)
        with _link(button), patch("pyflic_ble.client.FLIC1_BATTERY_LOG_DELAY", 0.2):
            client = _client()
            await client.start()
            # The header and a data frame of a request whose answer came too late
            header = (
                b"\x05"
                + (3).to_bytes(2, "little")
                + bytes(4)
                + (3).to_bytes(4, "little")
            )
            data = b"\x06" + bytes([9, 9, 9])
            client._response_queue.put_nowait(header.ljust(20, b"\x00"))  # noqa: SLF001
            client._response_queue.put_nowait(data.ljust(20, b"\x00"))  # noqa: SLF001

            await _until(lambda: client.state.battery_voltage is not None)

            assert client.state.battery_voltage == pytest.approx(1574 * 3.6 / 2048)
            await client.stop()

    asyncio.run(scenario())


def test_battery_log_of_several_blocks() -> None:
    """Test that the oldest entries the button cannot send are skipped."""

    async def scenario() -> None:
        button = FakeButton()
        # 300 entries, of which the button can send the newest 290 in two blocks
        button.log = bytes([50] * 10 + [158] * 290)
        button.log_available = 290
        with _link(button):
            client = _client()
            await client.start()

            assert await client.handler.read_battery_log() == 1574
            requests = [
                int.from_bytes(payload[:4], "little")
                for opcode, payload, _ in button.auth
                if opcode == 0x19
            ]
            assert requests == [10, 10 + 285]
            await client.stop()

    asyncio.run(scenario())


def test_battery_log_without_entries_or_answer() -> None:
    """Test an empty log and a button that does not answer."""

    async def scenario() -> None:
        button = FakeButton()
        with _link(button):
            client = _client()
            await client.start()

            assert await client.handler.read_battery_log() is None

            button.silent = True
            with (
                patch("pyflic_ble.handlers.flic1.FLIC1_BATTERY_LOG_TIMEOUT", 0.05),
                pytest.raises(TimeoutError, match="battery log"),
            ):
                await client.handler.read_battery_log()
            await client.stop()

    asyncio.run(scenario())


def _cloud(
    calls: list[tuple[str, bytes, bytes]],
    mac_address: str = ADDRESS.lower(),
    h2: bytes = b"\x22" * 8,
) -> Callable[[str, bytes, bytes], Any]:
    """Return a fake Flic cloud that records the requests."""

    async def cloud_unlock(
        button_uuid: str, random_bytes: bytes, button_nonce: bytes
    ) -> str:
        calls.append((button_uuid, random_bytes, button_nonce))
        return json.dumps(
            {
                "mac_address": mac_address,
                "h1": H1.hex() + "00" * 8,
                "h2": h2.hex(),
                "h3": H3.hex(),
                "r3": str(CLOUD_RANDOM),
                "factory_serial": SERIAL_NUMBER,
            }
        )

    return cloud_unlock


def _pairing_client(
    cloud_unlock: Callable[[str, bytes, bytes], Any] | None,
) -> FlicClient:
    """Return the client of a button that is not paired yet."""
    return FlicClient(
        ADDRESS,
        _device(),
        device_type=DeviceType.FLIC1,
        cloud_unlock=cloud_unlock,
    )


def test_full_verify_pairs_the_button() -> None:
    """Test a pairing with the help of the cloud, and the events after it."""

    async def scenario() -> None:
        button = FakeButton(flag=0x42)
        calls: list[tuple[str, bytes, bytes]] = []
        with _link(button):
            client = _pairing_client(_cloud(calls))
            events = _collect(client)
            await client.connect()

            result = await client.full_verify_pairing()

            assert result == (0, H1 + H3, SERIAL_NUMBER, 0, 0, BUTTON_UUID, 23)
            assert calls == [(BUTTON_UUID.hex(), button.random_bytes, button.nonce)]
            # Signed with the nonce of the pairing, from counter 0
            assert _opcodes(button) == [0x25, 0x06]

            button.event(0x02, 1, 1)
            await asyncio.sleep(0.05)
            assert events == [(EVENT_TYPE_CLICK, False)]
            await client.stop()

    asyncio.run(scenario())


def test_full_verify_warns_when_the_button_asks_for_a_bond(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that the flag for a Bluetooth bond is reported, not silently ignored."""

    async def scenario() -> None:
        button = FakeButton(flag=0x43)
        with _link(button):
            client = _pairing_client(_cloud([]))
            await client.connect()

            result = await client.full_verify_pairing()

            assert result[1] == H1 + H3
            await client.stop()

    with caplog.at_level(logging.WARNING, logger="pyflic_ble"):
        asyncio.run(scenario())
    assert "Bluetooth bond" in caplog.text


def test_firmware_update_and_name_are_not_supported() -> None:
    """Test that the operations a Flic 1 does not have say so."""
    handler = create_handler(DeviceType.FLIC1, address=ADDRESS)

    for call in (
        handler.start_firmware_update(b""),
        handler.send_firmware_data(b"", 0),
        handler.send_force_disconnect(),
        handler.get_name(),
        handler.set_name("Flic"),
    ):
        with pytest.raises(NotImplementedError):
            asyncio.run(call)


def test_full_verify_refuses_a_button_that_is_not_in_pairing_mode() -> None:
    """Test that a button which only talks to its owner is reported."""

    async def scenario() -> None:
        button = FakeButton(flag=0x40)
        calls: list[tuple[str, bytes, bytes]] = []
        with _link(button):
            client = _pairing_client(_cloud(calls))
            await client.connect()

            with pytest.raises(FlicPairingError, match="pairing mode"):
                await client.full_verify_pairing()
            assert calls == []
            await client.stop()

    asyncio.run(scenario())


def test_full_verify_needs_the_cloud_callback() -> None:
    """Test that pairing without a way to call the cloud fails clearly."""

    async def scenario() -> None:
        button = FakeButton(flag=0x42)
        with _link(button):
            client = _pairing_client(None)
            await client.connect()

            with pytest.raises(FlicPairingError, match="cloud_unlock"):
                await client.full_verify_pairing()
            await client.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("cloud_kwargs", "message"),
    [
        ({"mac_address": "80:e4:da:00:00:01"}, "another Bluetooth address"),
        ({"h2": b"\x33" * 8}, "proof"),
    ],
)
def test_full_verify_checks_the_answer_of_the_cloud(
    cloud_kwargs: dict[str, Any], message: str
) -> None:
    """Test that the cloud has to answer for this button and prove it knows it."""

    async def scenario() -> None:
        button = FakeButton(flag=0x42)
        with _link(button):
            client = _pairing_client(_cloud([], **cloud_kwargs))
            await client.connect()

            with pytest.raises(FlicPairingError, match=message):
                await client.full_verify_pairing()
            assert _opcodes(button) == []
            await client.stop()

    asyncio.run(scenario())


def test_full_verify_times_out_when_the_button_is_silent() -> None:
    """Test that a button which does not answer fails the pairing."""

    async def scenario() -> None:
        button = FakeButton(flag=0x42)
        button.silent = True
        with _link(button):
            client = _pairing_client(_cloud([]))
            await client.connect()

            with (
                patch("pyflic_ble.handlers.flic1.PAIRING_TIMEOUT", 0.05),
                pytest.raises(FlicPairingError, match="timeout"),
            ):
                await client.full_verify_pairing()
            await client.stop()

    asyncio.run(scenario())
