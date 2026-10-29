"""Test the Flic 1 messages and message authentication."""

import json

import pytest

from pyflic_ble.const import (
    EVENT_TYPE_CLICK,
    EVENT_TYPE_DOUBLE_CLICK,
    EVENT_TYPE_DOWN,
    EVENT_TYPE_HOLD,
    EVENT_TYPE_UP,
)
from pyflic_ble.handlers.flic1 import Flic1ProtocolHandler, _Flic1Credentials
from pyflic_ble.protocol import (
    Flic1AckEventsRequest,
    Flic1AdvertisedData,
    Flic1BatteryLogFromRequest,
    Flic1BatteryLogHeader,
    Flic1ConfigRequest,
    Flic1EventNotification,
    Flic1FullVerifyRequest1,
    Flic1FullVerifyRequest2,
    Flic1FullVerifyResponse1,
    Flic1FullVerifyResponse2,
    Flic1Hello,
    Flic1QuickVerifyRequest,
    Flic1UnlockRequest,
    Flic1UnlockResponse,
)
from pyflic_ble.security import (
    flic1_event_mac_valid,
    flic1_hello_mac_valid,
    flic1_packet_mac,
    flic1_ready_hash,
    flic1_sha256,
)

H1 = bytes(range(1, 9))
H3 = bytes(range(0xA0, 0xAC))


def _frame(event_byte: int, counter: int = 1, boot_id: int = 1, age: int = 0) -> bytes:
    """Build a signed 15 byte event frame."""
    body = (
        bytes([event_byte])
        + counter.to_bytes(3, "little")
        + boot_id.to_bytes(3, "little")
        + age.to_bytes(4, "little")
    )
    return body + flic1_sha256(body, H3)[:4]


def test_hello_parsing_and_both_mac_forms() -> None:
    """Test that a hello is parsed and checked in the new and the old MAC form."""
    body = bytes([0x40]) + bytes(range(8))
    new_form = body + bytes(8) + flic1_sha256(body + bytes(8), H3)[:3]
    old_form = body + bytes(5) + flic1_sha256(body + bytes(5), H3)[:3] + bytes(3)

    hello = Flic1Hello.from_bytes(new_form)
    assert hello.flag == 0x40
    assert hello.nonce == bytes(range(8))
    assert flic1_hello_mac_valid(new_form, H3)
    assert flic1_hello_mac_valid(old_form, H3)
    assert not flic1_hello_mac_valid(new_form, bytes(12))
    assert not flic1_hello_mac_valid(new_form[:19], H3)
    with pytest.raises(ValueError, match="20 bytes"):
        Flic1Hello.from_bytes(new_form[:19])


def test_requests_serialize_like_the_official_clients() -> None:
    """Test the byte layout of the requests."""
    assert Flic1FullVerifyRequest1(bytes(range(8))).to_bytes() == b"\x07\x00" + bytes(
        range(8)
    )
    assert Flic1FullVerifyRequest2(2**64 + 5, H1).to_bytes() == (
        b"\x07\x01" + (5).to_bytes(8, "little") + H1
    )
    assert Flic1QuickVerifyRequest(H1, bytes(6)).to_bytes() == b"\x09" + H1 + bytes(6)
    # six bytes of connection parameters stay zero, then the auto disconnect time
    assert Flic1ConfigRequest(511).to_bytes() == b"\x06" + bytes(6) + b"\xff\x01"
    assert Flic1ConfigRequest(10).to_bytes() == b"\x06" + bytes(6) + b"\x0a\x00"
    assert Flic1AckEventsRequest(6, 2, 0x101).to_bytes() == (
        b"\x25" + (6).to_bytes(4, "little") + (2).to_bytes(4, "little") + b"\x01"
    )
    assert Flic1BatteryLogFromRequest(6986).to_bytes() == b"\x19" + (6986).to_bytes(
        4, "little"
    )


def test_packet_mac_binds_counter_nonce_and_key() -> None:
    """Test that the packet MAC changes with every input."""
    body = b"\x09" + H1
    nonce = bytes(range(8))
    mac = flic1_packet_mac(body, 0, nonce, H3)
    assert len(mac) == 4
    assert mac != flic1_packet_mac(body, 1, nonce, H3)
    assert mac != flic1_packet_mac(body, 0, bytes(8), H3)
    assert mac != flic1_packet_mac(body, 0, nonce, bytes(12))


def test_ready_hash_and_event_mac() -> None:
    """Test the proof of a quick verify and the MAC of an event."""
    assert len(flic1_ready_hash(bytes(8), bytes(6), H3)) == 14
    frame = _frame(0x01)
    assert flic1_event_mac_valid(frame, H3)
    assert not flic1_event_mac_valid(frame[:-1] + b"\x00", H3)
    assert not flic1_event_mac_valid(frame[:14], H3)


def test_full_verify_responses() -> None:
    """Test the replies of the pairing exchange."""
    response1 = Flic1FullVerifyResponse1.from_bytes(
        b"\x00" + bytes(range(8)) + bytes(range(8, 16)) + bytes(3)
    )
    assert response1.nonce == bytes(range(8))
    assert response1.h2 == bytes(range(8, 16))
    response2 = Flic1FullVerifyResponse2.from_bytes(
        b"\x01" + bytes(range(16)) + bytes(3)
    )
    assert response2.button_uuid == bytes(range(16))
    with pytest.raises(ValueError, match="response 1"):
        Flic1FullVerifyResponse1.from_bytes(b"\x01" + bytes(19))
    with pytest.raises(ValueError, match="response 2"):
        Flic1FullVerifyResponse2.from_bytes(b"\x00" + bytes(19))


def test_unlock_request_and_response() -> None:
    """Test the JSON exchanged with the Flic cloud."""
    request = Flic1UnlockRequest("id", "secret", bytes(range(8)), b"\xff" * 8)
    body = json.loads(request.to_json())
    assert body["appId"] == "id"
    assert body["appSecret"] == "secret"
    assert body["r1"] == int.from_bytes(bytes(range(8)), "little", signed=True)
    assert body["r2"] == -1
    assert list(body) == [
        "appId",
        "appSecret",
        "r1",
        "r2",
        "platform",
        "version",
    ]

    # The cloud answers with longer secrets than the protocol uses
    reply = json.dumps(
        {
            "mac_address": "80:e4:da:12:34:56",
            "h1": "01" * 16,
            "h2": "02" * 16,
            "h3": "03" * 20,
            "r3": 7,
            "factory_serial": "AH25-D00214",
        }
    )
    response = Flic1UnlockResponse.from_json(reply)
    assert (response.h1, response.h2, response.h3) == (
        b"\x01" * 8,
        b"\x02" * 8,
        b"\x03" * 12,
    )
    assert response.cloud_random == 7
    assert response.serial_number == "AH25-D00214"
    for broken in ("not json", "{}", json.dumps({"mac_address": "x", "h1": "zz"})):
        with pytest.raises(ValueError, match="Invalid reply"):
            Flic1UnlockResponse.from_json(broken)


@pytest.mark.parametrize(
    ("event_byte", "event_types", "was_queued", "needs_ack"),
    [
        # seen on firmware 23
        (0x01, [EVENT_TYPE_DOWN], False, False),
        (0x08, [EVENT_TYPE_UP], False, False),
        (0x02, [EVENT_TYPE_CLICK], False, True),
        (0x0B, [EVENT_TYPE_UP, EVENT_TYPE_DOUBLE_CLICK], False, True),
        (0x03, [EVENT_TYPE_HOLD], False, False),
        (0x0E, [EVENT_TYPE_UP], False, True),
        (0x92, [EVENT_TYPE_CLICK], True, True),
        (0x9E, [EVENT_TYPE_UP], True, True),
        (0x1B, [EVENT_TYPE_UP, EVENT_TYPE_DOUBLE_CLICK], True, True),
        (0x07, [], False, False),
        (0x00, [EVENT_TYPE_UP], False, False),
    ],
)
def test_event_types(
    event_byte: int, event_types: list[str], was_queued: bool, needs_ack: bool
) -> None:
    """Test how an event byte maps to event types."""
    event = Flic1EventNotification.from_bytes(_frame(event_byte))
    assert event.event_types == event_types
    assert event.was_queued is was_queued
    assert event.needs_ack is needs_ack


def test_event_fields() -> None:
    """Test the counters and the age of an event."""
    event = Flic1EventNotification.from_bytes(_frame(0x11, 0xABCDEF, 0x123456, 1706))
    assert (event.counter, event.boot_id, event.age) == (0xABCDEF, 0x123456, 1706)
    with pytest.raises(ValueError, match="15 bytes"):
        Flic1EventNotification.from_bytes(bytes(14))


def test_replay_filter() -> None:
    """Test that every event is accepted once and old ones never."""
    credentials = _Flic1Credentials(H1, H3, counter=4, boot_id=2)

    def accept(event_byte: int, counter: int, boot_id: int = 2) -> bool:
        return credentials.accept(
            Flic1EventNotification.from_bytes(_frame(event_byte, counter, boot_id))
        )

    assert accept(0x01, 5)  # down
    assert accept(0x08, 5)  # up of the same counter
    assert not accept(0x01, 5)  # the same down again
    assert not accept(0x01, 3)  # older counter
    assert accept(0x0B, 6)  # new counter resets the mask
    assert credentials.counter == 6
    assert not accept(0x01, 100, boot_id=1)  # older boot
    assert accept(0x01, 1, boot_id=3)  # new boot
    assert (credentials.boot_id, credentials.counter) == (3, 1)


def test_credentials_round_trip_through_the_application_fields() -> None:
    """Test that pairing_id, pairing_key and sig_bits carry the whole state."""
    credentials = _Flic1Credentials(H1, H3, counter=0xABCDEF, boot_id=0x123456, mask=5)
    restored = _Flic1Credentials.from_pairing(
        credentials.pairing_id, credentials.pairing_key, credentials.mask
    )
    assert (restored.h1, restored.h3) == (H1, H3)
    assert (restored.counter, restored.boot_id, restored.mask) == (
        0xABCDEF,
        0x123456,
        5,
    )
    assert len(credentials.pairing_key) == 20
    with pytest.raises(ValueError, match="20 bytes"):
        _Flic1Credentials.from_pairing(0, bytes(16), 0)
    with pytest.raises(ValueError, match="h1 must be 8 bytes"):
        _Flic1Credentials(bytes(4), H3)


def test_battery_log_header() -> None:
    """Test the header of the battery log (read from a real button)."""
    header = Flic1BatteryLogHeader.from_bytes(
        bytes.fromhex("054a1f8a45ce0000040000000000000000000000")[:20]
    )
    assert (header.entries, header.available_entries) == (8010, 1024)


def test_battery_from_log_stops_at_the_battery_change_marker() -> None:
    """Test the battery value of real logs: old cell, 0 marker, new cell."""
    battery = Flic1ProtocolHandler._battery_from_log  # noqa: SLF001
    old_cell = bytes.fromhex("48474749")
    assert battery(old_cell + bytes([0, 0xC8, 0xD5])) == 1719  # mean of 1700, 1739
    assert battery(bytes([1, 1, 0, 0x98, 0xB2])) == 1595  # mean of 1556, 1634
    # the marker is the newest entry: the battery was changed, nothing sampled yet
    assert battery(old_cell + bytes([0])) is None
    assert battery(b"") is None
    # only the newest eight entries count
    assert battery(bytes([100] * 20 + [200] * 8)) == 1700


def test_advertised_data() -> None:
    """Test the manufacturer data of a real advertisement."""
    data = Flic1AdvertisedData.from_bytes(
        bytes.fromhex("0002ec052f2700002906020000dae480")
    )
    assert data.battery == 1577
    assert data.boot_battery == 1516
    with pytest.raises(ValueError, match="manufacturer data"):
        Flic1AdvertisedData.from_bytes(bytes(15))
