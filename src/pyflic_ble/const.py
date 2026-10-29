"""Constants for the pyflic-ble library."""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class DeviceType(StrEnum):
    """Flic device types."""

    FLIC1 = "flic1"
    FLIC2 = "flic2"
    DUO = "duo"
    TWIST = "twist"

    @classmethod
    def from_serial_number(cls, serial: str) -> DeviceType:
        """Detect device type from serial number prefix.

        Flic 1 serials have no reliable prefix: a Flic 1 is recognised by its BLE
        service UUID (FLIC1_SERVICE_UUID) and has to be passed as device_type.
        """
        if serial.startswith("T"):
            return cls.TWIST
        if serial.startswith("D"):
            return cls.DUO
        return cls.FLIC2


class PushTwistMode(StrEnum):
    """Push twist mode options."""

    DEFAULT = "default"
    CONTINUOUS = "continuous"
    SELECTOR = "selector"


# Flic 2/Duo BLE Service and Characteristics
FLIC_SERVICE_UUID: Final = "00420000-8f59-4420-870d-84f3b617e493"
FLIC_WRITE_CHAR_UUID: Final = "00420001-8f59-4420-870d-84f3b617e493"
FLIC_NOTIFY_CHAR_UUID: Final = "00420002-8f59-4420-870d-84f3b617e493"

# Flic Twist BLE Service and Characteristics
TWIST_SERVICE_UUID: Final = "00c90000-2cbd-4f2a-a725-5ccd960ffb7d"
TWIST_TX_CHAR_UUID: Final = "00c90001-2cbd-4f2a-a725-5ccd960ffb7d"
TWIST_RX_CHAR_UUID: Final = "00c90002-2cbd-4f2a-a725-5ccd960ffb7d"

# Flic 1 (first generation) BLE service and characteristics
FLIC1_SERVICE_UUID: Final = "f02adfc0-26e7-11e4-9edc-0002a5d5c51b"
FLIC1_CONFIG_CHAR_UUID: Final = "cc7efce0-26e8-11e4-8fd2-0002a5d5c51b"  # hello (read), verify and config (write, notify)
FLIC1_EVENT_CHAR_UUID: Final = (
    "06053ec0-26e9-11e4-adc2-0002a5d5c51b"  # button events (notify)
)
GAP_DEVICE_NAME_CHAR_UUID: Final = "00002a00-0000-1000-8000-00805f9b34fb"

# Ed25519 public keys for signature verification
FLIC2_ED25519_PUBLIC_KEY: Final = bytes.fromhex(
    "d33f2440dd54b31b2e1dcf40132efa41d8f8a7474168df4008f5a95fb3b0d022"
)
TWIST_ED25519_PUBLIC_KEY: Final = bytes.fromhex(
    "a8b7df10434f565069e4131f5b13f1d9056faf2b61cf929b05d02d630bdaf48b"
)

# Protocol constants
FLIC_MTU: Final = 140  # Maximum ATT MTU
FLIC_MAX_PACKET_SIZE: Final = 129  # Maximum packet size (140 - 11 ATT overhead)
FLIC_SIGNATURE_SIZE: Final = 5  # Chaskey-LTS MAC size for packets

# Frame header bitmasks (Flic 2/Duo framing)
FRAME_HEADER_CONN_ID_MASK: Final = 0x1F
FRAME_HEADER_NEWLY_ASSIGNED: Final = 0x20
FRAME_HEADER_FRAGMENT_FLAG: Final = 0x80

# Event types
EVENT_TYPE_UP: Final = "up"
EVENT_TYPE_DOWN: Final = "down"
EVENT_TYPE_CLICK: Final = "click"
EVENT_TYPE_DOUBLE_CLICK: Final = "double_click"
EVENT_TYPE_HOLD: Final = "hold"

# Gesture event types (Flic Duo only)
EVENT_TYPE_SWIPE_LEFT: Final = "swipe_left"
EVENT_TYPE_SWIPE_RIGHT: Final = "swipe_right"
EVENT_TYPE_SWIPE_UP: Final = "swipe_up"
EVENT_TYPE_SWIPE_DOWN: Final = "swipe_down"

# Rotate event types (Flic Duo and Twist)
EVENT_TYPE_ROTATE_CLOCKWISE: Final = "rotate_clockwise"
EVENT_TYPE_ROTATE_COUNTER_CLOCKWISE: Final = "rotate_counter_clockwise"

# Twist-specific event types
EVENT_TYPE_SELECTOR_CHANGED: Final = "selector_changed"

# Twist DEFAULT mode increment/decrement event types
EVENT_TYPE_TWIST_INCREMENT: Final = "twist_increment"
EVENT_TYPE_TWIST_DECREMENT: Final = "twist_decrement"
EVENT_TYPE_PUSH_TWIST_INCREMENT: Final = "push_twist_increment"
EVENT_TYPE_PUSH_TWIST_DECREMENT: Final = "push_twist_decrement"

# Twist slot position changed event types (one per slot, modes 0-11)
EVENT_TYPE_SLOT_CHANGED: Final = [f"slot_{i}_changed" for i in range(1, 13)]

# Duo dial position changed event type
EVENT_TYPE_DUO_DIAL_CHANGED: Final = "duo_dial_changed"

# Timeouts (seconds)
PAIRING_TIMEOUT: Final = 60
CONNECTION_TIMEOUT: Final = 30
COMMAND_TIMEOUT: Final = 10
LIVENESS_PROBE_INTERVAL: Final = 30  # at most one liveness probe per interval

# BLE connection parameters
CONN_PARAM_LATENCY: Final = 17
CONN_PARAM_INTERVAL_MIN: Final = 80
CONN_PARAM_INTERVAL_MAX: Final = 90
CONN_PARAM_TIMEOUT: Final = 800

# Protocol opcodes - from official Flic 2 SDK
# Request opcodes (OpcodeToFlic)
OPCODE_FULL_VERIFY_REQUEST_1: Final = 0
OPCODE_FULL_VERIFY_REQUEST_2: Final = 2
OPCODE_QUICK_VERIFY_REQUEST: Final = 5
OPCODE_GET_FIRMWARE_VERSION_REQUEST: Final = 8
OPCODE_GET_BATTERY_LEVEL_REQUEST: Final = 20
OPCODE_INIT_BUTTON_EVENTS_REQUEST: Final = 23

# Response opcodes (OpcodeFromFlic)
OPCODE_FULL_VERIFY_RESPONSE_1: Final = 0
OPCODE_FULL_VERIFY_RESPONSE_2: Final = 1
OPCODE_GET_FIRMWARE_VERSION_RESPONSE: Final = 5
OPCODE_QUICK_VERIFY_RESPONSE: Final = 8
OPCODE_BUTTON_EVENT: Final = 12
OPCODE_GET_BATTERY_LEVEL_RESPONSE: Final = 20

# Button event types for Flic 2
FLIC2_EVENT_UP: Final = 0
FLIC2_EVENT_DOWN: Final = 1
FLIC2_EVENT_SINGLE_CLICK_TIMEOUT: Final = 2
FLIC2_EVENT_HOLD: Final = 3
FLIC2_EVENT_UP_CLICK_PENDING: Final = 8
FLIC2_EVENT_UP_SINGLE_CLICK: Final = 10
FLIC2_EVENT_UP_DOUBLE_CLICK: Final = 11
FLIC2_EVENT_UP_AFTER_HOLD: Final = 14

# Indication opcodes (fire-and-forget, no response expected)
OPCODE_SET_CONNECTION_PARAMETERS_IND: Final = 12

# Response opcodes for button event initialization
OPCODE_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID: Final = 10
OPCODE_INIT_BUTTON_EVENTS_RESPONSE_WITHOUT_BOOT_ID: Final = 11

# Flic Duo specific opcodes
OPCODE_INIT_BUTTON_EVENTS_DUO_REQUEST: Final = 35
OPCODE_BUTTON_EVENT_DUO: Final = 32
OPCODE_ENABLE_PUSH_TWIST_IND: Final = 37
OPCODE_PUSH_TWIST_DATA_NOTIFICATION: Final = 33

# Response opcodes for Duo button event initialization
OPCODE_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITH_BOOT_ID: Final = 30
OPCODE_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID: Final = 31

# Flic Twist specific opcodes
TWIST_OPCODE_FULL_VERIFY_REQUEST_1: Final = 0x00
TWIST_OPCODE_FULL_VERIFY_REQUEST_2: Final = 0x02
TWIST_OPCODE_QUICK_VERIFY_REQUEST: Final = 0x05
TWIST_OPCODE_INIT_BUTTON_EVENTS: Final = 0x0C
TWIST_OPCODE_ACK_BUTTON_EVENTS: Final = 0x0D
TWIST_OPCODE_UPDATE_TWIST_POS: Final = 0x0E
TWIST_OPCODE_GET_FIRMWARE_VERSION_REQUEST: Final = 0x07
TWIST_OPCODE_GET_BATTERY_LEVEL_REQUEST: Final = 0x11

# Twist opcodes (Device -> Host)
TWIST_OPCODE_FULL_VERIFY_RESPONSE_1: Final = 0x00
TWIST_OPCODE_FULL_VERIFY_RESPONSE_2: Final = 0x01
TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE: Final = 0x02
TWIST_OPCODE_GET_FIRMWARE_VERSION_RESPONSE: Final = 0x04
TWIST_OPCODE_QUICK_VERIFY_NEGATIVE: Final = 0x05
TWIST_OPCODE_QUICK_VERIFY_RESPONSE: Final = 0x06
TWIST_OPCODE_DISCONNECTED_VERIFIED_LINK: Final = 0x07
TWIST_OPCODE_INIT_BUTTON_EVENTS_RESPONSE: Final = 0x08
TWIST_OPCODE_BUTTON_EVENT: Final = 0x09
TWIST_OPCODE_TWIST_EVENT: Final = 0x0A
TWIST_OPCODE_GET_BATTERY_LEVEL_RESPONSE: Final = 0x10

# Twist disconnect reasons
TWIST_DISCONNECT_REASON_INVALID_SIGNATURE: Final = 0
TWIST_DISCONNECT_REASON_OTHER_CLIENT: Final = 1

# Twist mode indices
TWIST_MODE_SLOT_FIRST: Final = 0
TWIST_MODE_SLOT_LAST: Final = 11
TWIST_MODE_SLOT_CHANGING: Final = 12

# Firmware update constants
# Twist firmware update opcodes (Host -> Device)
TWIST_OPCODE_FORCE_BT_DISCONNECT_IND: Final = 0x06
TWIST_OPCODE_START_FIRMWARE_UPDATE_REQUEST: Final = 0x0F
TWIST_OPCODE_FIRMWARE_UPDATE_DATA_IND: Final = 0x10

# Twist firmware update opcodes (Device -> Host)
TWIST_OPCODE_START_FIRMWARE_UPDATE_RESPONSE: Final = 0x0E
TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION: Final = 0x0F

# Flic 2 firmware update opcodes (Host -> Device)
OPCODE_FORCE_BT_DISCONNECT_IND: Final = 6
OPCODE_START_FIRMWARE_UPDATE_REQUEST: Final = 17
OPCODE_FIRMWARE_UPDATE_DATA_IND: Final = 18

# Flic 2 firmware update opcodes (Device -> Host)
OPCODE_START_FIRMWARE_UPDATE_RESPONSE: Final = 18
OPCODE_FIRMWARE_UPDATE_NOTIFICATION: Final = 19

# Flic Duo firmware update opcodes (Host -> Device)
OPCODE_START_FIRMWARE_UPDATE_DUO_REQUEST: Final = 38
OPCODE_FIRMWARE_UPDATE_DATA_DUO_IND: Final = 39

# Firmware binary header
FIRMWARE_HEADER_SIZE: Final = 76

# Twist transfer constants
FIRMWARE_DATA_CHUNK_SIZE: Final = 120
FIRMWARE_MAX_IN_FLIGHT: Final = 480
FIRMWARE_STATUS_INTERVAL: Final = 2
FIRMWARE_UPDATE_TIMEOUT: Final = 300
FIRMWARE_FINAL_ACK_TIMEOUT: Final = 30

# Flic 2 transfer constants
FLIC2_FIRMWARE_WORD_CHUNK_SIZE: Final = 30
FLIC2_FIRMWARE_MAX_IN_FLIGHT_WORDS: Final = 512
FLIC2_FIRMWARE_STATUS_INTERVAL: Final = 60
FLIC2_FIRMWARE_IV_SIZE: Final = 8

# Duo transfer constants
DUO_FIRMWARE_DATA_CHUNK_SIZE: Final = 110
DUO_FIRMWARE_MAX_IN_FLIGHT: Final = 550
DUO_FIRMWARE_STATUS_INTERVAL: Final = 2

# Name management opcodes - Flic 2/Duo (Host -> Device)
OPCODE_SET_NAME_REQUEST: Final = 10
OPCODE_GET_NAME_REQUEST: Final = 11

# Name management opcodes - Flic 2/Duo (Device -> Host)
OPCODE_GET_NAME_RESPONSE: Final = 16
OPCODE_SET_NAME_RESPONSE: Final = 17

# Name management opcodes - Twist (Host -> Device)
TWIST_OPCODE_SET_NAME_REQUEST: Final = 0x09
TWIST_OPCODE_GET_NAME_REQUEST: Final = 0x0A

# Name management opcodes - Twist (Device -> Host)
TWIST_OPCODE_GET_NAME_RESPONSE: Final = 0x0C
TWIST_OPCODE_SET_NAME_RESPONSE: Final = 0x0D

# Name constraints
DEVICE_NAME_MAX_BYTES: Final = 23

# Flic 1 message sizes
FLIC1_HELLO_SIZE: Final = 20
FLIC1_EVENT_SIZE: Final = 15
FLIC1_READY_FRAME_BYTE: Final = 0x40

# Flic 1 opcodes (Host -> Device, written to the configuration characteristic)
FLIC1_OPCODE_CONFIG_REQUEST: Final = 0x06
FLIC1_OPCODE_FULL_VERIFY_REQUEST: Final = 0x07
FLIC1_OPCODE_QUICK_VERIFY_REQUEST: Final = 0x09
FLIC1_OPCODE_BATTERY_LOG_REQUEST: Final = 0x18
FLIC1_OPCODE_BATTERY_LOG_FROM_REQUEST: Final = 0x19
FLIC1_OPCODE_ACK_EVENTS: Final = 0x25

# Flic 1 opcodes (Device -> Host, notified on the configuration characteristic)
FLIC1_OPCODE_FULL_VERIFY_RESPONSE_1: Final = 0
FLIC1_OPCODE_FULL_VERIFY_RESPONSE_2: Final = 1
FLIC1_OPCODE_FULL_VERIFY_RESPONSE_3: Final = 2
FLIC1_OPCODE_BATTERY_LOG_HEADER: Final = 5
FLIC1_OPCODE_BATTERY_LOG_DATA: Final = 6

# Flic 1 full verify steps (second byte of FLIC1_OPCODE_FULL_VERIFY_REQUEST)
FLIC1_FULL_VERIFY_STEP_1: Final = 0
FLIC1_FULL_VERIFY_STEP_2: Final = 1

# Flic 1 hello flags (first byte of the hello); 0x40 is a paired button that only accepts
# a quick verify
FLIC1_HELLO_FLAG_QUICK_VERIFY_OR_PAIRING: Final = 0x41
FLIC1_HELLO_FLAG_PAIRING: Final = 0x42
FLIC1_HELLO_FLAG_PAIRING_WITH_BOND: Final = 0x43

# Flic 1 event frames that carry connection parameters instead of a press
FLIC1_EVENT_STATUS_BYTES: Final = frozenset({0x20, 0x60, 0x68, 0x70})

# Flic 1 auto disconnect: seconds after the last press, 511 = stay connected
FLIC1_AUTO_DISCONNECT_NEVER: Final = 511

# Flic 1 connection parameters: flicd's "normal" interval and latency (the same idle wake-up
# every ~2 s) with a 20 s instead of a 5 s link timeout, which a weak proxy link needs.
FLIC1_CONN_PARAM_INTERVAL_MIN: Final = 70
FLIC1_CONN_PARAM_INTERVAL_MAX: Final = 80
FLIC1_CONN_PARAM_LATENCY: Final = 19
FLIC1_CONN_PARAM_TIMEOUT: Final = 2000

# Flic 1 buttons from the first production batch need acknowledged writes
FLIC1_WRITE_REQUEST_ADDRESS_FIRST: Final = 0x80E4DA700000
FLIC1_WRITE_REQUEST_ADDRESS_LAST: Final = 0x80E4DA707254

# Presses that waited longer than this (seconds) for a link are not reported
FLIC1_STALE_EVENT_AGE: Final = 5.0

# Flic 1 battery
FLIC1_MANUFACTURER_ID: Final = 0x030F  # advertisement manufacturer data, firmware >= 12
FLIC1_BATTERY_LOG_CHUNK_SIZE: Final = 19  # entries in one data frame
FLIC1_BATTERY_LOG_BLOCK_SIZE: Final = 285  # entries the button sends per request
FLIC1_BATTERY_LOG_AVERAGED_ENTRIES: Final = 8
FLIC1_BATTERY_ENTRY_OFFSET: Final = 1100  # raw value = offset + scale * entry
FLIC1_BATTERY_ENTRY_SCALE: Final = 3
FLIC1_BATTERY_RAW_TO_VOLTS: Final = 3.6 / 2048
FLIC1_BATTERY_LOG_TIMEOUT: Final = 20
FLIC1_BATTERY_LOG_DELAY: Final = 30  # seconds after connecting, queued presses go first
FLIC1_BATTERY_LOG_INTERVAL: Final = 3 * 3600
FLIC1_PROBE_TIMEOUT: Final = 8
