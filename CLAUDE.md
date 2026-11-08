# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pyflic-ble is a Python library for communicating with Flic smart buttons (Flic 1, Flic 2, Flic Duo, Flic Twist) over BLE. It handles pairing, authentication, button/rotation events, firmware updates, and name management. Primary consumer is the Home Assistant Flic integration.

## Build & Development

```bash
pip install -e .                    # Install in editable mode
python -m pytest tests/             # Run all tests
python -m pytest tests/test_rotate_tracker.py::test_multi_mode_tracker_mode_12_bounded  # Run single test
```

Dependencies: `bleak` (BLE), `bleak-retry-connector`, `cryptography` (Ed25519/X25519). Python >=3.12.

## Architecture

### Device Type Strategy Pattern

Four device types (`DeviceType` enum in `const.py`: FLIC1, FLIC2, DUO, TWIST) each have a protocol handler in `src/pyflic_ble/handlers/`. All extend `DeviceProtocolHandler` (ABC in `handlers/base.py`). Factory function `create_handler()` in `handlers/__init__.py` instantiates the correct handler by device type.

- **Flic 1** (`flic1.py`): Single button, first generation. Owns its transport (`DeviceCapabilities.raw_transport`): two GATT characteristics, SHA-256 MACs, no frame headers. The client routes its notifications to `handle_raw_notification()`. Pairing calls the Flic cloud through the application's `cloud_unlock` callback. Constants use the `FLIC1_*` prefix, messages the `Flic1*` prefix.
- **Flic 2** (`flic2.py`): Single button, no rotation. Uses Flic 2/Duo framing with frame headers.
- **Duo** (`duo.py`): Two buttons, rotation dial, swipe gestures. Shares Flic 2 BLE service UUIDs and framing.
- **Twist** (`twist.py`): Single button, rotation with 12 selector modes. Uses its own BLE service UUIDs and a completely different protocol (no frame headers, different opcodes prefixed `TWIST_OPCODE_*`).

### FlicClient (`client.py`)

Central class that orchestrates BLE connections via bleak. Manages session state machine (`SessionState` enum), pairing (full verify) and reconnection (quick verify), packet framing/signing, and delegates device-specific logic to the handler. Exposes callbacks: `on_button_event`, `on_rotate_event`, `on_firmware_progress`, `on_disconnect`. Optional `DeviceProtocolHandler` hooks (connection parameters, liveness probe, battery log, advertisement data) have no-op defaults, so only the handlers that need them override them.

### Protocol & Security

- `protocol.py`: Message dataclasses with `to_bytes()`/`from_bytes()` serialization for all request/response types (Flic 1, Flic 2/Duo and Twist variants).
- `security.py`: Chaskey-LTS MAC (packet signing), Ed25519 signature verification (4-variant twist), X25519 ECDH key exchange, HMAC-SHA256 key derivation, and the SHA-256 MACs of Flic 1.
- `const.py`: All BLE UUIDs, opcodes, event types, and protocol constants. Flic 2/Duo opcodes are plain integers; Twist opcodes use `TWIST_OPCODE_*` prefix with hex values.

### Rotation Tracking (`rotate_tracker.py`)

- `RotateTracker`: Single-mode tracker with velocity/acceleration, backlash suppression, configurable full-range units and clamping.
- `MultiModeRotateTracker`: Wraps 13 `RotateTracker` instances for Twist's 12 selector modes + 1 free rotation mode (index 12). Implements SDK-compatible min-boundary tracking for bounded position (0-100%).

## Key Conventions

- All protocol constants use `typing.Final` in `const.py`.
- Twist protocol is structurally different from Flic 2/Duo: separate BLE UUIDs, no frame header byte, different opcode numbering. Always check which protocol path you're in.
- Device type is detected from serial number prefix: `T`=Twist, `D`=Duo, else Flic 2 (`DeviceType.from_serial_number()`). Flic 1 cannot be detected; pass `device_type=DeviceType.FLIC1`.
- Event type strings (e.g., `"click"`, `"rotate_clockwise"`) are defined as constants in `const.py` and used throughout handlers and callbacks.
- Tests are plain pytest functions; async code runs through `asyncio.run()` (CI installs only `pytest`). `tests/test_flic1_client.py` plays a Flic 1 with a `FakeButton` that checks every packet MAC independently of the library.
