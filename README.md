# pyflic-ble

Python library for communicating with [Flic](https://flic.io/) smart buttons over Bluetooth Low Energy (BLE). Supports the full Flic 2 protocol including pairing, authentication, button events, rotation tracking, firmware updates, and device name management, as well as the first generation Flic 1 (pairing, button events, and battery).

## Supported Devices

| Device | Button(s) | Rotation | Gestures | Selector Modes |
|--------|-----------|----------|----------|----------------|
| **Flic 1** | 1 | — | — | — |
| **Flic 2** | 1 | — | — | — |
| **Flic Duo** | 2 | Dial (per-button) | Swipe (left/right/up/down) | — |
| **Flic Twist** | 1 | Full rotation | — | 12 slots + free mode |

## Installation

```bash
pip install pyflic-ble
```

Requires Python 3.12+.

### Dependencies

- [bleak](https://github.com/hbldh/bleak) — Cross-platform BLE communication (macOS, Linux, Windows)
- [bleak-retry-connector](https://github.com/bluetooth-devices/bleak-retry-connector) — Reliable BLE connections with retry logic
- [cryptography](https://cryptography.io/) — Ed25519 signature verification and X25519 key exchange

## Quick Start

```python
import asyncio
from bleak import BleakScanner
from pyflic_ble import FlicClient, DeviceType

async def main():
    # Discover a Flic button (they advertise a specific service UUID)
    device = await BleakScanner.find_device_by_filter(
        lambda d, ad: "00420000-8f59-4420-870d-84f3b617e493" in (ad.service_uuids or [])
        or "00c90000-2cbd-4f2a-a725-5ccd960ffb7d" in (ad.service_uuids or [])
    )

    if not device:
        print("No Flic button found")
        return

    # Create client
    client = FlicClient(
        address=device.address,
        ble_device=device,
    )

    # Set up event handler
    def on_button_event(event_type, event_data):
        print(f"Button event: {event_type} — {event_data}")

    client.on_button_event = on_button_event

    # Connect and pair
    await client.connect()
    pairing_id, pairing_key, serial, battery, sig_bits, uuid, fw = (
        await client.full_verify_pairing()
    )
    print(f"Paired with {serial} (battery: {battery}, firmware: {fw})")

    # Start receiving button events
    await client.init_button_events()

    # Keep running to receive events
    await asyncio.sleep(60)
    await client.disconnect()

asyncio.run(main())
```

## Usage

### Creating a Client

```python
from pyflic_ble import FlicClient, DeviceType, PushTwistMode

# New device (will pair)
client = FlicClient(
    address="AA:BB:CC:DD:EE:FF",
    ble_device=ble_device,
)

# Known device (will reconnect with stored credentials)
client = FlicClient(
    address="AA:BB:CC:DD:EE:FF",
    ble_device=ble_device,
    pairing_id=12345,
    pairing_key=b"\x00" * 16,
    serial_number="B123-A45678",
    device_type=DeviceType.FLIC2,
)

# Flic Twist with a specific rotation mode
client = FlicClient(
    address="AA:BB:CC:DD:EE:FF",
    ble_device=ble_device,
    device_type=DeviceType.TWIST,
    push_twist_mode=PushTwistMode.CONTINUOUS,
)

# Flic 1 (see Flic 1 below)
client = FlicClient(
    address="AA:BB:CC:DD:EE:FF",
    ble_device=ble_device,
    device_type=DeviceType.FLIC1,
    cloud_unlock=cloud_unlock,  # only needed for pairing
)
```

The device type is auto-detected from the serial number prefix (`T` = Twist, `D` = Duo, anything else = Flic 2), or can be specified explicitly. A Flic 1 has to be specified explicitly.

### Pairing (First Connection)

Pairing performs an ECDH key exchange authenticated with Ed25519 signatures. The button must be in pairing mode (hold for 7 seconds until LED flashes).

```python
await client.connect()

# Returns credentials to store for future reconnections
pairing_id, pairing_key, serial, battery, sig_bits, button_uuid, firmware_version = (
    await client.full_verify_pairing()
)

await client.init_button_events()
```

### Flic 1

Flic 1 predates the other devices and uses a different protocol: two GATT characteristics instead of framed packets, and SHA-256 MACs instead of Chaskey and Ed25519. Pass `device_type=DeviceType.FLIC1`.

**Pairing needs the Flic cloud once.** The cloud holds the secret that unlocks a button. The library does not make the HTTP call (the application owns the app credentials and the HTTP client); provide it as a `cloud_unlock` coroutine that posts the request body to the unlock endpoint and returns the reply text:

```python
from pyflic_ble import Flic1UnlockRequest

async def cloud_unlock(button_uuid: str, random_bytes: bytes, button_nonce: bytes) -> str:
    body = Flic1UnlockRequest(APP_ID, APP_SECRET, random_bytes, button_nonce).to_json()
    async with session.post(
        f"https://api.flic.io/api/v1/buttons/{button_uuid}/unlock",
        data=body,
        headers={"Content-Type": "application/json"},
    ) as response:
        response.raise_for_status()
        return await response.text()
```

The button has to be in pairing mode (hold it for 7 seconds). `full_verify_pairing()` then returns the usual tuple; `pairing_key` is the 20 byte secret. Later sessions (`start()`, `quick_verify()`) do not need the internet.

- **Credentials change during a session.** `pairing_id` and `sig_bits` hold the event counter, the boot id, and the events already received. They advance with every event, so store the values from `register_credentials_callback()`; otherwise a restart may report events again.
- **Queued presses.** A button that has no link queues presses and reports them after the next connection with `was_queued` set. Presses older than `stale_event_age` seconds (5 by default) are acknowledged but not reported; pass `stale_event_age=None` to report all of them.
- **Battery.** A Flic 1 has no battery request. Pass the manufacturer data of its advertisements to `set_ble_device(ble_device, manufacturer_data)` for the live value; otherwise the client reads the battery log in the background after connecting and every 3 hours. `get_battery_level()` returns the raw value on the scale of the Flic app, `get_battery_voltage()` the voltage.
- **Link check.** A connected Flic 1 does not advertise. An advertisement that arrives while the client believes it is connected means the link is gone (for example a Bluetooth proxy that hung), so the client checks the link and reconnects if the button does not answer.
- **Several adapters.** In private mode a Flic 1 only answers the adapter it was paired through; connecting through another one fails.

### Starting a Session (Recommended)

`start()` handles the full connection lifecycle in a single call: connect, quick verify, init button events, and read battery/firmware/name.

```python
client = FlicClient(
    address="AA:BB:CC:DD:EE:FF",
    ble_device=ble_device,
    pairing_id=saved_pairing_id,
    pairing_key=saved_pairing_key,
    serial_number=saved_serial,
    sig_bits=saved_sig_bits,
)

await client.start()
```

### Reconnecting (Subsequent Connections)

Quick verify uses stored pairing credentials for fast reconnection without user interaction. This is what `start()` calls internally, shown here for lower-level control.

```python
await client.connect()
await client.quick_verify()
await client.init_button_events()
```

### Button Events

```python
def on_button_event(event_type: str, event_data: dict):
    print(f"{event_type}: {event_data}")

client.on_button_event = on_button_event
```

**Event types** (all devices):
- `down` — Button pressed
- `up` — Button released
- `click` — Single click completed (fired after double-click timeout)
- `double_click` — Double click detected
- `hold` — Button held down

**Duo-only gesture events:**
- `swipe_left`, `swipe_right`, `swipe_up`, `swipe_down`

**Twist-only events:**
- `selector_changed` — Twist rotated to a different selector slot (extra data includes `selector_index` 0–11)

For Duo buttons, `event_data["button_index"]` indicates which button (0 = big, 1 = small).

### Rotation Events (Duo and Twist)

```python
def on_rotate_event(event_type: str, event_data: dict):
    print(f"{event_type}: {event_data}")

client.on_rotate_event = on_rotate_event
```

**Event types:**
- `rotate_clockwise`
- `rotate_counter_clockwise`

**Event data fields:**
- `angle_degrees` — Current rotational angle (0–360)
- `detent_crossings` — Number of 1% increments crossed in this event
- `total_turns` — Accumulated full revolutions (+/−)
- `total_detent_crossings` — Running total of percentage-boundary crossings
- `acceleration_multiplier` — 1.0–100.0, increases with faster rotation
- `rpm` — Revolutions per minute (positive = CW, negative = CCW)

Duo rotation events also include `dial_percentage` (0–100%, clamped) and `is_first_event`.

Twist rotation events also include `twist_mode_index` (0–12) and `mode_percentage` (0–100%).

### Twist Selector Change

```python
def on_selector_change(selector_index: int, extra_data: dict):
    print(f"Selector moved to slot {selector_index}")

client.on_selector_change = on_selector_change
```

### Twist Rotation Modes

The `PushTwistMode` setting controls how the Twist's rotation behaves:

| Mode | Behavior | LED Mode | Position |
|------|----------|----------|----------|
| `DEFAULT` | Rotation with click events, 12 independent selector slots + free rotation mode (index 12). Position bounded 0–100% per mode. | Fill | Bounded |
| `CONTINUOUS` | Same as default but position wraps continuously instead of clamping. | Wrapping | Wrapping |
| `SELECTOR` | Emphasizes slot selection (modes 0–11). Click and double-click events on all modes. | Slot indicator | Bounded |

### Updating Twist Position

For Twist devices, you can programmatically set the rotation position for any mode:

```python
# Set mode 12 (free rotation) to 50%
await client.async_send_update_twist_position(mode_index=12, percentage=50.0)

# Set selector slot 3 to 75%
await client.async_send_update_twist_position(mode_index=3, percentage=75.0)
```

### Device Information

```python
# Battery level (millivolts)
battery = await client.get_battery_level()

# Firmware version (integer)
firmware = await client.get_firmware_version()

# Device name (returns name and timestamp)
name, timestamp = await client.get_name()

# Set device name (max 23 UTF-8 bytes, auto-truncated)
new_name, timestamp = await client.set_name("My Flic")
```

### Firmware Updates

OTA firmware updates with flow-controlled data transfer and progress reporting:

```python
def on_progress(bytes_sent: int, total_bytes: int):
    print(f"Firmware update: {bytes_sent}/{total_bytes} bytes ({100*bytes_sent//total_bytes}%)")

with open("firmware.bin", "rb") as f:
    firmware_binary = f.read()

success = await client.async_firmware_update(
    firmware_binary=firmware_binary,
    progress_callback=on_progress,
)
```

The firmware update process:
1. Sends the firmware header to the device
2. Transfers compressed firmware data with flow control (device acknowledges chunks)
3. Device verifies the firmware signature
4. Sends force-disconnect to trigger device reboot with new firmware

During a firmware update, all other `FlicClient` instances are blocked from connecting to the same BLE address to prevent interference.

### Automatic Reconnection

When a BLE connection drops unexpectedly, the client automatically attempts to reconnect with exponential backoff (5 s → 300 s max). Call `set_ble_device()` when a new BLE advertisement arrives to provide a fresh device reference and wake the reconnect loop for an immediate retry:

```python
# Typically called from a BLE scanner callback
client.set_ble_device(new_ble_device)

# Flic 1: also pass the manufacturer data, it carries the battery value
client.set_ble_device(new_ble_device, advertisement_data.manufacturer_data)
```

Failed attempts are spaced at least 1 s apart (doubling up to 30 s), so advertisements that arrive faster do not make the client hammer a failing button or proxy.

The reconnect loop runs until the connection is restored or `stop()` is called. No manual intervention is needed.

### Disconnect Callback

```python
def on_disconnect():
    print("Connection lost — reconnecting automatically")

client.on_disconnect = on_disconnect
```

### Device Capabilities

Query what a device supports without checking its type:

```python
caps = client.capabilities

caps.button_count    # 1 for Flic 2/Twist, 2 for Duo
caps.has_rotation    # True for Duo and Twist
caps.has_selector    # True for Twist only (12 selector modes)
caps.has_gestures    # True for Duo only (swipe gestures)
caps.has_frame_header  # True for Flic 2/Duo, False for Twist/Flic 1
caps.raw_transport   # True for Flic 1 (the handler frames and signs its own packets)
```

## Protocol Details

### Security

The Flic protocol uses multiple cryptographic layers:

- **Ed25519** — Factory-signed device identity verification during pairing. Each device type has its own public key. The library tries all 4 signature twist variants to find the correct one.
- **X25519 ECDH** — Ephemeral key exchange during pairing to establish a shared secret.
- **HMAC-SHA256** — Key derivation for session keys and pairing credentials from the shared secret.
- **Chaskey-LTS** — Lightweight MAC algorithm for authenticating every packet in an established session. Uses a 5-byte truncated MAC with direction bit and packet counter to prevent replay.
- **SHA-256 MACs (Flic 1)** — Flic 1 predates the layers above. Packets and events are signed with a truncated SHA-256 keyed with a secret from pairing (the Flic cloud provides it). The button numbers its events, and the library drops events it has already received.

### Flic 2/Duo vs Twist Protocol Differences

The Flic 2 and Duo share one protocol variant, while the Twist uses a structurally different one:

| Feature | Flic 2 / Duo | Twist |
|---------|-------------|-------|
| BLE Service UUID | `00420000-...` | `00c90000-...` |
| Packet format | `[frame_header][opcode][payload][mac]` | `[opcode][payload][mac]` |
| Frame header | Yes (connection ID, fragment flags) | No |
| Packet fragmentation | Supported | Not needed |
| Opcode namespace | Integer constants | Hex constants (`TWIST_OPCODE_*`) |
| Pairing flags | `supportsDuo=true` | `clientVariant=0x00` |
| Quick verify | Uses stored `sig_bits` | Always `signature_variant=0` |

### Session Lifecycle

```
DISCONNECTED → connect() → CONNECTED
    → full_verify_pairing() → SESSION_ESTABLISHED  (new device)
    → quick_verify() → SESSION_ESTABLISHED          (known device)
        → init_button_events()                      (start receiving events)
        → disconnect() → DISCONNECTED

Automatic reconnection (after unexpected disconnect):
DISCONNECTED → async_reconnect() ←─ backoff loop ──╮
    → _start_inner() → CONNECTED → SESSION_ESTABLISHED
    │  (failure) ─────────────────────────────────────╯
    │  set_ble_device() wakes loop for immediate retry
    → stop() → DISCONNECTED (loop exits)
```

## Development

```bash
# Install in editable mode
pip install -e .

# Run tests
python -m pytest tests/

# Run a specific test
python -m pytest tests/test_rotate_tracker.py::test_multi_mode_tracker_mode_12_bounded
```

## License

MIT
