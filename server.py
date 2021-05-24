import binascii
import json
import logging
import threading
import traceback
from base64 import b64encode
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Empty, Queue
from socketserver import ThreadingMixIn
from threading import Event, Timer
from typing import Any, Callable, Dict, Generator, Iterable, Optional, Tuple

import click
from fido2.cbor import encode as cbor_encode
from fido2.client import WEBAUTHN_TYPE, ClientData
from fido2.ctap import STATUS
from fido2.ctap2 import AttestationObject, Ctap2
from fido2.hid import CtapHidDevice, open_device
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import PublicKeyCredentialCreationOptions
from serial import Serial

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def b64_object_hook(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Replace specific keys that _may_ contain base64 data with the decoded value."""
    for key, value in obj.items():
        if key in {"id", "challenge"}:
            with suppress(binascii.Error):
                obj[key] = websafe_decode(value)
    return obj


@dataclass
class Device:
    """FIDO2 device that can be pressed automatically."""
    device: CtapHidDevice
    ctap2: Ctap2
    pin: int

    def press(self, serial: Serial):
        """Trigger a button press."""
        serial.write(self.pin.to_bytes(1, "little"))


class DeviceManager:
    """Lease FIDO2 devices on the system."""

    queue = Queue()

    def __init__(self, devices: Iterable[Tuple[str, int]]):
        """Populates the internal device queue with provides devices."""
        for device_path, pin in devices:
            device = open_device(device_path)
            self.queue.put(Device(
                device=device,
                ctap2=Ctap2(device),
                pin=pin,
            ))

    @contextmanager
    def checkout(
        self, timeout: Optional[int] = 10
    ) -> Generator[None, None, Ctap2]:
        """Yields a devices from the internal queue, blocking until it's available as needed."""
        try:
            # Try to checkout a device
            device: Ctap2 = self.queue.get(timeout=timeout)
        except Empty:
            # Re-write the exception to something easier to understand/user friendly
            raise Exception(f"no devices available after {timeout} seconds")
        # Yield devices and return it to the queue once the caller is done with it
        try:
            yield device
        finally:
            self.queue.put(device)

class CredentialHTTPHandler(BaseHTTPRequestHandler):
    """Handle HTTP request to use a method on a Device."""

    # Replace the default error HTML page with just plaintext
    error_content_type = "text/plain"
    error_message_format = "%(explain)s"

    def send_response(self, code, message=None):
        super().send_response(code, message)
        # Add some CORS headers to all responses
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Headers", "*")

    def do_OPTIONS(self):
        # Support CORS preflight requests
        self.send_response(HTTPStatus.OK.value)
        self.end_headers()

    def do_GET(self):
        # This shouldn't be used, but return something just in case
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Move Along, Nothing to See Here")

    def do_POST(self):
        # Read and parse the JSON method parameters from the POST body
        try:
            content_length: int = int(self.headers.get("Content-Length", 0))
            options: Dict[str, Any] = json.loads(
                self.rfile.read(content_length), object_hook=b64_object_hook
            )
        except json.JSONDecodeError:
            log.exception("failed to parse JSON body")
            self.send_error(
                HTTPStatus.BAD_REQUEST.value, explain=traceback.format_exc()
            )
            return
        # Catch _any_ errors and return/log them since this can break in lots of ways
        try:
            # Parse the JSON data into the relevant classes
            options = PublicKeyCredentialCreationOptions._wrap(options)
            client_data = ClientData.build(
                type=WEBAUTHN_TYPE.MAKE_CREDENTIAL,
                origin=self.headers.get("Origin", "https://example.com"),
                challenge=websafe_encode(options.challenge),
                clientExtensions={},
            )
            # Checkout a device for as little time as possible and perform the operation
            with self.server.devices.checkout() as device:
                # Timeout the actual call after 5 seconds just to be safe
                timeout_event = Event()
                timer = Timer(5, timeout_event.set)
                timer.daemon = True
                timer.start()
                attestation_object = device.ctap2.make_credential(
                    client_data.hash,
                    options.rp,
                    options.user,
                    options.pub_key_cred_params,
                    options.exclude_credentials or None,
                    event=timeout_event,
                    # When the device is waiting for a press, send one via serial
                    # TODO: _probably_ need to lock here, but it's a single byte so probably :fine:
                    on_keepalive=lambda status: device.press(self.server.serial) if status == STATUS.UPNEEDED else None,
                )
            # Encode the result as JSON
            self.send_response(HTTPStatus.OK.value)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "id": b64encode(attestation_object.auth_data.credential_data.credential_id).decode('ascii'),
                "client_data": str(client_data),
                "attestation_object": b64encode(bytes(attestation_object.with_string_keys())).decode('ascii'),
            }).encode("utf-8"))
        except Exception:
            log.exception("failed to make credential")
            self.send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR.value, explain=traceback.format_exc()
            )
            return


class CredentialHTTPServer(ThreadingMixIn, HTTPServer):
    """Extends http.server.HTTPServer with each socket handled in a thread and a global device manager instance."""

    def __init__(self, serial: str, baud: int, devices: Iterable[Tuple[str, int]], bind: str, port:int):
        self.devices = DeviceManager(devices)
        self.serial = Serial(port=serial, baudrate=baud, timeout=1)
        super().__init__((bind, port), CredentialHTTPHandler)


@click.command()
@click.option('--bind', type=str, default="0.0.0.0", help='IP Address to bind HTTP')
@click.option('--port', type=int, default=1337, help='Port to bind HTTP')
@click.option('--serial', type=click.Path(readable=False), default='/dev/ttyACM0', help='Port to connect via serial')
@click.option('--baud', type=int, default=115200, help='Baud rate for serial')
@click.option('--device', 'devices', type=(click.Path(readable=False), int), multiple=True, help='hardcode HID devices/pin pairs')
def main(**kwargs):
    server = CredentialHTTPServer(**kwargs)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

if __name__ == '__main__':
    main()