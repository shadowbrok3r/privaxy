#!/usr/bin/env python3
"""Test the Linux CA save dialog with a private portal and no graphical session.

Requires dbus-run-session, Python dbus-python, and PyGObject (GLib).
Run from any directory: python3 scripts/test-ca-export-dialog.py
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


def run_isolated():
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName("org.freedesktop.portal.Desktop", bus)
    loop = GLib.MainLoop()

    class Request(dbus.service.Object):
        @dbus.service.signal("org.freedesktop.portal.Request", signature="ua{sv}")
        def Response(self, code, results):
            pass

    class FileChooser(dbus.service.Object):
        def __init__(self, expected):
            super().__init__(name, "/org/freedesktop/portal/desktop")
            self.expected = expected
            self.requests = []

        @dbus.service.method(
            "org.freedesktop.portal.FileChooser",
            in_signature="ssa{sv}",
            out_signature="o",
            sender_keyword="sender",
        )
        def SaveFile(self, parent, title, options, sender=None):
            if options.get("current_name") != "privaxy-desktop-ca.crt":
                raise dbus.exceptions.DBusException("Unexpected CA filename")
            request_path = (
                "/org/freedesktop/portal/desktop/request/"
                + sender[1:].replace(".", "_")
                + "/"
                + str(options["handle_token"])
            )
            request = Request(bus, request_path)
            self.requests.append(request)
            code = 0 if len(self.requests) == 1 else 1
            results = dbus.Dictionary(
                {"uris": dbus.Array([self.expected.as_uri()] if code == 0 else [], signature="s")},
                signature="sv",
            )
            # Emit after the method reply; the client subscribes using handle_token.
            GLib.idle_add(lambda: request.Response(dbus.UInt32(code), results))
            return dbus.ObjectPath(request_path)

    with tempfile.TemporaryDirectory(prefix="privaxy-dialog-test-") as directory:
        expected = Path(directory) / "exported certificate.crt"
        chooser = FileChooser(expected)
        result = [1]
        environment = os.environ.copy()
        environment["PRIVAXY_DIALOG_TEST_PATH"] = str(expected)

        def run_test():
            try:
                result[0] = subprocess.run(
                    [
                        "cargo", "test", "--locked", "-p", "privaxy-app",
                        "--test", "ca_export_dialog", "--", "--ignored", "--nocapture",
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    env=environment,
                    timeout=120,
                    check=False,
                ).returncode
            except subprocess.TimeoutExpired:
                print("CA dialog test timed out", file=sys.stderr)
            finally:
                GLib.idle_add(loop.quit)

        worker = threading.Thread(target=run_test)
        worker.start()
        loop.run()
        worker.join()
        if result[0] == 0 and len(chooser.requests) != 2:
            raise RuntimeError("Expected one Save and one Cancel portal request")
        return result[0]


if __name__ == "__main__":
    if sys.argv[1:] == ["--isolated"]:
        sys.exit(run_isolated())
    # Never register a mock portal on the user's desktop session bus.
    sys.exit(subprocess.run([
        "dbus-run-session", "--", sys.executable, str(Path(__file__).resolve()), "--isolated",
    ], check=False).returncode)
