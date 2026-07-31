#!/usr/bin/env python3
"""Tests for multi-credential iteration and assembly."""
import json
import os
import types

import requests

import lldp_mapper
from lldp_mapper import poll_device


class _Resp:
    def __init__(self, code):
        self.status_code = code


def _auth_error():
    exc = requests.HTTPError("401")
    exc.response = _Resp(401)
    return exc


class FakeRest:
    """Accepts only ('svc_net', 'pw2'); rejects others with 401."""
    attempts = []

    def __init__(self, host, username, password, api_version, verify):
        self.username, self.password = username, password
        self.api_version = "v10.16"
        FakeRest.attempts.append(username)

    def __enter__(self):
        if (self.username, self.password) != ("svc_net", "pw2"):
            raise _auth_error()
        return self

    def __exit__(self, *exc):
        pass

    def system_info(self):
        return {"hostname": "sw1", "platform_name": "6300M",
                "software_version": "FL.10.16", "system_mac": "aa:bb:cc:00:00:99"}

    def lldp_neighbors(self):
        return {}


real = lldp_mapper.AosCxRest
lldp_mapper.AosCxRest = FakeRest
try:
    creds = [("admin", "pw1"), ("svc_net", "pw2"), ("backup", "pw3")]
    pr = poll_device("10.0.0.1", creds, "auto", False,
                     want_details=False, want_routing=False)
    assert pr is not None and pr.device.hostname == "sw1"
    # tried admin (401), succeeded on svc_net, never touched backup
    assert FakeRest.attempts == ["admin", "svc_net"], FakeRest.attempts

    # all rejected -> None, all tried
    FakeRest.attempts = []
    pr2 = poll_device("10.0.0.2", [("a", "x"), ("b", "y")], "auto", False,
                      want_details=False, want_routing=False)
    assert pr2 is None and FakeRest.attempts == ["a", "b"]

    # connection error aborts immediately without trying further creds
    class DeadRest(FakeRest):
        def __enter__(self):
            raise requests.ConnectionError("refused")
    lldp_mapper.AosCxRest = DeadRest
    FakeRest.attempts = []
    pr3 = poll_device("10.0.0.3", creds, "auto", False,
                      want_details=False, want_routing=False)
    assert pr3 is None and FakeRest.attempts == ["admin"], FakeRest.attempts
finally:
    lldp_mapper.AosCxRest = real
print("credential iteration OK (401 advances, success stops, conn error aborts)")

# --- gather_credentials assembly ---------------------------------------------
from lldp_mapper import gather_credentials

with open("creds_test.json", "w") as f:
    json.dump([{"username": "filed", "password": "fp"},
               {"username": "filed2", "password": "fp2"}], f)
os.chmod("creds_test.json", 0o600)

ns = types.SimpleNamespace(creds="creds_test.json", username=[])
assert gather_credentials(ns) == [("filed", "fp"), ("filed2", "fp2")]

os.environ["AOSCX_PASSWORD"] = "envpw"
ns2 = types.SimpleNamespace(creds=None, username=["admin"])
assert gather_credentials(ns2) == [("admin", "envpw")]
del os.environ["AOSCX_PASSWORD"]

ns3 = types.SimpleNamespace(creds="missing.json", username=[])
assert gather_credentials(ns3) == []
os.remove("creds_test.json")
print("credential assembly OK (file order, env single-user, missing file)")
