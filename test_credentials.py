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

# --- multi-subnet: duplicate device polls collapse by chassis MAC ------------
from lldp_mapper import Device, PollResult, dedupe_polled

def _pr(mac, ip, host):
    return PollResult(device=Device(key=mac, hostname=host, mgmt_ip=ip,
                                    is_switch=True))

polled = [
    _pr("aa:bb:cc:00:00:01", "10.1.0.1", "core-01"),
    _pr("aa:bb:cc:00:00:02", "10.1.0.2", "core-02"),
    # core-01 seen again via its routed interface on a second subnet
    _pr("aa:bb:cc:00:00:01", "10.2.0.1", "core-01"),
]
deduped = dedupe_polled(polled)
assert len(deduped) == 2
assert [p.device.mgmt_ip for p in deduped] == ["10.1.0.1", "10.1.0.2"]
print("multi-subnet dedupe OK (duplicate switch dropped, first IP kept)")

# --- non-AOS-CX hosts never receive credentials ------------------------------
from lldp_mapper import AosCxRest, NotAosCxError

class _R:
    def __init__(self, code, body): self.status_code, self._b = code, body
    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(str(self.status_code)); e.response = self
            raise e
    def json(self):
        if self._b is None:
            raise ValueError("not json")
        return self._b

class _Sess:
    def __init__(self, resp): self.resp, self.posts, self.verify = resp, [], False
    def get(self, url, **kw): return self.resp
    def post(self, url, **kw):
        self.posts.append(url); return _R(200, {})
    def close(self): pass

for resp in (_R(404, None), _R(200, None), _R(200, {"hello": 1}),
             _R(200, ["x"])):
    api = AosCxRest("10.9.9.9", "u", "p")
    api.session = _Sess(resp)
    try:
        api.__enter__()
        raise AssertionError("login attempted against a non-CX host")
    except NotAosCxError:
        pass
    assert api.session.posts == [], api.session.posts

api = AosCxRest("10.9.9.9", "u", "p")
api.session = _Sess(_R(200, {"latest": {"version": "v10.13"}, "v10.04": {}}))
api.__enter__()
assert api.session.posts == ["https://10.9.9.9/rest/v10.13/login"]
# a pinned version skips the fingerprint by design
api = AosCxRest("10.9.9.9", "u", "p", api_version="v10.04")
api.session = _Sess(_R(404, None))
api.__enter__()
assert api.session.posts == ["https://10.9.9.9/rest/v10.04/login"]

real = lldp_mapper.AosCxRest
class _NotCx:
    def __init__(self, *a, **k): pass
    def __enter__(self): raise NotAosCxError("/rest returned HTTP 404")
    def __exit__(self, *e): pass
lldp_mapper.AosCxRest = _NotCx
try:
    assert poll_device("10.9.9.9", [("u", "p"), ("u2", "p2")],
                       "auto", False) is None
finally:
    lldp_mapper.AosCxRest = real
print("AOS-CX fingerprint OK (no login without a /rest index; pin bypasses)")
