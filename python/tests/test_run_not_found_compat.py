"""Regression: the server returns HTTP 404 for an unknown run, and the SDK keeps its exception contract.

Before the 404 change, ``run_not_found`` arrived as HTTP 200 with ``ok: false``. Callers using
``raise_on_body_ok_false=True`` (bundle and evidence helpers) got ``GovAIAPIError``; callers without
the flag got the decoded body. These tests pin both behaviours for the 404 body, and check that
unrelated HTTP errors still raise ``GovAIHTTPError``.
"""

import json
from unittest.mock import MagicMock

import pytest

from govai import GovAIAPIError, GovAIClient, GovAIHTTPError
from govai.bundle import get_bundle

RUN_NOT_FOUND = {
    "ok": False,
    "error": "run_not_found",
    "message": "No events for run_id in tenant ledger.",
    "run_id": "missing-run",
}


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self._body = body
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


@pytest.fixture
def client_with(monkeypatch):
    def make(status_code, body):
        client = GovAIClient("http://127.0.0.1:8088")
        client._session.request = MagicMock(return_value=FakeResponse(status_code, body))
        return client

    return make


def test_bundle_run_not_found_404_raises_api_error_as_before(client_with):
    client = client_with(404, RUN_NOT_FOUND)
    with pytest.raises(GovAIAPIError) as excinfo:
        get_bundle(client, "missing-run")
    assert type(excinfo.value) is GovAIAPIError
    assert str(excinfo.value) == "run_not_found"
    assert excinfo.value.payload == RUN_NOT_FOUND


def test_request_without_flag_returns_body_for_run_not_found_404(client_with):
    client = client_with(404, RUN_NOT_FOUND)
    out = client.request_json("GET", "/bundle", params={"run_id": "missing-run"})
    assert out == RUN_NOT_FOUND


def test_other_404_bodies_still_raise_http_error(client_with):
    client = client_with(404, {"ok": False, "error": "route_not_found"})
    with pytest.raises(GovAIHTTPError) as excinfo:
        client.request_json("GET", "/bundle", params={"run_id": "x"}, raise_on_body_ok_false=True)
    assert excinfo.value.status_code == 404


def test_run_not_found_without_json_body_still_raises_http_error(client_with):
    client = client_with(404, None)
    with pytest.raises(GovAIHTTPError) as excinfo:
        client.request_json("GET", "/bundle", params={"run_id": "x"}, raise_on_body_ok_false=True)
    assert excinfo.value.status_code == 404


def test_server_error_still_raises_http_error(client_with):
    client = client_with(500, {"ok": False, "error": "run_not_found"})
    with pytest.raises(GovAIHTTPError):
        client.request_json("GET", "/bundle", params={"run_id": "x"}, raise_on_body_ok_false=True)


def test_http_200_ok_false_behaviour_unchanged(client_with):
    client = client_with(200, RUN_NOT_FOUND)
    with pytest.raises(GovAIAPIError):
        client.request_json("GET", "/bundle", params={"run_id": "x"}, raise_on_body_ok_false=True)
    assert client.request_json("GET", "/bundle", params={"run_id": "x"}) == RUN_NOT_FOUND
