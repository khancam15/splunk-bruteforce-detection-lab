"""Tests for soc_automation.py. Splunk is mocked, so nothing leaves the machine."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import soc_automation  # noqa: E402

ALERT = {
    "_time": "2026-01-10T14:05:00.000+00:00",
    "Account_Name": "jdoe",
    "Source_Network_Address": "10.0.0.50",
    "host": "WIN-DC01",
    "failed_logins": "24",
    "logon_types": "3",
    "reasons": "Unknown user name or bad password.",
    "severity": "High",
}


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise soc_automation.requests.exceptions.HTTPError(f"{self.status_code}", response=self)

    def json(self):
        return self.payload


def test_query_detects_failed_logons_at_threshold():
    query = soc_automation.SPL_QUERY
    assert "EventCode=4625" in query
    assert "where failed_logins >= 10" in query
    assert 'severity=if(failed_logins >= 20, "High", "Medium")' in query


def test_query_excludes_loopback_sources():
    assert 'Source_Network_Address="127.0.0.1"' in soc_automation.SPL_QUERY
    assert 'Source_Network_Address="::1"' in soc_automation.SPL_QUERY


def test_saved_search_uses_same_detection_logic():
    saved = (Path(__file__).resolve().parent.parent / "queries" / "brute_force_detection.spl").read_text()
    for clause in ("EventCode=4625", "bucket _time span=5m", "where failed_logins >= 10"):
        assert clause in saved


def test_splunk_calls_use_timeouts_and_session_key(monkeypatch):
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("/auth/login"):
            return FakeResponse({"sessionKey": "abc123"})
        return FakeResponse({"sid": "job-1"})

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({"results": [ALERT]})

    monkeypatch.setattr(soc_automation.requests, "post", fake_post)
    monkeypatch.setattr(soc_automation.requests, "get", fake_get)

    key = soc_automation.get_session_key()
    sid = soc_automation.run_search(key)
    results = soc_automation.get_results(key, sid)

    assert key == "abc123"
    assert sid == "job-1"
    assert results == [ALERT]
    for url, kwargs in calls:
        assert url.startswith(soc_automation.SPLUNK_HOST)
        assert kwargs["timeout"] > 0
    assert calls[1][1]["headers"]["Authorization"] == "Splunk abc123"
    assert calls[1][1]["data"]["search"] == soc_automation.SPL_QUERY
    assert calls[2][0].endswith("/services/search/jobs/job-1/results")


def test_case_note_lists_every_alert(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    second = {**ALERT, "Account_Name": "admin", "failed_logins": "12", "severity": "Medium"}

    path = Path(soc_automation.generate_case_note([ALERT, second]))

    assert path.parent.name == soc_automation.OUTPUT_DIR
    assert path.name.startswith("soc_case_") and path.suffix == ".md"
    note = path.read_text()
    assert "- Alerts found: **2**" in note
    assert "### High - jdoe from 10.0.0.50" in note
    assert "### Medium - admin from 10.0.0.50" in note
    assert note.count("**Recommended actions**") == 2


@pytest.mark.parametrize("missing", ["Account_Name", "severity", "host"])
def test_case_note_tolerates_missing_fields(tmp_path, monkeypatch, missing):
    monkeypatch.chdir(tmp_path)
    alert = {k: v for k, v in ALERT.items() if k != missing}

    note = Path(soc_automation.generate_case_note([alert])).read_text()

    assert "- Alerts found: **1**" in note


@pytest.fixture
def no_sleep(monkeypatch):
    waits = []
    monkeypatch.setattr(soc_automation.time, "sleep", waits.append)
    return waits


def scripted_post(monkeypatch, steps):
    """Replace requests.post with one that plays back steps (a response or an exception)."""
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        step = steps[len(calls) - 1]
        if isinstance(step, Exception):
            raise step
        return step

    monkeypatch.setattr(soc_automation.requests, "post", fake_post)
    return calls


def test_retries_a_splunk_restart_then_succeeds(monkeypatch, no_sleep):
    exc = soc_automation.requests.exceptions
    calls = scripted_post(monkeypatch, [exc.ConnectionError("refused"), FakeResponse({}, 503), FakeResponse({"sessionKey": "k"})])

    assert soc_automation.get_session_key() == "k"
    assert len(calls) == 3
    assert no_sleep == list(soc_automation.RETRY_DELAYS)


def test_never_retries_a_rejected_login(monkeypatch, no_sleep):
    calls = scripted_post(monkeypatch, [FakeResponse({}, 401), FakeResponse({"sessionKey": "k"})])
    monkeypatch.setattr(soc_automation, "SPLUNK_USER", "analyst")
    monkeypatch.setattr(soc_automation, "SPLUNK_PASS", "wrong")

    assert soc_automation.main() == soc_automation.EXIT_NEEDS_YOU
    assert len(calls) == 1
    assert no_sleep == []


def test_unreachable_splunk_exits_try_later(monkeypatch, no_sleep):
    exc = soc_automation.requests.exceptions
    scripted_post(monkeypatch, [exc.Timeout("slow")] * 3)
    monkeypatch.setattr(soc_automation, "SPLUNK_USER", "analyst")
    monkeypatch.setattr(soc_automation, "SPLUNK_PASS", "pw")

    assert soc_automation.main() == soc_automation.EXIT_TRY_LATER


def test_missing_credentials_need_a_person(monkeypatch):
    monkeypatch.setattr(soc_automation, "SPLUNK_USER", None)
    assert soc_automation.main() == soc_automation.EXIT_NEEDS_YOU
