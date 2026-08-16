"""Tests for the Prometheus exposition endpoint.

The format is a contract with an external scraper: a malformed line makes
Prometheus reject the whole scrape, and a renamed series silently breaks every
dashboard built on it. Both fail somewhere the platform cannot see, so they are
worth pinning here.
"""
from __future__ import annotations

import re

import pytest

from observability.metrics import MetricsWriter, render_platform_metrics


class _FakeStats:
    def __init__(self, **fields):
        self._fields = fields

    def as_dict(self):
        return dict(self._fields)


class _FakePlatform:
    ready = True
    memory_provider = None
    artifacts = None
    ingestion_service = None
    response_agent = None


# ── Writer ────────────────────────────────────────────────────────────────────


def test_declares_help_and_type_once_per_family():
    w = MetricsWriter()
    w.add("cs_thing", 1, labels={"a": "x"}, help_text="A thing.")
    w.add("cs_thing", 2, labels={"a": "y"}, help_text="A thing.")

    body = w.render()
    assert body.count("# HELP cs_thing") == 1
    assert body.count("# TYPE cs_thing") == 1
    assert 'cs_thing{a="x"} 1.0' in body
    assert 'cs_thing{a="y"} 2.0' in body


def test_non_numeric_values_are_skipped_not_rendered_as_nan():
    """A scraper reading NaN as a measurement is worse than a missing series."""
    w = MetricsWriter()
    w.add("cs_ok", 3)
    w.add("cs_string", "not a number")
    w.add("cs_none", None)
    w.add("cs_nan", float("nan"))
    w.add("cs_inf", float("inf"))

    body = w.render()
    assert "cs_ok 3.0" in body
    for absent in ("cs_string", "cs_none", "cs_nan", "cs_inf"):
        assert absent not in body


def test_label_values_are_escaped():
    w = MetricsWriter()
    w.add("cs_thing", 1, labels={"name": 'quote" and \\ back'})
    body = w.render()
    assert r'name="quote\" and \\ back"' in body


def test_output_ends_with_a_newline():
    """Prometheus rejects a body whose final line is unterminated."""
    w = MetricsWriter()
    w.add("cs_thing", 1)
    assert w.render().endswith("\n")


def test_underscore_prefixed_fields_are_not_exported():
    w = MetricsWriter()
    w.add_many("cs_x", {"real": 1, "_internal": 2})
    body = w.render()
    assert "cs_x_real" in body
    assert "_internal" not in body


# ── Platform rendering ────────────────────────────────────────────────────────


def test_renders_with_a_bare_platform():
    """A half-initialised platform is normal during startup and after an
    artifact failure. /metrics must not be the endpoint that takes the
    server down."""
    body = render_platform_metrics(_FakePlatform())
    assert "cs_platform_ready 1.0" in body
    assert "cs_memory_available 0.0" in body


def test_ingestion_counters_are_exported_when_present():
    class Service:
        stats = _FakeStats(polls=7, flows_published=42, errors=0)
        bridge = None
        processor = None
        producer = None
        consumer = None

        def is_running(self):
            return True

    class P(_FakePlatform):
        ingestion_service = Service()

    body = render_platform_metrics(P())
    assert "cs_ingestion_running 1.0" in body
    assert "cs_ingestion_worker_polls 7.0" in body
    assert "cs_ingestion_worker_flows_published 42.0" in body


def test_a_raising_service_does_not_break_the_scrape():
    class Hostile:
        stats = None
        bridge = None
        processor = None
        producer = None
        consumer = None

        def is_running(self):
            raise RuntimeError("worker exploded")

    class P(_FakePlatform):
        ingestion_service = Hostile()

    body = render_platform_metrics(P())
    assert "cs_ingestion_running 0.0" in body


def test_every_line_is_valid_exposition_syntax():
    class Service:
        stats = _FakeStats(polls=1, errors=2)
        bridge = None
        processor = None
        producer = None
        consumer = None

        def is_running(self):
            return False

    class P(_FakePlatform):
        ingestion_service = Service()

    sample = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{.*\})? -?[\d.eE+]+$")
    for line in render_platform_metrics(P()).splitlines():
        if not line or line.startswith("#"):
            continue
        assert sample.match(line), f"malformed exposition line: {line!r}"


# ── Endpoint ──────────────────────────────────────────────────────────────────


def test_metrics_endpoint_is_public_and_correctly_typed():
    """No API key: a scraper that needs a rotating credential silently stops."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    try:
        import app
    except RuntimeError as exc:
        pytest.skip(f"app unavailable: {exc}")

    with TestClient(app.app) as client:
        response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "version=0.0.4" in response.headers["content-type"]
    assert "cs_platform_ready" in response.text
