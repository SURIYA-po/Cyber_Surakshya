"""POST /ingestion/pcap — the transport half of remote submission.

`test_remote_ingest.py` covers what happens to a pcap once it is on disk. This
covers getting it there, which is where the exposure is: the endpoint writes
caller-supplied bytes to this host before anything parses them, and the only
credential in front of it is a shared API key.

So the checks that must hold while the body streams are pinned here — size
ceiling, magic bytes, and the refusal to accept anything at all when no worker
is running to read what a submission publishes.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI

from api.routers import ingestion as ingestion_router

TestClient = pytest.importorskip("fastapi.testclient").TestClient

#: A valid libpcap header (little-endian, microsecond) with no packets. Enough
#: to pass the transport checks, which is all these tests exercise.
PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"      # magic
    b"\x02\x00\x04\x00"      # version 2.4
    b"\x00\x00\x00\x00"      # thiszone
    b"\x00\x00\x00\x00"      # sigfigs
    b"\x00\x00\x04\x00"      # snaplen
    b"\x01\x00\x00\x00"      # linktype: Ethernet
)


class StubService:
    """Ingestion service double: records what the router hands it."""

    def __init__(self, tmp_path, *, accepting: bool = True, max_file_mb: int = 1):
        from dataclasses import replace

        from ingestion.config import IngestionPolicy

        base = IngestionPolicy()
        self.policy = replace(
            base,
            upload=replace(
                base.upload, work_dir=str(tmp_path / "uploads"), max_file_mb=max_file_mb
            ),
        )
        self._accepting = accepting
        self.ingested: list[dict] = []
        self.rejections: list[str] = []

    def accepts_submissions(self) -> bool:
        return self._accepting

    def upload_dir(self):
        return self.policy.upload.resolved_work_dir()

    def stage_upload_name(self, digest: str) -> str:
        return f"rx_{digest[:32]}.pcap"

    def record_rejected_upload(self, reason, *, source=None, filename=None):
        self.rejections.append(reason)

    def ingest_pcap(self, path, *, original_name=None, source=None):
        self.ingested.append(
            {"bytes": path.stat().st_size, "name": original_name, "source": source}
        )
        path.unlink(missing_ok=True)
        return {"accepted": True, "flows_published": 3, "filename": original_name}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A minimal app holding only the ingestion router.

    Deliberately not the real app: booting it would construct model artifacts,
    Qdrant, and the graph runtime to test four bytes of file header.
    """
    def make(**kwargs):
        service = StubService(tmp_path, **kwargs)
        monkeypatch.setattr(ingestion_router, "ensure_runtime", lambda: None)
        monkeypatch.setattr(
            ingestion_router.platform, "ingestion_service", service, raising=False
        )
        app = FastAPI()
        app.include_router(ingestion_router.router)
        return TestClient(app), service

    return make


def _post(http, body: bytes, name: str = "capture.pcap"):
    return http.post(
        "/ingestion/pcap", files={"file": (name, body, "application/octet-stream")}
    )


# ── The happy path ────────────────────────────────────────────────────────────


def test_a_valid_capture_is_accepted_and_reported(client):
    http, service = client()

    response = _post(http, PCAP_HEADER)

    assert response.status_code == 200
    assert response.json()["flows_published"] == 3
    assert len(service.ingested) == 1
    assert service.ingested[0]["name"] == "capture.pcap"


def test_the_senders_address_is_recorded(client):
    """Attribution: a submission is traffic the platform did not witness."""
    http, service = client()

    _post(http, PCAP_HEADER)

    assert service.ingested[0]["source"] is not None


def test_pcapng_is_accepted_too(client):
    http, service = client()

    response = _post(http, b"\x0a\x0d\x0d\x0a" + b"\x00" * 60, name="sensor.pcapng")

    assert response.status_code == 200
    assert len(service.ingested) == 1


# ── Refusals ──────────────────────────────────────────────────────────────────


def test_submissions_are_refused_when_nothing_is_listening(client):
    """409, not 200: flows published to an unread stream are silently lost."""
    http, service = client(accepting=False)

    response = _post(http, PCAP_HEADER)

    assert response.status_code == 409
    assert "remote" in response.json()["detail"]
    assert service.ingested == []


def test_a_body_that_is_not_a_capture_is_refused(client):
    """The extension is a courtesy check; the magic bytes are the real gate."""
    http, service = client()

    response = _post(http, b"#!/bin/sh\nrm -rf /\n" * 10)

    assert response.status_code == 415
    assert service.ingested == [], "unparsed bytes must never reach the extractor"
    assert service.rejections, "a refused submission must be counted"


def test_a_capture_renamed_to_pcap_is_still_checked(client):
    """A hostile sender controls the filename. It controls the header too, but
    at least the header has to look like a capture."""
    http, _ = client()

    response = _post(http, b"PK\x03\x04" + b"\x00" * 100, name="totally.pcap")

    assert response.status_code == 415


def test_a_disallowed_extension_is_refused_before_the_body_is_read(client):
    http, service = client()

    response = _post(http, PCAP_HEADER, name="capture.exe")

    assert response.status_code == 415
    assert service.ingested == []


def test_an_empty_submission_is_refused(client):
    http, _ = client()

    response = _post(http, b"")

    assert response.status_code == 415


def test_an_oversized_submission_is_refused(client):
    """Enforced while streaming — the point is to stop reading, not to measure
    afterwards what was already in memory."""
    http, service = client(max_file_mb=1)

    response = _post(http, PCAP_HEADER + b"\x00" * (2 * 1_048_576))

    assert response.status_code == 413
    assert "1 MB" in response.json()["detail"]
    assert service.ingested == []


@pytest.mark.anyio
async def test_the_size_ceiling_holds_without_a_content_length(tmp_path):
    """Content-Length is a hint a sender chooses. The streaming check is not.

    The endpoint short-circuits on the declared length as a courtesy, so that
    path is the one an honest client exercises. This calls the receiver
    directly to prove the real ceiling is enforced chunk by chunk, on bytes
    already arriving, where a lying header cannot help.
    """
    import io

    from fastapi import HTTPException, UploadFile

    service = StubService(tmp_path, max_file_mb=1)
    oversized = UploadFile(
        file=io.BytesIO(PCAP_HEADER + b"\x00" * (2 * 1_048_576)),
        filename="capture.pcap",
    )

    with pytest.raises(HTTPException) as exc:
        await ingestion_router._receive_to_disk(
            oversized, service, original="capture.pcap", source="10.0.0.9"
        )

    assert exc.value.status_code == 413
    assert list(service.upload_dir().glob("*")) == []


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_a_rejected_submission_leaves_nothing_on_disk(client):
    """Partial uploads are still somebody's network traffic."""
    http, service = client(max_file_mb=1)

    _post(http, PCAP_HEADER + b"\x00" * (2 * 1_048_576))

    leftovers = list(service.upload_dir().glob("*"))
    assert leftovers == [], f"upload directory not cleaned: {leftovers}"


# ── Mode plumbing ─────────────────────────────────────────────────────────────


def test_start_rejects_an_unknown_mode_with_422(client, monkeypatch):
    from ingestion.service import IngestionServiceError

    http, service = client()

    def refuse(*, interface=None, mode=None):
        raise IngestionServiceError(f"Unknown ingestion mode '{mode}'.")

    service.start = refuse

    response = http.post("/ingestion/start", params={"mode": "remotte"})

    assert response.status_code == 422
    assert "Unknown ingestion mode" in response.json()["detail"]


def test_preflight_passes_the_mode_through(client):
    http, service = client()
    seen = {}

    class Result:
        def as_dict(self):
            return {"ready": True, "mode": seen.get("mode")}

    def preflight(mode=None):
        seen["mode"] = mode
        return Result()

    service.preflight = preflight

    response = http.get("/ingestion/preflight", params={"mode": "remote"})

    assert response.status_code == 200
    assert response.json()["mode"] == "remote"
