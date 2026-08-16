"""Live capture lifecycle: preflight, start, stop, status — and remote ingest.

Two ways traffic reaches the pipeline:

    capture mode   this host's NIC ──► dumpcap ──► closed pcaps ──► pipeline
    remote mode    a sensor elsewhere ──HTTP──► POST /ingestion/pcap ──► pipeline

The second exists because the network worth watching is often not the one the
dashboard runs on. It joins the *same* processing path at "closed pcaps", so a
submitted capture produces alerts indistinguishable from live ones.

That is also why this module is careful about what it accepts. Every submission
is traffic the platform did not witness, arriving from a caller whose only
credential is a shared API key, so the body is validated **while** it streams:
size ceiling and magic bytes are enforced before a single byte is handed to the
flow extractor, and the sender's filename is discarded rather than trusted.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from api.runtime import ensure_runtime, platform
from ingestion.service import IngestionService, IngestionServiceError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ingestion"])

#: File headers a capture reader will accept. Checked on the first bytes off
#: the wire so a mislabelled or hostile body is refused before it is stored,
#: never after it has been handed to the flow extractor.
PCAP_MAGIC: tuple[bytes, ...] = (
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microsecond
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microsecond
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanosecond
    b"\x0a\x0d\x0d\x0a",  # pcapng, section header block
)

#: Streamed in chunks rather than read whole: `await file.read()` on a 256 MB
#: submission is 256 MB of process memory before any limit is consulted.
CHUNK_BYTES = 1024 * 1024


def _require_ingestion() -> IngestionService:
    ensure_runtime()
    if platform.ingestion_service is None:
        raise HTTPException(
            status_code=503,
            detail="Ingestion is unavailable: the agent runtime failed to initialize.",
        )
    return platform.ingestion_service


@router.get("/ingestion/preflight")
def ingestion_preflight(mode: str | None = None):
    """Can the platform go live, and if not, what is missing?

    The frontend calls this to decide whether to enable "Go Live" and to show
    the reason when it cannot. ``mode`` matters: remote mode needs neither
    dumpcap nor an interface, so a host with no capture privileges is still
    perfectly able to ingest what its sensors send it.
    """
    try:
        result = _require_ingestion().preflight(mode)
    except IngestionServiceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse(content=result.as_dict())


@router.get("/ingestion/interfaces")
def ingestion_interfaces():
    """Capturable network interfaces, for the picker."""
    try:
        return JSONResponse(content=_require_ingestion().list_interfaces())
    except IngestionServiceError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.post("/ingestion/start")
def ingestion_start(interface: str | None = None, mode: str | None = None):
    """Begin ingestion and feed the agent pipeline.

    ``interface`` overrides the configured one; it is resolved against the
    enumerated list, so an unknown name fails with the valid options rather
    than capturing nothing.

    ``mode`` selects where traffic comes from — ``capture`` (default) taps this
    host, ``remote`` taps nothing and opens ``POST /ingestion/pcap`` to sensors.
    """
    service = _require_ingestion()
    try:
        return JSONResponse(content=service.start(interface=interface, mode=mode))
    except IngestionServiceError as exc:
        message = str(exc)
        # Already-running is a conflict; anything else is a missing dependency.
        status = 409 if "already running" in message else 422
        raise HTTPException(status_code=status, detail=message)


@router.post("/ingestion/stop")
def ingestion_stop():
    """Stop capture and the worker. Idempotent."""
    return JSONResponse(content=_require_ingestion().stop())


@router.get("/ingestion/status")
def ingestion_status():
    """Capture, stream, worker, and pipeline counters. Never includes secrets."""
    return JSONResponse(content=_require_ingestion().status())


@router.post("/ingestion/pcap")
async def ingestion_submit_pcap(request: Request, file: UploadFile = File(...)):
    """Accept a closed pcap from a remote sensor and run it through the pipeline.

    Synchronous by design: flow extraction happens before the response, so the
    sender is told how many flows its own submission produced instead of
    getting an ack and no answer. Extraction runs in the threadpool — it is
    CPU-bound and would otherwise stall every other request on the event loop.

    Send one with::

        curl -X POST http://<host>:8000/ingestion/pcap \\
             -H "X-API-Key: $CYBER_SURAKSHYA_API_KEY" \\
             -F "file=@capture.pcap"

    Status codes are chosen so an unattended sender can react without parsing
    prose: 409 means "not listening, retry after the operator goes live", 413
    means "rotate your captures smaller", 415 means "that was not a capture",
    422 means "the file was unusable, do not retry it unchanged".
    """
    service = _require_ingestion()
    upload  = service.policy.upload

    # Refuse before reading the body. Making a sensor push 200 MB uphill only
    # to be told nobody is listening is the kind of thing that gets a capture
    # agent throttled by its own network team.
    if not service.accepts_submissions():
        raise HTTPException(
            status_code=409,
            detail=(
                "Ingestion is not running, so submitted flows would reach no "
                "agent. Start it in remote mode first: "
                "POST /ingestion/start?mode=remote"
            ),
        )

    original = Path(file.filename or "submission.pcap").name
    suffix   = Path(original).suffix.lower()
    if suffix and suffix not in upload.allowed_suffixes:
        raise HTTPException(
            status_code=415,
            detail=(
                f"'{original}' does not look like a capture file. Allowed "
                f"extensions: {', '.join(upload.allowed_suffixes)}."
            ),
        )

    # Content-Length is a hint, not a guarantee — the streaming ceiling below
    # is the real limit. Checking it first turns a doomed 2 GB upload into an
    # immediate rejection instead of two minutes of wasted bandwidth.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > upload.max_file_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Submission is ~{int(declared) / 1_048_576:.0f} MB; the limit is "
                f"{upload.max_file_mb} MB. Rotate captures more often on the "
                "sensor and send smaller files."
            ),
        )

    source = request.client.host if request.client else None
    staged = await _receive_to_disk(file, service, original=original, source=source)

    try:
        result = await run_in_threadpool(
            service.ingest_pcap, staged, original_name=original, source=source
        )
    except IngestionServiceError as exc:
        # ingest_pcap removes the file on every path, including this one.
        raise HTTPException(status_code=422, detail=str(exc))

    return JSONResponse(content=result)


async def _receive_to_disk(
    file: UploadFile,
    service: IngestionService,
    *,
    original: str,
    source: str | None,
) -> Path:
    """Stream a submission to the upload directory, validating as it arrives.

    Returns the staged path, named after the content hash. Nothing derived from
    the sender's filename reaches the filesystem.

    Raises:
        HTTPException: 413 over the size ceiling, 415 not a capture file.
    """
    upload   = service.policy.upload
    work_dir = service.upload_dir()
    work_dir.mkdir(parents=True, exist_ok=True)

    # A partial name while streaming: the final name is the content hash, which
    # is not known until the last chunk. The suffix is deliberately not .pcap
    # so a crash mid-upload cannot leave something the processor mistakes for a
    # complete submission, and the uuid keeps concurrent senders off each
    # other's file.
    partial = work_dir / f"rx_partial_{uuid4().hex}.part"
    digest  = hashlib.sha256()
    total   = 0

    try:
        with partial.open("wb") as sink:
            while chunk := await file.read(CHUNK_BYTES):
                if total == 0:
                    _require_capture_magic(chunk, original)

                total += len(chunk)
                if total > upload.max_file_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"Submission exceeds the {upload.max_file_mb} MB limit. "
                            "Rotate captures more often on the sensor and send "
                            "smaller files."
                        ),
                    )

                digest.update(chunk)
                sink.write(chunk)

        if total == 0:
            raise HTTPException(status_code=415, detail=f"'{original}' is empty.")

        staged = work_dir / service.stage_upload_name(digest.hexdigest())
        try:
            partial.replace(staged)
        except OSError as exc:
            # The staged name is the content hash, so this collides only with a
            # byte-identical submission still being processed — and on Windows
            # that file is open, so the move fails. Nothing is lost: the run
            # already underway is ingesting exactly these bytes.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"An identical submission is already being processed. Its "
                    f"flows will reach the pipeline; this copy was not needed. "
                    f"({exc.__class__.__name__})"
                ),
            ) from exc
        logger.info(
            "remote_pcap_received",
            extra={"file": original, "source": source, "bytes": total},
        )
        return staged
    except HTTPException as exc:
        # Counted here rather than in the service: a submission refused during
        # streaming never reaches ingest_pcap, and a sender whose files are all
        # being rejected must not look like a quiet network.
        service.record_rejected_upload(
            f"{original}: {exc.detail}", source=source, filename=original
        )
        raise
    finally:
        partial.unlink(missing_ok=True)


def _require_capture_magic(head: bytes, original: str) -> None:
    """Reject anything whose first bytes are not a pcap or pcapng header.

    The extension check earlier is a courtesy to honest senders; this is the
    one that matters. Without it the flow extractor would be handed arbitrary
    caller-supplied bytes to parse.
    """
    if not any(head.startswith(magic) for magic in PCAP_MAGIC):
        raise HTTPException(
            status_code=415,
            detail=(
                f"'{original}' is not a pcap or pcapng file — its header does "
                "not match either format. If the sensor writes a different "
                "format, convert it with `editcap -F pcap` before sending."
            ),
        )
