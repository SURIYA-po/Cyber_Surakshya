"""Ingestion service — the lifecycle behind the frontend's "Go Live" control.

Owns the whole chain and runs it on one background thread:

    capture ─► closed pcaps ─► flows ─► Redis Stream ─► agent pipeline

Four verbs: ``start``, ``stop``, ``status``, ``preflight``.

TWO MODES
---------
CAPTURE — this host taps an interface. The chain above runs end to end.
REMOTE  — this host taps nothing. Sensors elsewhere POST closed pcaps to
          ``/ingestion/pcap`` and the chain is joined at "closed pcaps":

    remote sensor ─HTTP─► ingest_pcap ─► flows ─► Redis Stream ─► pipeline

Remote mode exists because the interesting network is frequently not the one
the dashboard runs on. It is the *same* processing path — the same
``PcapProcessor``, normalizer, stream, and agents — so a submitted pcap
produces alerts indistinguishable from live capture. That is the point, and
also the risk: a submission is traffic the platform did not witness, and it is
trusted exactly as far as the API key holder is.

WHY A SINGLE WORKER
-------------------
The graph runtime, agents, and memory provider are module-level singletons
shared with the HTTP handlers. One ingestion worker keeps the pipeline
single-threaded from ingestion's side, so the only concurrency the platform
has to tolerate is "worker running while an API request also runs" — which the
guard's lock and the memory provider's RLock already cover. Scaling out means
a second *process* joining the consumer group, not a second thread here.

FAIL CLOSED
-----------
``preflight()`` checks every dependency before anything starts. A capture that
begins without a reachable Redis would fill the disk with pcaps whose flows go
nowhere, and report itself healthy while doing it.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ingestion.bridge.event_builder import EventBuilder
from ingestion.bridge.pipeline_bridge import PipelineBridge
from ingestion.capture.retention import sweep
from ingestion.capture.session import CaptureSession, CaptureSessionError
from ingestion.config import IngestionConfigError, IngestionPolicy
from ingestion.flows.normalizer import FlowNormalizer
from ingestion.flows.pcap_processor import PcapProcessor
from ingestion.stream.client import RedisUnavailableError, connect, health
from ingestion.stream.consumer import FlowConsumer
from ingestion.stream.producer import FlowProducer

logger = logging.getLogger(__name__)

#: Prefix for submitted pcaps on disk. Distinct from the capture prefix so the
#: retention sweeper, the ready-file scan, and an operator reading `ls` can all
#: tell locally-witnessed traffic from traffic somebody sent us.
UPLOAD_PREFIX = "rx"


class IngestionServiceError(Exception):
    """Raised when the ingestion service cannot perform the requested action."""


class IngestionMode(str, Enum):
    """Where the traffic comes from.

    CAPTURE — dumpcap on this host taps an interface.
    REMOTE  — sensors elsewhere submit closed pcaps over HTTP; nothing is
              captured here.
    """

    CAPTURE = "capture"
    REMOTE  = "remote"

    @classmethod
    def parse(cls, value: str | None, default: IngestionMode | None = None) -> IngestionMode:
        """Resolve a mode name, refusing anything unrecognized.

        Falling back to CAPTURE on a typo would start a real packet capture
        for an operator who asked for the mode that taps nothing.
        """
        if isinstance(value, cls):
            # str(IngestionMode.CAPTURE) is "IngestionMode.CAPTURE", not
            # "capture", so a member handed back in must short-circuit before
            # the string path turns it into an unknown mode.
            return value
        if value is None or value == "":
            return default or cls.CAPTURE
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            raise IngestionServiceError(
                f"Unknown ingestion mode '{value}'. Valid modes: "
                f"{', '.join(m.value for m in cls)}."
            ) from None


@dataclass
class WorkerStats:
    """Loop counters, surfaced so a stalled worker is visible."""

    polls:              int = 0
    files_processed:    int = 0
    flows_published:    int = 0
    events_processed:   int = 0
    sweeps:             int = 0
    errors:             int = 0
    consecutive_errors: int = 0
    last_error:         str | None = None
    last_poll_at:       datetime | None = None
    started_at:         datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "polls":              self.polls,
            "files_processed":    self.files_processed,
            "flows_published":    self.flows_published,
            "events_processed":   self.events_processed,
            "sweeps":             self.sweeps,
            "errors":             self.errors,
            "consecutive_errors": self.consecutive_errors,
            "last_error":         self.last_error,
            "last_poll_at":       self.last_poll_at.isoformat() if self.last_poll_at else None,
            "started_at":         self.started_at.isoformat() if self.started_at else None,
        }


@dataclass
class UploadStats:
    """Remote submission counters.

    Separate from WorkerStats because these describe callers, not this host's
    loop: a sender whose submissions are all being rejected looks identical to
    a quiet network unless the rejections are counted somewhere visible.
    """

    received:    int = 0
    accepted:    int = 0
    duplicates:  int = 0
    rejected:    int = 0
    failed:      int = 0
    bytes_received:  int = 0
    flows_published: int = 0
    last_filename:   str | None = None
    last_source:     str | None = None
    last_error:      str | None = None
    last_at:         datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "received":        self.received,
            "accepted":        self.accepted,
            "duplicates":      self.duplicates,
            "rejected":        self.rejected,
            "failed":          self.failed,
            "bytes_received":  self.bytes_received,
            "mb_received":     round(self.bytes_received / 1_048_576, 2),
            "flows_published": self.flows_published,
            "last_filename":   self.last_filename,
            "last_source":     self.last_source,
            "last_error":      self.last_error,
            "last_at":         self.last_at.isoformat() if self.last_at else None,
        }


@dataclass
class PreflightResult:
    """Whether the platform can go live, and what is missing if not."""

    ready:    bool = False
    mode:     str = "capture"
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks:   dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready":    self.ready,
            "mode":     self.mode,
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "checks":   dict(self.checks),
        }


class IngestionService:
    """Starts, stops, and reports on live network ingestion."""

    def __init__(
        self,
        runtime,
        *,
        policy: IngestionPolicy | None = None,
        base_dir: Path | None = None,
        redis_client=None,
        coordinator_budget: int | None = None,
    ) -> None:
        """
        Args:
            runtime: a GraphRuntime with a registered coordinator.
            redis_client: injected in tests; built from the policy otherwise.
            coordinator_budget: the coordinator's max_iterations, used to cap
                the bridge batch so events cannot be stranded mid-run.
        """
        self.runtime  = runtime
        self.policy   = policy or IngestionPolicy.load()
        self.base_dir = base_dir or Path.cwd()
        self.coordinator_budget = coordinator_budget

        self._injected_client = redis_client
        self._lock   = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop   = threading.Event()

        # Submissions are processed on the request thread, so without this two
        # concurrent uploads would run cicflowmeter twice over and mutate the
        # processor's counters from both. One at a time; the second waits.
        self._upload_lock = threading.Lock()

        self.mode      = IngestionMode.CAPTURE
        self.session   = CaptureSession(self.policy, base_dir=self.base_dir)
        self.stats     = WorkerStats()
        self.uploads   = UploadStats()
        self.client    = None
        self.producer: FlowProducer | None = None
        self.consumer: FlowConsumer | None = None
        self.processor: PcapProcessor | None = None
        self.bridge:   PipelineBridge | None = None

    # ── Preflight ─────────────────────────────────────────────────────────────

    def preflight(self, mode: IngestionMode | str | None = None) -> PreflightResult:
        """Check every dependency without changing anything.

        This is what the frontend calls to decide whether "Go Live" is
        available, and why it is not. ``mode`` matters: remote mode needs no
        dumpcap and no interface, so checking for them would report a host
        with no capture privileges as unable to ingest anything at all — when
        in fact it can ingest everything its sensors send it.
        """
        target = IngestionMode.parse(mode, default=self.mode)
        result = PreflightResult(mode=target.value)

        if target is IngestionMode.CAPTURE:
            backend_ok = self.session.backend.is_available()
            result.checks["capture_backend"] = backend_ok
            if not backend_ok:
                result.blockers.append(self.session.backend.unavailable_reason())

            try:
                policy_warnings = self.policy.validate_for_start(base_dir=self.base_dir)
                result.checks["capture_policy"] = True
                result.warnings.extend(policy_warnings)
            except IngestionConfigError as exc:
                result.checks["capture_policy"] = False
                result.blockers.append(str(exc))
        else:
            try:
                upload_warnings = self.policy.validate_for_remote(base_dir=self.base_dir)
                result.checks["upload_policy"] = True
                result.warnings.extend(upload_warnings)
            except IngestionConfigError as exc:
                result.checks["upload_policy"] = False
                result.blockers.append(str(exc))

        redis_ok = False
        try:
            client = self._injected_client or connect(self.policy.stream, verify=True)
            client.ping()
            redis_ok = True
        except Exception as exc:
            result.blockers.append(
                f"Redis is unreachable: {exc} Start it with "
                "`docker compose up -d redis`, or the capture would fill the "
                "disk with pcaps whose flows go nowhere."
            )
        result.checks["stream"] = redis_ok

        result.checks["normalizer"] = True
        try:
            FlowNormalizer()
        except Exception as exc:
            result.checks["normalizer"] = False
            result.blockers.append(f"Feature contract unavailable: {exc}")

        result.checks["runtime"] = self.runtime is not None
        if self.runtime is None:
            result.blockers.append("The agent pipeline runtime is not initialized.")

        if target is IngestionMode.CAPTURE:
            # Session warnings are all about backend selection. In remote mode
            # no backend is used, so reporting "dumpcap not found" would be a
            # warning about a component the operator deliberately isn't using.
            result.warnings.extend(self.session.status().warnings)

        result.ready = not result.blockers
        return result

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(
        self,
        *,
        interface: str | None = None,
        mode: IngestionMode | str | None = None,
    ) -> dict[str, Any]:
        """Begin feeding the pipeline, from this host's NIC or from sensors.

        In CAPTURE mode this starts dumpcap. In REMOTE mode it starts only the
        worker — the stream drain, the retention sweep, and the counters — so
        that submissions to ``ingest_pcap`` have somewhere to go. Nothing on
        this host is captured, and no capture privileges are required.

        Raises:
            IngestionServiceError: a dependency is missing or already running.
        """
        with self._lock:
            if self.is_running():
                raise IngestionServiceError(
                    "Ingestion is already running. Stop it before starting again."
                )

            target = IngestionMode.parse(mode, default=IngestionMode.CAPTURE)

            if interface and target is IngestionMode.REMOTE:
                raise IngestionServiceError(
                    "Remote mode taps no interface, so an interface override is "
                    "meaningless here. Start without one, or use capture mode."
                )

            if interface:
                # Rebuild the session for the new interface but keep the
                # existing backend: re-selecting would discard a deliberately
                # configured or injected one and silently fall back to
                # auto-detection.
                self.policy = self.policy.with_interface(interface)
                self.session = CaptureSession(
                    self.policy,
                    backend=self.session.backend,
                    base_dir=self.base_dir,
                )

            check = self.preflight(target)
            if not check.ready:
                raise IngestionServiceError("; ".join(check.blockers))

            try:
                self._build_components()
            except (RedisUnavailableError, Exception) as exc:
                raise IngestionServiceError(
                    f"Could not initialize the ingestion pipeline: {exc}"
                ) from exc

            if target is IngestionMode.CAPTURE:
                try:
                    self.session.start()
                except CaptureSessionError as exc:
                    raise IngestionServiceError(str(exc)) from exc

            # Set only once everything that can fail has succeeded, so a failed
            # start leaves the recorded mode matching what is actually running.
            self.mode = target
            self._stop.clear()
            self.stats   = WorkerStats(started_at=datetime.now(timezone.utc))
            self.uploads = UploadStats()
            self._thread = threading.Thread(
                target=self._run, name="ingestion-worker", daemon=True
            )
            self._thread.start()

            logger.info(
                "ingestion_started",
                extra={
                    "mode":       target.value,
                    "interface":  (
                        self.policy.capture.interface
                        if target is IngestionMode.CAPTURE else None
                    ),
                    "backend":    (
                        self.session.backend.backend_name
                        if target is IngestionMode.CAPTURE else "remote_submission"
                    ),
                    "stream":     self.policy.stream.stream_key,
                    "poll_s":     self.policy.worker.poll_interval_seconds,
                },
            )
            return self.status()

    def stop(self) -> dict[str, Any]:
        """Stop the worker and the capture. Idempotent."""
        with self._lock:
            self._stop.set()
            thread = self._thread
            self._thread = None

        if thread is not None and thread.is_alive():
            # Slightly longer than one poll so an in-flight batch can finish
            # and acknowledge rather than being reclaimed later.
            thread.join(timeout=self.policy.worker.poll_interval_seconds + 15)
            if thread.is_alive():
                logger.warning("ingestion_worker_did_not_stop_cleanly", extra={})

        try:
            self.session.stop()
        except Exception as exc:
            logger.warning("ingestion_capture_stop_failed", extra={"error": str(exc)})

        logger.info("ingestion_stopped", extra=self.stats.as_dict())
        return self.status()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        """Full ingestion status. Never includes credentials."""
        capture = self.session.status().to_dict()
        payload: dict[str, Any] = {
            "running":  self.is_running(),
            "mode":     self.mode.value,
            "capture":  capture,
            "worker":   self.stats.as_dict(),
            "uploads":  self.uploads.as_dict(),
            "remote": {
                "accepting":   self.accepts_submissions(),
                "endpoint":    "/ingestion/pcap",
                "max_file_mb": self.policy.upload.max_file_mb,
                "allowed_suffixes": list(self.policy.upload.allowed_suffixes),
                "work_dir":    str(self.policy.upload.resolved_work_dir(self.base_dir)),
            },
            "policy": {
                "source":         self.policy.source_path or "built_in_defaults",
                "poll_interval":  self.policy.worker.poll_interval_seconds,
                "batch_size":     self.policy.stream.batch_size,
                "retention_seconds": self.policy.capture.retention_seconds,
                "snaplen":        self.policy.capture.snaplen,
            },
        }

        if self.client is not None:
            snapshot = health(self.client, self.policy.stream)
            # The URL may carry credentials in some deployments; never return it.
            snapshot.pop("url", None)
            payload["stream"] = snapshot
        else:
            payload["stream"] = {"reachable": False, "stream_key": self.policy.stream.stream_key}

        if self.bridge is not None:
            payload["bridge"] = self.bridge.status()
        if self.processor is not None:
            payload["processor"] = self.processor.stats.as_dict()
        if self.producer is not None:
            payload["producer"] = self.producer.stats.as_dict()

        return payload

    def list_interfaces(self) -> list[dict[str, Any]]:
        """Capturable interfaces, for the frontend picker."""
        try:
            return self.session.list_interfaces()
        except CaptureSessionError as exc:
            raise IngestionServiceError(str(exc)) from exc

    # ── Remote submission ─────────────────────────────────────────────────────

    def accepts_submissions(self) -> bool:
        """Whether a remote sensor's pcap would be processed right now.

        Requires the worker to be running: without it the flows a submission
        publishes would sit in the stream unread, and the sender would get a
        success response for traffic no agent ever saw.
        """
        return self.is_running() and self.processor is not None

    def upload_dir(self) -> Path:
        return self.policy.upload.resolved_work_dir(self.base_dir)

    def record_rejected_upload(
        self,
        reason: str,
        *,
        source: str | None = None,
        filename: str | None = None,
    ) -> None:
        """Count a submission refused before it could be processed.

        The transport layer rejects oversized and non-capture bodies while they
        stream, so those never reach ``ingest_pcap``. Recording them here is
        what keeps "sensor is misconfigured" from looking like "sensor is
        quiet" on the dashboard.
        """
        self.uploads.received  += 1
        self.uploads.rejected  += 1
        self.uploads.last_error = reason[:300]
        self.uploads.last_source   = source
        self.uploads.last_filename = filename
        self.uploads.last_at       = datetime.now(timezone.utc)
        logger.warning(
            "remote_pcap_rejected",
            extra={"file": filename, "source": source, "reason": reason[:300]},
        )

    def ingest_pcap(
        self,
        path: Path,
        *,
        original_name: str | None = None,
        source: str | None = None,
    ) -> dict[str, Any]:
        """Process one submitted pcap through the live pipeline.

        The file is run through the same ``PcapProcessor`` as a locally
        captured one — same normalizer, same feature contract, same stream —
        and is **deleted** once processed. Traffic somebody sent us is exactly
        as sensitive as traffic we captured, and it has no ring buffer bounding
        how long it stays.

        Identical bytes submitted twice are recognized and skipped: the file is
        named by its content hash, so ``already_processed`` catches the repeat
        across restarts. Without that, a retrying sender would fabricate a
        volumetric attack out of one honest capture.

        Args:
            path: a pcap already written to disk by the caller.
            original_name: the sender's filename, for logs and status only.
            source: the sender's address, for logs and status only.

        Returns:
            What the submission produced: flows extracted, published, rejected.

        Raises:
            IngestionServiceError: not accepting, or the file could not be
                processed. The file is removed either way.
        """
        display = original_name or path.name

        if not self.accepts_submissions():
            path.unlink(missing_ok=True)
            self.record_rejected_upload(
                "ingestion is not running", source=source, filename=display
            )
            raise IngestionServiceError(
                "Ingestion is not running, so a submitted pcap would publish "
                "flows that no agent reads. Start it in remote mode first "
                "(POST /ingestion/start?mode=remote)."
            )

        # Serialized: flow extraction is CPU-heavy and the processor's counters
        # are plain integers. Two senders at once would corrupt both.
        with self._upload_lock:
            self.uploads.received += 1
            self.uploads.last_filename = display
            self.uploads.last_source   = source
            self.uploads.last_at       = datetime.now(timezone.utc)

            try:
                # The staged name is the content hash, so a second sender with
                # byte-identical traffic stages to the same path — and may have
                # had it consumed by the run that got here first. Same content,
                # already ingested: the honest answer is "duplicate", not 500.
                try:
                    self.uploads.bytes_received += path.stat().st_size
                except FileNotFoundError:
                    self.uploads.duplicates += 1
                    return self._submission_result(
                        display, path, source,
                        accepted=False, duplicate=True, published=0, extracted=0,
                    )

                if self.processor.already_processed(path):
                    self.uploads.duplicates += 1
                    logger.info(
                        "remote_pcap_duplicate",
                        extra={"file": display, "source": source, "stored": path.name},
                    )
                    return self._submission_result(
                        display, path, source,
                        accepted=False, duplicate=True, published=0, extracted=0,
                    )

                before_failed    = self.processor.stats.files_failed
                before_extracted = self.processor.stats.flows_extracted
                before_rejected  = self.processor.stats.flows_rejected

                published = self.processor.process_file(path)

                if self.processor.stats.files_failed > before_failed:
                    # process_file logs and counts its own failures rather than
                    # raising, so the only way to tell a bad pcap from an empty
                    # one is the counter. A sender must not be told "0 flows,
                    # fine" when its file was unreadable or off-contract.
                    self.uploads.failed += 1
                    self.uploads.last_error = "flow extraction or schema check failed"
                    raise IngestionServiceError(
                        f"'{display}' could not be processed. Either it is not a "
                        "readable capture, or the flows it yielded do not match "
                        "the platform's feature contract. See the server log for "
                        "the specific failure."
                    )

                extracted = self.processor.stats.flows_extracted - before_extracted
                rejected  = self.processor.stats.flows_rejected - before_rejected

                self.uploads.accepted += 1
                self.uploads.flows_published += published
                self.stats.flows_published   += published
                self.stats.files_processed    = self.processor.stats.files_processed

                logger.info(
                    "remote_pcap_ingested",
                    extra={
                        "file":      display,
                        "source":    source,
                        "extracted": extracted,
                        "published": published,
                        "rejected":  rejected,
                    },
                )
                return self._submission_result(
                    display, path, source,
                    accepted=True, duplicate=False,
                    published=published, extracted=extracted, rejected=rejected,
                )
            finally:
                # Always, on every path. A submission that failed is still a
                # full record of who talked to whom on somebody else's network.
                self._discard_submission(path)

    def stage_upload_name(self, digest: str) -> str:
        """Filename for a submission, derived from its content.

        Content-addressed for two reasons. It dedupes: ``PcapProcessor``'s
        processed-file set keys on the name and persists in Redis, so repeat
        submissions of identical bytes are caught with no extra bookkeeping.
        And it discards the sender's filename entirely, which is the only way
        to be sure a remote caller cannot steer where the file is written.

        Always ``.pcap`` — the format is decided by the magic bytes the reader
        finds, never by the extension, so honouring the sender's would add a
        variable that changes nothing.
        """
        return f"{UPLOAD_PREFIX}_{digest[:32]}.pcap"

    def _submission_result(
        self,
        display: str,
        path: Path,
        source: str | None,
        *,
        accepted: bool,
        duplicate: bool,
        published: int,
        extracted: int,
        rejected: int = 0,
    ) -> dict[str, Any]:
        return {
            "accepted":  accepted,
            "duplicate": duplicate,
            "filename":  display,
            "stored_as": path.name,
            "source":    source,
            "flows_extracted": extracted,
            "flows_published": published,
            "flows_rejected":  rejected,
            "mode":     self.mode.value,
            "message": (
                "Identical bytes were already ingested; skipped so a retry "
                "cannot fabricate duplicate traffic."
                if duplicate else
                f"{published} flow(s) published to the pipeline."
            ),
            "uploads": self.uploads.as_dict(),
        }

    def _discard_submission(self, path: Path) -> None:
        """Delete a processed submission without ever masking the outcome.

        This runs in a `finally`, so a raise here would replace the real result
        — and on Windows that is not hypothetical: when cicflowmeter fails on a
        malformed capture it leaves the handle open, and the PermissionError
        from unlink turned a precise "this file is unreadable" into an opaque
        server error. The leftover is not lost — `_sweep_uploads` collects it.
        """
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning(
                "remote_pcap_cleanup_deferred",
                extra={"path": path.name, "error": str(exc)[:200]},
            )

    def _sweep_uploads(self):
        """Remove submissions a crash left behind mid-processing."""
        upl = self.policy.upload
        return sweep(
            self.upload_dir(),
            prefix=UPLOAD_PREFIX,
            max_age_seconds=upl.retention_seconds,
            # Unlike a capture ring, nothing here is being actively written by
            # us — the newest file is just the newest leftover.
            keep_newest=False,
        )

    # ── Worker ────────────────────────────────────────────────────────────────

    def _build_components(self) -> None:
        stream = self.policy.stream
        # Separate connections so each side authenticates as its own ACL user.
        self.client = self._injected_client or connect(stream, verify=True)
        producer_client = self._injected_client or connect(
            stream, verify=False, role="producer"
        )
        consumer_client = self._injected_client or connect(
            stream, verify=False, role="consumer"
        )
        self.producer = FlowProducer(stream, client=producer_client)
        self.consumer = FlowConsumer(stream, client=consumer_client)
        self.processor = PcapProcessor(
            FlowNormalizer(),
            self.producer,
            # Processed-file tracking is capture-side work, so it uses the
            # producer identity — cs:pcap:processed is in that ACL's keyspace.
            state_client=producer_client,
            work_dir=self.session.output_dir / "_work",
        )
        self.bridge = PipelineBridge(
            self.consumer,
            self.runtime,
            event_builder=EventBuilder(),
            coordinator_budget=self.coordinator_budget,
        )

    def _run(self) -> None:
        """Background loop: sweep, process closed captures, drain the stream."""
        worker = self.policy.worker
        last_sweep = 0.0

        while not self._stop.wait(worker.poll_interval_seconds):
            self.stats.polls += 1
            self.stats.last_poll_at = datetime.now(timezone.utc)
            try:
                remote = self.mode is IngestionMode.REMOTE

                now = time.monotonic()
                if now - last_sweep >= worker.sweep_interval_seconds:
                    result = (
                        self._sweep_uploads() if remote
                        else self.session.sweep_retention()
                    )
                    self.stats.sweeps += 1
                    last_sweep = now
                    if result.deleted:
                        logger.info(
                            "ingestion_retention_swept",
                            extra={"deleted": result.deleted, "mode": self.mode.value},
                        )

                # Only capture mode has a ring to scan. In remote mode files
                # arrive through ingest_pcap and are processed there, on the
                # request thread, so the caller learns what its own submission
                # produced instead of getting an ack and no answer.
                if not remote:
                    ready = self.session.ready_files()
                    if ready:
                        published = self.processor.process_ready(ready)
                        self.stats.flows_published += published
                        self.stats.files_processed = self.processor.stats.files_processed

                # Drained one batch at a time, checking for stop between them.
                # bridge.drain() would run up to max_batches back to back —
                # tens of seconds at ~0.5s/event — and stop() cannot interrupt
                # it, so shutdown would hang well past its join timeout.
                for _ in range(worker.max_batches_per_poll):
                    if self._stop.is_set():
                        break
                    processed = self.bridge.run_once()
                    if processed == 0:
                        break
                    # Updated per batch so status is current during a long
                    # drain rather than only at the end of the iteration.
                    self.stats.events_processed += processed

                self.stats.consecutive_errors = 0

            except Exception as exc:
                self.stats.errors += 1
                self.stats.consecutive_errors += 1
                self.stats.last_error = f"{type(exc).__name__}: {exc}"[:500]
                logger.exception(
                    "ingestion_worker_iteration_failed",
                    extra={
                        "consecutive_errors": self.stats.consecutive_errors,
                        "error_type": type(exc).__name__,
                    },
                )
                if self.stats.consecutive_errors >= worker.max_consecutive_errors:
                    # An unreachable dependency must not spin at full speed
                    # forever. Stop and report unhealthy so an operator sees it.
                    logger.error(
                        "ingestion_worker_giving_up",
                        extra={
                            "consecutive_errors": self.stats.consecutive_errors,
                            "last_error": self.stats.last_error,
                        },
                    )
                    break

        logger.info("ingestion_worker_exited", extra=self.stats.as_dict())
