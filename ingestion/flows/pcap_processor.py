"""Turns closed capture files into published flows.

    ready pcap ──► cicflowmeter ──► FlowNormalizer ──► FlowProducer

Only *closed* files are processed. dumpcap's ring buffer guarantees file *k* is
complete once file *k+1* exists, and `CaptureSession.ready_files()` already
excludes the newest. Reading the file still being written yields a truncated
final packet and a corrupt final flow — a silent one, because a partial flow
looks exactly like a real short flow.

Processed filenames are remembered so a restart neither reprocesses (which
would fabricate duplicate traffic) nor skips (which would lose it). The
producer's `flow_id` dedup is the second line of defence behind that.
"""
from __future__ import annotations

import logging
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Redis key holding the set of processed capture filenames.
PROCESSED_KEY = "cs:pcap:processed"

# Filenames are small; a week is long enough to survive any restart while
# bounding the set. Capture files are gone within the retention window anyway.
PROCESSED_TTL_SECONDS = 604_800


@dataclass
class ProcessorStats:
    """Counters exposed so nothing is dropped without a number attached."""

    files_processed: int = 0
    files_skipped:   int = 0
    files_failed:    int = 0
    flows_extracted: int = 0
    flows_published: int = 0
    flows_rejected:  int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


class PcapProcessor:
    """Extracts flows from completed capture files and publishes them."""

    def __init__(
        self,
        normalizer,
        producer,
        *,
        state_client=None,
        work_dir: Path | None = None,
    ) -> None:
        """
        Args:
            state_client: Redis client used to remember processed filenames.
                Falls back to an in-process set, which is correct for a single
                run but forgets across restarts.
            work_dir: scratch space for intermediate CSVs.
        """
        self.normalizer   = normalizer
        self.producer     = producer
        self.state_client = state_client
        self.work_dir     = work_dir
        self.stats        = ProcessorStats()
        self._seen: set[str] = set()

    # ── Processing ────────────────────────────────────────────────────────────

    def process_ready(self, ready_files: list[Path]) -> int:
        """Process every unseen closed capture file. Returns flows published."""
        published = 0
        for path in ready_files:
            if self.already_processed(path):
                self.stats.files_skipped += 1
                continue
            published += self.process_file(path)
        return published

    def process_file(self, path: Path) -> int:
        """Extract, normalize, and publish the flows in one capture file."""
        try:
            frame = self._extract_flows(path)
        except Exception as exc:
            self.stats.files_failed += 1
            logger.error(
                "pcap_extract_failed",
                extra={"path": str(path), "error": str(exc)[:300]},
            )
            return 0

        if frame is None or frame.empty:
            # An empty capture window is normal on a quiet interface, not an
            # error. Mark it done so it is not retried forever.
            self._mark_processed(path)
            self.stats.files_processed += 1
            logger.info("pcap_contained_no_flows", extra={"path": path.name})
            return 0

        try:
            self.normalizer.validate_source_columns(frame.columns)
        except Exception as exc:
            self.stats.files_failed += 1
            logger.error(
                "pcap_schema_rejected",
                extra={"path": str(path), "error": str(exc)[:300]},
            )
            return 0

        before_rejected = self.normalizer.stats.rejected
        flows = self.normalizer.normalize_frame(frame)
        self.stats.flows_extracted += len(frame)
        self.stats.flows_rejected += self.normalizer.stats.rejected - before_rejected

        published = self.producer.publish_many(flows)
        self.stats.flows_published += published

        # Marked only after publishing. A crash mid-file replays it, and the
        # producer's flow_id dedup absorbs the overlap — losing flows is worse
        # than briefly duplicating them.
        self._mark_processed(path)
        self.stats.files_processed += 1

        logger.info(
            "pcap_processed",
            extra={
                "path":      path.name,
                "flows":     len(frame),
                "published": published,
                "rejected":  self.stats.flows_rejected,
            },
        )
        return published

    # ── Deduplication of files ────────────────────────────────────────────────

    def already_processed(self, path: Path) -> bool:
        name = path.name
        if name in self._seen:
            return True
        if self.state_client is None:
            return False
        try:
            return bool(self.state_client.sismember(PROCESSED_KEY, name))
        except Exception as exc:
            logger.warning(
                "pcap_processed_check_failed",
                extra={"path": name, "error": str(exc)},
            )
            return False

    def _mark_processed(self, path: Path) -> None:
        name = path.name
        self._seen.add(name)
        if self.state_client is None:
            return
        try:
            self.state_client.sadd(PROCESSED_KEY, name)
            self.state_client.expire(PROCESSED_KEY, PROCESSED_TTL_SECONDS)
        except Exception as exc:
            logger.warning(
                "pcap_processed_mark_failed",
                extra={"path": name, "error": str(exc)},
            )

    # ── Flow extraction ───────────────────────────────────────────────────────

    def _extract_flows(self, path: Path):
        """Run cicflowmeter offline over one pcap and return its flows.

        cicflowmeter writes CSV, so the extraction round-trips through a
        temporary file that is always removed — capture-derived data must not
        accumulate outside the retention window.
        """
        import pandas as pd
        from cicflowmeter.sniffer import create_sniffer

        directory = str(self.work_dir) if self.work_dir else None
        if directory:
            Path(directory).mkdir(parents=True, exist_ok=True)

        handle = tempfile.NamedTemporaryFile(
            suffix=".csv", prefix="cs_flows_", dir=directory, delete=False
        )
        csv_path = Path(handle.name)
        handle.close()

        try:
            sniffer, session = create_sniffer(
                input_file=str(path),
                input_interface=None,
                output_mode="csv",
                output=str(csv_path),
                input_directory=None,
            )
            sniffer.start()
            sniffer.join()
            if hasattr(session, "_gc_stop"):
                session._gc_stop.set()
                session._gc_thread.join(timeout=2.0)
            session.flush_flows()

            if csv_path.stat().st_size == 0:
                return None
            return pd.read_csv(csv_path)
        finally:
            csv_path.unlink(missing_ok=True)
