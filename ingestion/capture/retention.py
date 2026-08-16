"""Capture retention — a second line of defence behind dumpcap's ring buffer.

``-b files:N`` already bounds a *single* dumpcap run. It does not bound the
directory: a crashed or restarted capture leaves the previous ring in place,
and a changed ``file_prefix`` orphans every file written under the old one.
Two or three restarts is all it takes for a "2 hour retention" directory to
hold a day of traffic nobody is watching.

Capture files are sensitive — even at snaplen 96 they are a full record of who
talked to whom and when. Retention is a security control, not housekeeping.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

PCAP_SUFFIXES = (".pcap", ".pcapng")


@dataclass(frozen=True)
class CaptureFile:
    """One pcap on disk."""

    path:       Path
    size_bytes: int
    modified_at: float

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.modified_at)


@dataclass(frozen=True)
class RetentionResult:
    """Outcome of one sweep. Deletions are always reported, never silent."""

    scanned:       int = 0
    deleted:       int = 0
    bytes_freed:   int = 0
    failed:        int = 0
    remaining:     int = 0
    remaining_bytes: int = 0


def list_capture_files(directory: Path, prefix: str | None = None) -> list[CaptureFile]:
    """Return pcap files in a directory, oldest first."""
    if not directory.is_dir():
        return []
    files: list[CaptureFile] = []
    for path in directory.iterdir():
        if not path.is_file() or path.suffix.lower() not in PCAP_SUFFIXES:
            continue
        if prefix and not path.name.startswith(prefix):
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        files.append(
            CaptureFile(path=path, size_bytes=stat.st_size, modified_at=stat.st_mtime)
        )
    files.sort(key=lambda f: f.modified_at)
    return files


def newest_file(directory: Path, prefix: str | None = None) -> Path | None:
    """Return the file dumpcap is currently writing, if any.

    Phase 3 must never read this one: a truncated final packet silently yields
    a corrupt final flow.
    """
    files = list_capture_files(directory, prefix)
    return files[-1].path if files else None


def sweep(
    directory: Path,
    *,
    prefix: str | None = None,
    max_age_seconds: int | None = None,
    max_total_bytes: int | None = None,
    keep_newest: bool = True,
) -> RetentionResult:
    """Delete capture files beyond the retention window or size ceiling.

    Args:
        keep_newest: never delete the file dumpcap is actively writing.

    Age is enforced first, then total size, oldest-first — so a burst of
    traffic sheds history rather than truncating the present.
    """
    files = list_capture_files(directory, prefix)
    if not files:
        return RetentionResult()

    protected: set[Path] = set()
    if keep_newest:
        protected.add(files[-1].path)

    deleted = failed = 0
    freed = 0
    survivors: list[CaptureFile] = []

    for capture in files:
        expired = (
            max_age_seconds is not None
            and capture.age_seconds > max_age_seconds
            and capture.path not in protected
        )
        if not expired:
            survivors.append(capture)
            continue
        if _delete(capture.path):
            deleted += 1
            freed += capture.size_bytes
        else:
            failed += 1
            survivors.append(capture)

    if max_total_bytes is not None:
        total = sum(c.size_bytes for c in survivors)
        remaining: list[CaptureFile] = list(survivors)
        for capture in list(survivors):
            if total <= max_total_bytes:
                break
            if capture.path in protected:
                continue
            if _delete(capture.path):
                deleted += 1
                freed += capture.size_bytes
                total -= capture.size_bytes
                remaining.remove(capture)
            else:
                failed += 1
        survivors = remaining

    result = RetentionResult(
        scanned=len(files),
        deleted=deleted,
        bytes_freed=freed,
        failed=failed,
        remaining=len(survivors),
        remaining_bytes=sum(c.size_bytes for c in survivors),
    )
    if deleted or failed:
        logger.info(
            "capture_retention_sweep",
            extra={
                "directory":   str(directory),
                "scanned":     result.scanned,
                "deleted":     result.deleted,
                "mb_freed":    round(result.bytes_freed / 1_048_576, 2),
                "failed":      result.failed,
                "remaining":   result.remaining,
            },
        )
    return result


def _delete(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except OSError as exc:
        # A file dumpcap still holds open cannot be removed on Windows. It will
        # be swept on the next pass once the handle is released.
        logger.warning(
            "capture_file_delete_failed",
            extra={"path": str(path), "error": str(exc)},
        )
        return False
