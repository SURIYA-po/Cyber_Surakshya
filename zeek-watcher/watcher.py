import time
import json
import requests
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/cybersurakshya/logs/watcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

CONN_LOG = '/opt/zeek/logs/current/conn.log'
DETECTION_API = 'http://localhost:8001/detect'

FIELDS = [
    'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p',
    'proto', 'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'orig_pkts', 'resp_pkts'
]

class ConnLogHandler(FileSystemEventHandler):
    def __init__(self):
        self._file = open(CONN_LOG, 'r')
        self._file.seek(0, 2)
        logger.info("Zeek watcher started — tailing conn.log")

    def on_modified(self, event):
        if event.src_path != CONN_LOG:
            return
        for line in self._file:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                payload = {k: record.get(k) for k in FIELDS}
                requests.post(DETECTION_API, json=payload, timeout=5)
                logger.info(f"Forwarded: {payload.get('id.orig_h')} -> {payload.get('id.resp_h')}")
            except json.JSONDecodeError:
                logger.warning(f"Skipped non-JSON line: {line[:80]}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed to forward to Detection API: {e}")

if __name__ == '__main__':
    event_handler = ConnLogHandler()
    observer = Observer()
    observer.schedule(event_handler, path='/opt/zeek/logs/current/', recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
