import time
import shutil
import requests
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/cybersurakshya/logs/batch_uploader.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

CONN_LOG = '/opt/zeek/spool/zeek/conn.log'
SNAPSHOT_PATH = '/tmp/conn_snapshot.log'
SURYA_URL = os.getenv('SURYA_URL', 'https://powerseller-tutorial-produces-annex.trycloudflare.com/predict/zeek')
SURYA_API_KEY = 'cyber-surakshya-secret-key'
BIKRAM_URL = os.getenv('BIKRAM_URL', 'https://pipeline-undo-message-flag.trycloudflare.com')
CONFIDENCE_THRESHOLD = 0.50
UPLOAD_INTERVAL = 30

LABEL_MAP = {
    'PORTSCAN': 'PortScan',
    'DDOS': 'DDoS',
    'DOS': 'DDoS',
    'BRUTEFORCE': 'BruteForce',
    'BOTNET': 'Malware',
    'WEBATTACK': 'SQLInjection',
    'INFILTRATION': 'Malware'
}

SEVERITY_MAP = {
    'PortScan': 'MEDIUM',
    'DDoS': 'CRITICAL',
    'BruteForce': 'HIGH',
    'Malware': 'CRITICAL',
    'SQLInjection': 'HIGH'
}

def take_snapshot():
    try:
        shutil.copy2(CONN_LOG, SNAPSHOT_PATH)
        os.chmod(SNAPSHOT_PATH, 0o644)
        logger.info(f"Snapshot taken: {SNAPSHOT_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to take snapshot: {e}")
        return False

def upload_to_surya():
    try:
        with open(SNAPSHOT_PATH, 'rb') as f:
            response = requests.post(
                'https://powerseller-tutorial-produces-annex.trycloudflare.com/predict/zeek',
                headers={'X-API-Key': 'cyber-surakshya-secret-key'},
                files={'file': ('conn.log', f, 'text/plain')},
                timeout=30
            )
        if response.status_code == 200:
            raw = response.json()
            predictions = raw.get("predictions", raw) if isinstance(raw, dict) else raw
            logger.info(f"Got {len(predictions)} predictions from Surya")
            return predictions
        else:
            logger.error(f"Surya returned {response.status_code}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to reach Surya: {e}")
        return None

def process_predictions(predictions):
    threats = []
    predictions = predictions if isinstance(predictions, list) else [predictions]
    for record in predictions:
        label = record.get('prediction', 'BENIGN')
        confidence = record.get('confidence', 0)
        source_ip = record.get('source_ip', '')
        if label == 'BENIGN':
            continue
        if confidence < CONFIDENCE_THRESHOLD:
            logger.info(f"Low confidence {label} ({confidence:.2f}) for {source_ip} -- skipping")
            continue
        threats.append({
            'label': label,
            'confidence': confidence,
            'source_ip': source_ip,
            'attack_type': LABEL_MAP.get(label, 'Malware'),
            'severity': SEVERITY_MAP.get(LABEL_MAP.get(label, 'Malware'), 'MEDIUM')
        })
        logger.warning(f"THREAT DETECTED: {label} ({confidence:.2%}) from {source_ip}")
    return threats

def block_ip(ip, reason, severity):
    try:
        response = requests.post(
            'http://localhost:8000/response/block-ip',
            json={'ip': ip, 'reason': reason, 'severity': severity},
            timeout=5
        )
        if response.status_code == 200:
            logger.info(f"Blocked IP {ip} via Response Agent")
            return True
        else:
            logger.error(f"Response Agent returned {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Failed to call Response Agent: {e}")
        return False

def notify_bikram(threat):
    try:
        response = requests.post(
            'http://localhost:8000/alerts',
            json={
                'attack_type': threat['attack_type'],
                'severity': threat['severity'],
                'source_ip': threat['source_ip'],
                'status': 'NEW'
            },
            timeout=5
        )
        if response.status_code == 201:
            logger.info(f"Alert sent to Bikram for {threat['source_ip']}")
        if threat['severity'] in ['HIGH', 'CRITICAL']:
            requests.post(
                'http://localhost:8000/blocked-ips',
                json={
                    'ip': threat['source_ip'],
                    'reason': f"{threat['label']} detected with {threat['confidence']:.2%} confidence"
                },
                timeout=5
            )
    except Exception as e:
        logger.warning(f"Could not reach Bikram: {e}")

def run_cycle():
    logger.info("--- Starting detection cycle ---")
    if not take_snapshot():
        return
    predictions = None  # Surya temporarily disabled
    if not predictions:
        return
    threats = process_predictions(predictions)
    if not threats:
        logger.info("No threats detected -- all BENIGN")
        return
    logger.warning(f"Found {len(threats)} threats!")
    for threat in threats:
        block_ip(
            threat['source_ip'],
            f"{threat['label']} detected with {threat['confidence']:.2%} confidence",
            threat['severity']
        )
        notify_bikram(threat)

if __name__ == '__main__':
    logger.info("Batch uploader started -- uploading every 30 seconds")
    logger.info(f"Surya URL: https://powerseller-tutorial-produces-annex.trycloudflare.com/predict/zeek")
    logger.info(f"Confidence threshold: {CONFIDENCE_THRESHOLD}")
    while True:
        try:
            run_cycle()
        except Exception as e:
            logger.error(f"Cycle failed: {e}")
        time.sleep(UPLOAD_INTERVAL)
