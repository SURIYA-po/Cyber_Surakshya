import json
import time
import requests
import logging
import os
from dotenv import load_dotenv
load_dotenv('/opt/cybersurakshya/config/.env')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/cybersurakshya/logs/suricata_forwarder.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

EVE_LOG = '/var/log/suricata/eve.json'
BIKRAM_URL = os.getenv('BIKRAM_URL', 'https://pipeline-undo-message-flag.trycloudflare.com')
RESPONSE_AGENT = 'http://localhost:8000'

SEVERITY_MAP = {
    1: 'CRITICAL',
    2: 'HIGH',
    3: 'MEDIUM',
    4: 'LOW'
}

ATTACK_TYPE_MAP = {
    'scan': 'PortScan',
    'portscan': 'PortScan',
    'dos': 'DDoS',
    'ddos': 'DDoS',
    'brute': 'BruteForce',
    'bruteforce': 'BruteForce',
    'sql': 'SQLInjection',
    'web': 'SQLInjection',
    'malware': 'Malware',
    'trojan': 'Malware',
    'botnet': 'Malware'
}

def map_attack_type(signature):
    sig_lower = signature.lower()
    for key, value in ATTACK_TYPE_MAP.items():
        if key in sig_lower:
            return value
    return 'PortScan'

def send_to_bikram(alert):
    try:
        attack_type = map_attack_type(alert['alert']['signature'])
        severity = SEVERITY_MAP.get(alert['alert']['severity'], 'MEDIUM')
        source_ip = alert.get('src_ip', '0.0.0.0')

        # Send alert to Bikram's dashboard
        response = requests.post(
            f'{BIKRAM_URL}/alerts',
            json={
                'attack_type': attack_type,
                'severity': severity,
                'source_ip': source_ip,
                'status': 'NEW'
            },
            timeout=10
        )
        if response.status_code == 201:
            logger.info(f"Alert sent to Bikram: {attack_type} from {source_ip}")
        else:
            logger.warning(f"Bikram returned {response.status_code}: {response.text}")

        # If HIGH or CRITICAL also block the IP and add to blocked IPs
        if severity in ['HIGH', 'CRITICAL']:
            # Block via iptables
            requests.post(
                f'{RESPONSE_AGENT}/response/block-ip',
                json={
                    'ip': source_ip,
                    'reason': alert['alert']['signature'],
                    'severity': severity
                },
                timeout=5
            )
            # Add to Bikram's blocked IPs
            requests.post(
                f'{BIKRAM_URL}/blocked-ips',
                json={
                    'ip': source_ip,
                    'reason': f"{alert['alert']['signature']} (Suricata)"
                },
                timeout=10
            )
            logger.warning(f"Blocked IP {source_ip} — {severity} severity")

    except Exception as e:
        logger.error(f"Failed to send to Bikram: {e}")

def tail_eve_log():
    logger.info("Suricata forwarder started — watching eve.json for alerts")
    logger.info(f"Bikram URL: {BIKRAM_URL}")

    with open(EVE_LOG, 'r') as f:
        # Seek to end of file
        f.seek(0, 2)
        logger.info("Waiting for Suricata alerts...")

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line.strip())
                if event.get('event_type') == 'alert':
                    sig = event['alert']['signature']
                    src = event.get('src_ip', '?')
                    sev = event['alert']['severity']
                    logger.warning(f"SURICATA ALERT: {sig} | src: {src} | severity: {sev}")
                    send_to_bikram(event)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")

if __name__ == '__main__':
    tail_eve_log()
