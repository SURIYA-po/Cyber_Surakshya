import os
import subprocess
import logging
import redis
import threading
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv('/opt/cybersurakshya/config/.env')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/cybersurakshya/logs/response-agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Cyber Surakshya Response Agent")

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')
LOCAL_RULES = '/etc/suricata/rules/local.rules'

class BlockRequest(BaseModel):
    ip: str
    reason: str = ""
    severity: str = "medium"

class UnblockRequest(BaseModel):
    ip: str

class SuricataRuleRequest(BaseModel):
    rule: str

class NotifyRequest(BaseModel):
    message: str
    severity: str = "info"

@app.get("/health")
def health():
    return {"status": "ok", "service": "response-agent"}

@app.post("/response/block-ip")
def block_ip(req: BlockRequest):
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", req.ip, "-j", "DROP"],
            check=True
        )
        logger.info(f"Blocked IP: {req.ip} | Reason: {req.reason} | Severity: {req.severity}")
        return {"status": "blocked", "ip": req.ip}
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP {req.ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/response/unblock-ip")
def unblock_ip(req: UnblockRequest):
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", req.ip, "-j", "DROP"],
            check=True
        )
        logger.info(f"Unblocked IP: {req.ip}")
        return {"status": "unblocked", "ip": req.ip}
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to unblock IP {req.ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/response/active-blocks")
def active_blocks():
    result = subprocess.run(
        ["iptables", "-L", "INPUT", "-n"],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    blocked = [l.split()[3] for l in lines if "DROP" in l and len(l.split()) > 3]
    return {"blocked_ips": blocked}

@app.post("/response/add-suricata-rule")
def add_suricata_rule(req: SuricataRuleRequest):
    try:
        with open(LOCAL_RULES, 'a') as f:
            f.write(req.rule + '\n')
        subprocess.run(["kill", "-USR2", "$(pidof suricata)"], shell=True)
        logger.info(f"Added Suricata rule: {req.rule}")
        return {"status": "rule added"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/response/notify")
def notify(req: NotifyRequest):
    logger.info(f"NOTIFICATION [{req.severity.upper()}]: {req.message}")
    if WEBHOOK_URL:
        try:
            requests.post(WEBHOOK_URL, json={"message": req.message, "severity": req.severity}, timeout=5)
        except Exception as e:
            logger.warning(f"Webhook failed: {e}")
    return {"status": "notified"}

def redis_subscriber():
    try:
        r = redis.from_url(REDIS_URL)
        pubsub = r.pubsub()
        pubsub.subscribe('channel:response_command')
        logger.info("Redis subscriber started")
        for message in pubsub.listen():
            if message['type'] == 'message':
                logger.info(f"Redis command received: {message['data']}")
    except Exception as e:
        logger.warning(f"Redis not available: {e}")

@app.on_event("startup")
def startup():
    t = threading.Thread(target=redis_subscriber, daemon=True)
    t.start()
