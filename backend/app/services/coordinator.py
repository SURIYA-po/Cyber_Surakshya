from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.blocked_ip import BlockedIP

from app.repositories.alert_repository import AlertRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.blocked_repository import BlockedRepository
from app.repositories.agent_repository import AgentRepository

from app.services.attack_generator import AttackGenerator
from app.services.analysis_generator import AnalysisGenerator
from app.services.response_generator import ResponseGenerator
from app.services.threat_scoring import ThreatScoring
from app.services.event_bus import EventBus
from app.services.cache_service import invalidate_stats_cache

REDIS_AGENT_NAME = "Redis Event Bus"


class Coordinator:

    @staticmethod
    async def execute(db: AsyncSession) -> dict:

        # 1. Generate attack data
        attack = AttackGenerator.generate_attack()

        # 2. Calculate threat score
        score = ThreatScoring.calculate_score(attack["attack_type"])

        # 3. Save alert
        alert = Alert(
            attack_type=attack["attack_type"],
            severity=attack["severity"],
            source_ip=attack["source_ip"],
            status="NEW"
        )
        alert = await AlertRepository.create(db, alert)

        # --- publish: simulated_detections -------------------------------
        bus_ok = await EventBus.publish(
            EventBus.CHANNEL_DETECTIONS,
            "detection",
            {
                "alert_id": alert.id,
                "attack_type": attack["attack_type"],
                "source_ip": attack["source_ip"],
                "severity": attack["severity"],
                "threat_score": score,
            }
        )

        # 4. Generate and save analysis
        generated_analysis = AnalysisGenerator.generate(attack)

        analysis = Analysis(
            alert_id=alert.id,
            prediction=generated_analysis["prediction"],
            confidence=generated_analysis["confidence"],
            summary=generated_analysis["summary"]
        )
        analysis = await AnalysisRepository.create(db, analysis)

        # --- publish: simulated_analysis ----------------------------------
        bus_ok = await EventBus.publish(
            EventBus.CHANNEL_ANALYSIS,
            "analysis",
            {
                "alert_id": alert.id,
                "prediction": analysis.prediction,
                "confidence": analysis.confidence,
                "summary": analysis.summary,
            }
        ) and bus_ok

        # 5. Determine and execute response
        response = ResponseGenerator.generate(score)

        blocked = None
        if response["action"] == "Block IP":
            existing = await BlockedRepository.get_by_ip(db, attack["source_ip"])

            if not existing:
                blocked = BlockedIP(
                    ip=attack["source_ip"],
                    reason=analysis.summary
                )
                blocked = await BlockedRepository.create(db, blocked)
            else:
                blocked = existing

        # --- publish: simulated_response -----------------------------------
        bus_ok = await EventBus.publish(
            EventBus.CHANNEL_RESPONSE,
            "response",
            {
                "alert_id": alert.id,
                "action": response["action"],
                "status": response["status"],
                "blocked_ip": blocked.ip if blocked else None,
            }
        ) and bus_ok

        # 6. Update agent heartbeats
        agents = await AgentRepository.get_all(db)
        now = datetime.utcnow()
        for agent in agents:
            agent.heartbeat = now
            if agent.agent_name == REDIS_AGENT_NAME:
                # Real, live signal: did our own publishes above succeed?
                agent.status = "ONLINE" if bus_ok else "OFFLINE"
            else:
                agent.status = "ONLINE"

        await db.commit()

        # Stats numbers just changed — drop the cached summary so the next
        # dashboard read recomputes instead of serving stale totals.
        await invalidate_stats_cache()

        result = {
            "alert": {
                "id": alert.id,
                "attack_type": alert.attack_type,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "status": alert.status,
                "created_at": alert.created_at.isoformat()
            },
            "analysis": {
                "id": analysis.id,
                "alert_id": analysis.alert_id,
                "prediction": analysis.prediction,
                "confidence": analysis.confidence,
                "summary": analysis.summary
            },
            "threat_score": score,
            "response": response,
            "blocked_ip": {
                "id": blocked.id,
                "ip": blocked.ip,
                "reason": blocked.reason,
                "blocked_at": blocked.blocked_at.isoformat()
            } if blocked else None
        }

        # --- publish: dashboard_feed (final, complete alert) ----------------
        # This is what the SSE /feed endpoint forwards to the browser as
        # the "new_alert" event — same shape the old DB-polling code sent,
        # so the existing frontend hook (useLiveFeed) needs no changes.
        await EventBus.publish(
            EventBus.CHANNEL_DASHBOARD,
            "new_alert",
            result["alert"]
        )

        return result
