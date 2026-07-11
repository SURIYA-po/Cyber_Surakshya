from app.constants.severity_levels import THREAT_SCORES


class ThreatScoring:

    @staticmethod
    def calculate_score(attack_type: str) -> dict:
        score = THREAT_SCORES.get(attack_type, 50)

        if score >= 90:
            risk = "CRITICAL"
            priority = "P1"
        elif score >= 80:
            risk = "HIGH"
            priority = "P2"
        elif score >= 60:
            risk = "MEDIUM"
            priority = "P3"
        else:
            risk = "LOW"
            priority = "P4"

        return {
            "score": score,
            "risk": risk,
            "priority": priority
        }
