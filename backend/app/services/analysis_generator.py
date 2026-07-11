from app.services.threat_scoring import ThreatScoring


class AnalysisGenerator:

    @staticmethod
    def generate(attack: dict) -> dict:
        score = ThreatScoring.calculate_score(attack["attack_type"])

        prediction = attack["attack_type"]
        confidence = min(99.0, float(score["score"] + 3))

        summary = (
            f"Detected a possible {prediction} attack "
            f"originating from {attack['source_ip']}. "
            f"Threat score indicates {score['risk']} risk "
            f"requiring {score['priority']} priority handling."
        )

        return {
            "prediction": prediction,
            "confidence": confidence,
            "summary": summary
        }
