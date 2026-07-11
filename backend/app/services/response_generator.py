from app.constants.response_actions import RESPONSE_ACTIONS, SUCCESS_STATUS


class ResponseGenerator:

    @staticmethod
    def generate(score_data: dict) -> dict:
        risk = score_data["risk"]
        action = RESPONSE_ACTIONS.get(risk, "Monitor")

        return {
            "action": action,
            "status": SUCCESS_STATUS
        }
