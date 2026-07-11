import random

from app.constants.attack_types import ATTACK_TYPES, SEVERITY_MAPPING


class AttackGenerator:

    @staticmethod
    def generate_attack() -> dict:
        attack_type = random.choice(ATTACK_TYPES)

        source_ip = ".".join(
            str(random.randint(1, 255)) for _ in range(4)
        )

        severity = SEVERITY_MAPPING[attack_type]

        return {
            "attack_type": attack_type,
            "source_ip": source_ip,
            "severity": severity
        }
