from app.services.attack_generator import AttackGenerator
from app.constants.attack_types import ATTACK_TYPES


def test_generate_attack_returns_required_keys():
    attack = AttackGenerator.generate_attack()
    assert "attack_type" in attack
    assert "source_ip" in attack
    assert "severity" in attack


def test_attack_type_is_valid():
    for _ in range(20):
        attack = AttackGenerator.generate_attack()
        assert attack["attack_type"] in ATTACK_TYPES


def test_source_ip_format():
    attack = AttackGenerator.generate_attack()
    parts = attack["source_ip"].split(".")
    assert len(parts) == 4
    assert all(1 <= int(p) <= 255 for p in parts)


def test_severity_is_valid():
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    for _ in range(20):
        attack = AttackGenerator.generate_attack()
        assert attack["severity"] in valid_severities
