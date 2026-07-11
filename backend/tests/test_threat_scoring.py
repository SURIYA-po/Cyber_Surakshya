from app.services.threat_scoring import ThreatScoring


def test_ddos_is_critical():
    result = ThreatScoring.calculate_score("DDoS")
    assert result["risk"] == "CRITICAL"
    assert result["priority"] == "P1"
    assert result["score"] == 95


def test_malware_is_critical():
    result = ThreatScoring.calculate_score("Malware")
    assert result["risk"] == "CRITICAL"
    assert result["priority"] == "P1"


def test_sql_injection_is_high():
    result = ThreatScoring.calculate_score("SQLInjection")
    assert result["risk"] == "HIGH"
    assert result["priority"] == "P2"


def test_portscan_is_medium():
    result = ThreatScoring.calculate_score("PortScan")
    assert result["risk"] == "MEDIUM"
    assert result["priority"] == "P3"


def test_unknown_attack_defaults_to_low():
    result = ThreatScoring.calculate_score("UnknownAttack")
    assert result["score"] == 50
    assert result["risk"] == "LOW"
