ATTACK_TYPES = [
    "PortScan",
    "DDoS",
    "BruteForce",
    "SQLInjection",
    "Malware",
    "Phishing"
]

SEVERITY_MAPPING = {
    "PortScan": "MEDIUM",
    "BruteForce": "HIGH",
    "SQLInjection": "HIGH",
    "Malware": "CRITICAL",
    "DDoS": "CRITICAL",
    "Phishing": "MEDIUM"
}
