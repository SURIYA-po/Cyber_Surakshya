export const alertDetail = {
  id: "ALT-1001",
  attackType: "SQL Injection",
  severity: "Critical",
  status: "Open",
  sourceIp: "192.168.1.10",
  destination: "Web Server",
  time: "27 Jun 2026, 10:30 AM",
  threatScore: 95,
  confidence: 98,
  riskLevel: "Critical",
  mitre: "T1190",
};

export const analysis = {
  title: "AI Threat Analysis",

  summary:
    "A SQL Injection attack was detected against the login endpoint. The payload indicates an automated exploitation attempt designed to extract sensitive database information. Similar attack patterns have been observed in previous incidents.",

  recommendations: [
    "Block the source IP immediately.",
    "Review web server access logs.",
    "Patch vulnerable application endpoints.",
    "Enable Web Application Firewall rules.",
    "Notify SOC analysts for further investigation.",
  ],
};

export const sourceInfo = {
  country: "Nepal",
  city: "Kathmandu",
  isp: "Demo ISP",
  reputation: "Malicious",
};

export const timeline = [
  {
    time: "10:30",
    event: "Attack Detected",
  },
  {
    time: "10:31",
    event: "Threat Analysis Started",
  },
  {
    time: "10:32",
    event: "Threat Score Calculated",
  },
  {
    time: "10:33",
    event: "Source IP Blocked",
  },
];