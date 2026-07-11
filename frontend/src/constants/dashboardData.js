import {
  ShieldAlert,
  ShieldCheck,
  Server,
  Ban,
} from "lucide-react";

export const stats = [
  {
    id: 1,
    title: "Total Alerts",
    value: "248",
    change: "+18%",
    icon: ShieldAlert,
    color: "text-red-400",
    bg: "from-red-500/20 to-red-900/10",
  },
  {
    id: 2,
    title: "Critical Threats",
    value: "17",
    change: "+4",
    icon: ShieldCheck,
    color: "text-yellow-400",
    bg: "from-yellow-500/20 to-yellow-900/10",
  },
  {
    id: 3,
    title: "Healthy Agents",
    value: "5",
    change: "100%",
    icon: Server,
    color: "text-green-400",
    bg: "from-green-500/20 to-green-900/10",
  },
  {
    id: 4,
    title: "Blocked IPs",
    value: "92",
    change: "+11",
    icon: Ban,
    color: "text-blue-400",
    bg: "from-blue-500/20 to-blue-900/10",
  },
];



export const agents = [
  {
    id: 1,
    name: "Coordinator",
    status: "Healthy",
    heartbeat: 99,
    cpu: 18,
    memory: 42,
    lastSeen: "Just now",
  },
  {
    id: 2,
    name: "Threat Engine",
    status: "Healthy",
    heartbeat: 96,
    cpu: 25,
    memory: 39,
    lastSeen: "10 sec ago",
  },
  {
    id: 3,
    name: "Response Engine",
    status: "Warning",
    heartbeat: 82,
    cpu: 65,
    memory: 71,
    lastSeen: "1 min ago",
  },
  {
    id: 4,
    name: "Analysis Generator",
    status: "Healthy",
    heartbeat: 94,
    cpu: 22,
    memory: 41,
    lastSeen: "5 sec ago",
  },
];

export const activities = [
  {
    id: 1,
    title: "Attack Generated",
    description: "SQL Injection detected from 192.168.1.10",
    time: "10:30",
    color: "green",
  },
  {
    id: 2,
    title: "Threat Analysis Started",
    description: "AI engine calculating threat score",
    time: "10:31",
    color: "yellow",
  },
  {
    id: 3,
    title: "IP Blocked",
    description: "Firewall blocked malicious IP",
    time: "10:32",
    color: "red",
  },
  {
    id: 4,
    title: "Incident Closed",
    description: "Response workflow completed",
    time: "10:33",
    color: "blue",
  },
];

export const threatTrendData = [
  {
    day: "Mon",
    alerts: 12,
  },
  {
    day: "Tue",
    alerts: 20,
  },
  {
    day: "Wed",
    alerts: 15,
  },
  {
    day: "Thu",
    alerts: 30,
  },
  {
    day: "Fri",
    alerts: 25,
  },
  {
    day: "Sat",
    alerts: 40,
  },
  {
    day: "Sun",
    alerts: 32,
  },
];

export const severityData = [
  { name: "Critical", value: 40 },
  { name: "High", value: 30 },
  { name: "Medium", value: 20 },
  { name: "Low", value: 10 },
];

export const attackTypeData = [
  {
    attack: "SQL Injection",
    count: 35,
  },
  {
    attack: "Brute Force",
    count: 28,
  },
  {
    attack: "DDoS",
    count: 20,
  },
  {
    attack: "XSS",
    count: 15,
  },
  {
    attack: "Malware",
    count: 10,
  },
];

export const recentAlerts = [
  {
    id: "ALT-1001",
    attack: "SQL Injection",
    severity: "Critical",
    source: "192.168.1.10",
    status: "Open",
    time: "2 min ago",
  },
  {
    id: "ALT-1002",
    attack: "Brute Force",
    severity: "High",
    source: "172.16.5.23",
    status: "Investigating",
    time: "5 min ago",
  },
  {
    id: "ALT-1003",
    attack: "Cross Site Scripting",
    severity: "Medium",
    source: "10.10.0.8",
    status: "Monitoring",
    time: "12 min ago",
  },
  {
    id: "ALT-1004",
    attack: "Malware Detection",
    severity: "Low",
    source: "192.168.10.50",
    status: "Resolved",
    time: "20 min ago",
  },
];