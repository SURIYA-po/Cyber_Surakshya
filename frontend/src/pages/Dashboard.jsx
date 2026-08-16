import { useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck, Server, Ban, RefreshCw } from "lucide-react";
import StatCard from "../components/cards/StatCard";
import Panel from "../components/common/Panel";
import ThreatStatus from "../components/panels/ThreatStatus";
import RecentAlerts from "../components/panels/RecentAlerts";
import AgentHealth from "../components/panels/AgentHealth";
import ActivityTimeline from "../components/panels/ActivityTimeline";
import PlatformStatus from "../components/panels/PlatformStatus";
import ThreatTrendChart from "../components/charts/ThreatTrendChart";
import AttackTypeChart from "../components/charts/AttackTypeChart";
import SeverityChart from "../components/charts/SeverityChart";
import { getStats } from "../api/dashboardApi";

function buildCards(stats) {
  const total   = stats.total_alerts ?? 0;
  const sample  = stats.breakdown_sample_size ?? total;
  const online  = stats.online_agents ?? 0;
  const agents  = stats.total_agents ?? 0;

  // The severity breakdown is computed over the newest page, not the whole
  // history. Saying "0 critical" against a total of 999 would read as a fact
  // about all 999, so the scope is stated whenever the sample is smaller.
  const scoped = (text) => (sample < total ? `${text} (newest ${sample})` : text);

  return [
    { id:1, title:"Total Alerts",     value:String(total),
      change:scoped(`${stats.severity_breakdown?.CRITICAL ?? 0} critical`),
      icon:ShieldAlert, accentColor:"#EF4444" },
    { id:2, title:"Critical Threats", value:String(stats.severity_breakdown?.CRITICAL ?? 0),
      change:scoped(`${stats.severity_breakdown?.HIGH ?? 0} high`),
      icon:ShieldCheck, accentColor:"#F59E0B" },
    { id:3, title:"Online Agents",    value:`${online}/${agents}`,
      change: online === agents && agents > 0 ? "all systems online" : `${agents - online} offline`,
      icon:Server, accentColor: online === agents ? "#10B981" : "#F59E0B" },
    { id:4, title:"Blocked IPs",      value:String(stats.total_blocked_ips ?? 0),
      change:`avg ${stats.average_confidence ?? 0}% AI confidence`,
      icon:Ban, accentColor:"#3B82F6" },
  ];
}

export default function Dashboard() {
  const [stats, setStats]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchStats = () => {
    getStats()
      .then((d) => { setStats(d); setLastRefresh(new Date()); })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchStats();
    const t = setInterval(fetchStats, 10000);
    return () => clearInterval(t);
  }, []);

  const cards = stats ? buildCards(stats) : [];

  return (
    <div className="page" style={{ maxWidth:"none" }}>
      {/* Header */}
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:"1.5rem" }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:700, color:"var(--text-primary)", marginBottom:4 }}>Dashboard</h1>
          <p style={{ fontSize:12, color:"var(--text-secondary)" }}>
            {lastRefresh ? `Last updated ${lastRefresh.toLocaleTimeString()}` : "Loading…"}
          </p>
        </div>
        <button className="btn-ghost" onClick={fetchStats} style={{ gap:5 }}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Ingestion, approvals, and self-measurement — each links to the page
          that can act on it. */}
      <PlatformStatus />

      {/* Stat cards */}
      <div className="grid-cards" style={{ marginBottom:"1.5rem" }}>
        {loading
          ? Array.from({length:4}).map((_,i) => (
              <div key={i} className="skeleton" style={{ height:110 }} />
            ))
          : cards.map((c) => <StatCard key={c.id} {...c} />)
        }
      </div>

      {/* Charts row */}
      <div className="grid-dashboard" style={{ marginBottom:"1.5rem" }}>
        <Panel title="Threat Analytics" accent="#3B82F6">
          <div className="grid-analysis" style={{ marginBottom:"1.25rem" }}>
            <div>
              <p className="section-title" style={{ marginBottom:10 }}>Severity Distribution</p>
              <SeverityChart stats={stats} />
            </div>
            <div>
              <p className="section-title" style={{ marginBottom:10 }}>Threat Trend</p>
              <ThreatTrendChart stats={stats} />
            </div>
          </div>
          <div>
            <p className="section-title" style={{ marginBottom:10 }}>Attack Types</p>
            <AttackTypeChart stats={stats} />
          </div>
        </Panel>
        <ThreatStatus stats={stats} />
      </div>

      {/* Bottom panels */}
      <div className="grid-2" style={{ marginBottom:"1.5rem" }}>
        <RecentAlerts />
        <AgentHealth />
      </div>

      <ActivityTimeline />
    </div>
  );
}
