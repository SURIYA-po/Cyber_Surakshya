import { Bell, Search, Menu, Shield } from "lucide-react";
import { useLiveFeed } from "../../hooks/useLiveFeed";

export default function Navbar({ onMenuClick }) {
  const { alerts: liveAlerts, connected } = useLiveFeed(99);

  return (
    <header style={{
      height:"var(--navbar-h)",
      background:"var(--bg-surface)",
      borderBottom:"1px solid var(--border)",
      display:"flex", alignItems:"center",
      padding:"0 1.25rem",
      gap:"0.75rem",
      flexShrink:0,
    }}>
      {/* Mobile menu */}
      <button
        onClick={onMenuClick}
        className="lg:hidden"
        style={{ color:"var(--text-secondary)", lineHeight:0, marginRight:4 }}
      >
        <Menu size={18} />
      </button>

      {/* Page context */}
      <div style={{ flex:1, minWidth:0 }}>
        <p style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)" }}>
          Security Operations Center
        </p>
        <p className="hidden sm:block" style={{ fontSize:11, color:"var(--text-secondary)", marginTop:1 }}>
          Real-time threat monitoring
        </p>
      </div>

      {/* Right controls */}
      <div style={{ display:"flex", alignItems:"center", gap:"0.625rem", flexShrink:0 }}>
        {/* Search */}
        <div
          className="hidden md:flex"
          style={{
            alignItems:"center", gap:6,
            padding:"0.35rem 0.75rem",
            borderRadius:"var(--radius)",
            background:"var(--bg-input)",
            border:"1px solid var(--border-strong)",
          }}
        >
          <Search size={12} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search alerts, IPs…"
            className="input-base"
            style={{
              background:"transparent", border:"none", padding:0,
              width:140, fontSize:12, color:"var(--text-primary)",
            }}
          />
        </div>

        {/* Live feed status */}
        <div style={{
          display:"flex", alignItems:"center", gap:5,
          padding:"0.3rem 0.625rem",
          borderRadius:"var(--radius)",
          background: connected ? "var(--green-dim)" : "var(--red-dim)",
          border:`1px solid ${connected ? "rgba(16,185,129,0.25)" : "rgba(239,68,68,0.25)"}`,
        }}>
          {connected ? (
            <div className="live-dot" style={{ width:10, height:10 }}>
              <span className="live-dot-core" style={{ width:5, height:5 }} />
            </div>
          ) : (
            <span style={{ width:5, height:5, borderRadius:"50%", background:"var(--red)", display:"inline-block" }} />
          )}
          <span style={{ fontSize:10, fontWeight:600, color: connected ? "var(--green)" : "var(--red)" }}>
            {connected ? "LIVE" : "OFFLINE"}
          </span>
        </div>

        {/* Bell */}
        <button style={{
          position:"relative", width:32, height:32,
          borderRadius:"var(--radius-sm)",
          background:"var(--bg-card)",
          border:"1px solid var(--border-strong)",
          display:"flex", alignItems:"center", justifyContent:"center",
          color:"var(--text-secondary)",
        }}>
          <Bell size={14} />
          {liveAlerts.length > 0 && (
            <span style={{
              position:"absolute", top:5, right:5,
              width:6, height:6, borderRadius:"50%",
              background:"var(--red)",
            }} />
          )}
        </button>

        {/* Avatar */}
        <div style={{
          width:30, height:30, borderRadius:"var(--radius-sm)",
          background:"linear-gradient(135deg,#2563EB,#7C3AED)",
          display:"flex", alignItems:"center", justifyContent:"center",
          fontSize:10, fontWeight:700, color:"#fff", letterSpacing:"0.05em",
        }}>
          SOC
        </div>
      </div>
    </header>
  );
}
