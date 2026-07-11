import { LayoutDashboard, ShieldAlert, Server, Ban, PlayCircle, Settings, X, Shield, Activity } from "lucide-react";
import { NavLink } from "react-router-dom";

const menu = [
  { label:"Overview",  items:[
    { name:"Dashboard",   icon:LayoutDashboard, path:"/" },
    { name:"Simulation",  icon:PlayCircle,       path:"/simulation" },
  ]},
  { label:"Security", items:[
    { name:"Alerts",      icon:ShieldAlert,     path:"/alerts" },
    { name:"Blocked IPs", icon:Ban,             path:"/blocked" },
  ]},
  { label:"System", items:[
    { name:"Agents",      icon:Server,          path:"/agents" },
    { name:"Settings",    icon:Settings,        path:"/settings" },
  ]},
];

export default function Sidebar({ open, onClose }) {
  return (
    <>
      {open && (
        <div
          onClick={onClose}
          style={{
            position:"fixed", inset:0, background:"rgba(0,0,0,0.6)",
            zIndex:30, backdropFilter:"blur(2px)"
          }}
          className="lg:hidden"
        />
      )}

      <aside
        className={`${open ? "translate-x-0" : "-translate-x-full"} lg:translate-x-0`}
        style={{
          position:"fixed", top:0, left:0, zIndex:40,
          display:"flex", flexDirection:"column",
          height:"100vh",
          width:"var(--sidebar-w)",
          background:"var(--bg-surface)",
          borderRight:"1px solid var(--border)",
          transition:"transform 0.25s ease",
        }}
      >
        {/* Logo */}
        <div style={{
          display:"flex", alignItems:"center", justifyContent:"space-between",
          padding:"1rem 1.125rem",
          borderBottom:"1px solid var(--border)",
        }}>
          <div style={{ display:"flex", alignItems:"center", gap:"0.625rem" }}>
            <div style={{
              width:30, height:30, borderRadius:8,
              background:"linear-gradient(135deg,#2563EB,#1D4ED8)",
              display:"flex", alignItems:"center", justifyContent:"center",
              flexShrink:0,
            }}>
              <Shield size={14} color="#fff" />
            </div>
            <div>
              <p style={{ fontSize:12, fontWeight:600, color:"var(--text-primary)", lineHeight:1.2 }}>
                Cyber Surakshya
              </p>
              <p style={{ fontSize:10, color:"var(--text-secondary)", marginTop:1 }}>SOC Platform</p>
            </div>
          </div>
          <button onClick={onClose} className="lg:hidden" style={{ color:"var(--text-secondary)", lineHeight:0 }}>
            <X size={16} />
          </button>
        </div>

        {/* Nav groups */}
        <nav style={{ flex:1, overflowY:"auto", padding:"0.75rem 0.625rem" }}>
          {menu.map(({ label, items }) => (
            <div key={label} style={{ marginBottom:"1.25rem" }}>
              <p style={{
                fontSize:10, fontWeight:600, letterSpacing:"0.08em",
                textTransform:"uppercase", color:"var(--text-muted)",
                padding:"0 0.5rem", marginBottom:"0.375rem",
              }}>
                {label}
              </p>
              <div style={{ display:"flex", flexDirection:"column", gap:2 }}>
                {items.map(({ name, icon:Icon, path }) => (
                  <NavLink
                    key={name}
                    to={path}
                    end={path === "/"}
                    onClick={onClose}
                    style={({ isActive }) => ({
                      display:"flex", alignItems:"center", gap:"0.625rem",
                      padding:"0.5rem 0.625rem",
                      borderRadius:"var(--radius-sm)",
                      fontSize:13, fontWeight:500,
                      transition:"all 0.12s",
                      border:`1px solid ${isActive ? "var(--border-accent)" : "transparent"}`,
                      background: isActive ? "var(--accent-dim)" : "transparent",
                      color: isActive ? "var(--accent-bright)" : "var(--text-secondary)",
                    })}
                  >
                    {({ isActive }) => (
                      <>
                        <Icon size={14} color={isActive ? "var(--accent-bright)" : "var(--text-secondary)"} />
                        {name}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Status footer */}
        <div style={{ padding:"0.875rem 1.125rem", borderTop:"1px solid var(--border)" }}>
          <div style={{ display:"flex", alignItems:"center", gap:"0.5rem" }}>
            <div className="live-dot" style={{ width:12, height:12 }}>
              <span className="live-dot-core" />
            </div>
            <span style={{ fontSize:11, color:"var(--text-secondary)" }}>All systems operational</span>
          </div>
        </div>
      </aside>

      {/* Desktop spacer */}
      <div className="hidden lg:block" style={{ width:"var(--sidebar-w)", flexShrink:0 }} />
    </>
  );
}
