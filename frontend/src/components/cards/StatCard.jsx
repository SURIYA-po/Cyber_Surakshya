import { motion } from "framer-motion";
import { TrendingUp } from "lucide-react";

export default function StatCard({ title, value, change, icon:Icon, accentColor="#3B82F6" }) {
  return (
    <motion.div
      whileHover={{ y:-3, borderColor:"var(--border-hover)" }}
      transition={{ duration:0.18 }}
      style={{
        background:"var(--bg-card)",
        border:"1px solid var(--border)",
        borderRadius:"var(--radius-lg)",
        padding:"1.125rem 1.25rem",
        position:"relative",
        overflow:"hidden",
        cursor:"default",
      }}
    >
      {/* top accent line */}
      <div style={{
        position:"absolute", top:0, left:0, right:0, height:2,
        background:`linear-gradient(90deg,${accentColor}CC,transparent)`,
      }} />

      {/* faint circle glow behind icon */}
      <div style={{
        position:"absolute", top:-20, right:-20,
        width:80, height:80, borderRadius:"50%",
        background:`radial-gradient(circle, ${accentColor}18 0%, transparent 70%)`,
      }} />

      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:"0.75rem" }}>
        <p className="section-title">{title}</p>
        <div style={{
          width:32, height:32, borderRadius:"var(--radius-sm)",
          background:`${accentColor}14`,
          border:`1px solid ${accentColor}28`,
          display:"flex", alignItems:"center", justifyContent:"center",
          flexShrink:0,
        }}>
          <Icon size={14} color={accentColor} />
        </div>
      </div>

      <p style={{ fontSize:28, fontWeight:700, color:"var(--text-primary)", lineHeight:1, marginBottom:"0.5rem" }}>
        {value}
      </p>

      <div style={{ display:"flex", alignItems:"center", gap:4 }}>
        <TrendingUp size={10} color="var(--green)" />
        <span style={{ fontSize:11, color:"var(--text-secondary)" }}>{change}</span>
      </div>
    </motion.div>
  );
}
