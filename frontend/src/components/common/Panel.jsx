import { motion } from "framer-motion";

export default function Panel({ title, children, className = "", action, accent }) {
  return (
    <motion.div
      initial={{ opacity:0, y:10 }}
      animate={{ opacity:1, y:0 }}
      transition={{ duration:0.25, ease:"easeOut" }}
      className={`card ${className}`}
      style={{ padding:"1.25rem", position:"relative", overflow:"hidden" }}
    >
      {accent && (
        <div style={{
          position:"absolute", top:0, left:0, right:0, height:2,
          background:`linear-gradient(90deg, ${accent}, transparent)`,
          borderRadius:"var(--radius-lg) var(--radius-lg) 0 0",
        }} />
      )}
      {title && (
        <div style={{
          display:"flex", alignItems:"center", justifyContent:"space-between",
          marginBottom:"1rem", paddingBottom:"0.75rem",
          borderBottom:"1px solid var(--border)",
        }}>
          <h2 style={{ fontSize:12, fontWeight:600, color:"var(--text-primary)", letterSpacing:"0.01em" }}>
            {title}
          </h2>
          {action}
        </div>
      )}
      {children}
    </motion.div>
  );
}
