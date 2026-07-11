import { Link } from "react-router-dom";
import SeverityBadge from "./SeverityBadge";
import StatusBadge from "./StatusBadge";
import { ArrowRight } from "lucide-react";

export default function BlockedIpRow({ ip }) {
  return (
    <tr className="trow" style={{ borderBottom:"1px solid var(--border)" }}>
      <td style={{ padding:"0.75rem 1rem" }}>
        <span className="mono" style={{ fontSize:11, color:"#FCA5A5", fontWeight:500 }}>{ip.ip}</span>
      </td>
      <td style={{ padding:"0.75rem 1rem", fontSize:12, color:"var(--text-secondary)" }}>{ip.country}</td>
      <td style={{ padding:"0.75rem 1rem", fontSize:12, color:"var(--text-primary)", maxWidth:200 }}>
        <span style={{ display:"block", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
          {ip.reason}
        </span>
      </td>
      <td style={{ padding:"0.75rem 1rem" }}><SeverityBadge severity={ip.severity} /></td>
      <td style={{ padding:"0.75rem 1rem", fontSize:11, color:"var(--text-secondary)" }}>{ip.blockedAt}</td>
      <td style={{ padding:"0.75rem 1rem" }}><StatusBadge status={ip.status} /></td>
      <td style={{ padding:"0.75rem 1rem" }}>
        <Link to={`/blocked/${ip.id}`} style={{
          display:"inline-flex", alignItems:"center", gap:4,
          padding:"4px 10px", borderRadius:"var(--radius-sm)",
          fontSize:11, fontWeight:500,
          background:"var(--accent-dim)",
          border:"1px solid var(--border-accent)",
          color:"var(--accent-bright)",
        }}>
          View <ArrowRight size={10} />
        </Link>
      </td>
    </tr>
  );
}
