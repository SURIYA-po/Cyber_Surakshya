import { Link } from "react-router-dom";
import SeverityBadge from "./SeverityBadge";
import StatusBadge from "./StatusBadge";
import { ArrowRight } from "lucide-react";

export default function AlertRow({ alert }) {
  return (
    <tr className="trow" style={{ borderBottom:"1px solid var(--border)" }}>
      <td style={{ padding:"0.75rem 1rem" }}>
        <span className="mono" style={{ color:"var(--accent-bright)", fontSize:11 }}>#{alert.id}</span>
      </td>
      <td style={{ padding:"0.75rem 1rem" }}>
        <span style={{ fontSize:13, color:"var(--text-primary)", fontWeight:500 }}>{alert.attackType}</span>
      </td>
      <td style={{ padding:"0.75rem 1rem" }}>
        <SeverityBadge severity={alert.severity} />
      </td>
      <td style={{ padding:"0.75rem 1rem" }}>
        <span className="mono" style={{ fontSize:11, color:"var(--text-secondary)" }}>{alert.sourceIp}</span>
      </td>
      <td style={{ padding:"0.75rem 1rem" }}>
        <StatusBadge status={alert.status} />
      </td>
      <td style={{ padding:"0.75rem 1rem" }}>
        <span style={{ fontSize:11, color:"var(--text-secondary)" }}>{alert.time}</span>
      </td>
      <td style={{ padding:"0.75rem 1rem" }}>
        <Link
          to={`/alerts/${alert.id}`}
          style={{
            display:"inline-flex", alignItems:"center", gap:4,
            padding:"4px 10px", borderRadius:"var(--radius-sm)",
            fontSize:11, fontWeight:500,
            background:"var(--accent-dim)",
            border:"1px solid var(--border-accent)",
            color:"var(--accent-bright)",
            transition:"background 0.12s",
          }}
        >
          View <ArrowRight size={10} />
        </Link>
      </td>
    </tr>
  );
}
