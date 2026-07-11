import BlockedIpRow from "./BlockedIpRow";

const HEADERS = ["IP Address","Country","Reason","Severity","Blocked At","Status",""];

export default function BlockedIpTable({ blockedIps }) {
  if (blockedIps.length === 0) {
    return (
      <div style={{ textAlign:"center", padding:"3rem 0", color:"var(--text-secondary)", fontSize:13 }}>
        No blocked IPs found.
      </div>
    );
  }
  return (
    <div style={{ overflowX:"auto", borderRadius:"var(--radius)", border:"1px solid var(--border)" }}>
      <table style={{ width:"100%", borderCollapse:"collapse" }}>
        <thead>
          <tr style={{ background:"var(--bg-surface)", borderBottom:"1px solid var(--border)" }}>
            {HEADERS.map((h, i) => (
              <th key={i} style={{
                padding:"0.625rem 1rem", textAlign:"left",
                fontSize:10, fontWeight:600,
                letterSpacing:"0.08em", textTransform:"uppercase",
                color:"var(--text-secondary)", whiteSpace:"nowrap",
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {blockedIps.map((ip) => <BlockedIpRow key={ip.id} ip={ip} />)}
        </tbody>
      </table>
    </div>
  );
}
