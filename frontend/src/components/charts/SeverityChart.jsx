import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
const COLORS = ["#EF4444","#F97316","#F59E0B","#10B981"];
const EMPTY = <div style={{display:"flex",alignItems:"center",justifyContent:"center",height:180,fontSize:12,color:"var(--text-secondary)"}}>No data — run a simulation</div>;

export default function SeverityChart({ stats }) {
  const data = stats?.severity_breakdown
    ? Object.entries(stats.severity_breakdown).map(([name,value]) => ({ name, value }))
    : [];
  if (!data.length) return EMPTY;
  return (
    <ResponsiveContainer width="100%" height={180}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={40} outerRadius={70} paddingAngle={3}>
          {data.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}
        </Pie>
        <Tooltip contentStyle={{ background:"var(--bg-surface)", border:"1px solid var(--border)", borderRadius:8, fontSize:12 }} />
        <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize:11 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}
