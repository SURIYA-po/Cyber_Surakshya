import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
const COLORS = ["#3B82F6","#8B5CF6","#06B6D4","#10B981","#F59E0B","#EF4444"];
const EMPTY = <div style={{display:"flex",alignItems:"center",justifyContent:"center",height:180,fontSize:12,color:"var(--text-secondary)"}}>No data — run a simulation</div>;

export default function AttackTypeChart({ stats }) {
  const data = stats?.attack_type_breakdown
    ? Object.entries(stats.attack_type_breakdown).map(([attack,count]) => ({ attack, count }))
    : [];
  if (!data.length) return EMPTY;
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} barCategoryGap="30%">
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={true} vertical={false} />
        <XAxis dataKey="attack" stroke="var(--text-muted)" tick={{ fontSize:10 }} axisLine={false} tickLine={false} />
        <YAxis stroke="var(--text-muted)" tick={{ fontSize:10 }} axisLine={false} tickLine={false} width={20} />
        <Tooltip contentStyle={{ background:"var(--bg-surface)", border:"1px solid var(--border)", borderRadius:8, fontSize:12 }} />
        <Bar dataKey="count" radius={[4,4,0,0]}>
          {data.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
