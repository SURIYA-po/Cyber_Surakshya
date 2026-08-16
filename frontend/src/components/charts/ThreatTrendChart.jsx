import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from "recharts";
const DAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
const EMPTY = <div style={{display:"flex",alignItems:"center",justifyContent:"center",height:180,fontSize:12,color:"var(--text-secondary)"}}>No data — run a simulation</div>;

export default function ThreatTrendChart({ stats }) {
  const trend = Array.isArray(stats?.trend) && stats.trend.length ? stats.trend : [];
  if (!stats?.total_alerts && !trend.length) return EMPTY;

  const data = trend.length
    ? trend.map((point) => ({ day: point.label, alerts: Number(point.value) || 0 }))
    : DAYS.map((day, i) => ({ day, alerts: i === 6 ? stats.total_alerts : 0 }));

  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#3B82F6" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}   />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="day" stroke="var(--text-muted)" tick={{ fontSize:10 }} axisLine={false} tickLine={false} />
        <YAxis stroke="var(--text-muted)" tick={{ fontSize:10 }} axisLine={false} tickLine={false} width={24} />
        <Tooltip contentStyle={{ background:"var(--bg-surface)", border:"1px solid var(--border)", borderRadius:8, fontSize:12 }} />
        <Area type="monotone" dataKey="alerts" stroke="#3B82F6" strokeWidth={2} fill="url(#alertGrad)" dot={{ r:3, fill:"#3B82F6" }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
