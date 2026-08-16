import { useMemo } from "react";
import { Database, RefreshCw, Layers, Tag, Clock3, ArrowRight } from "lucide-react";
import { useApi } from "../hooks/useApi";
import { getMemoryInsights } from "../api/memoryApi";

function formatValue(value) {
  if (value == null) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(formatValue).join(", ");
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function SummaryCard({ label, value, icon: Icon }) {
  return (
    <div className="card" style={{ padding: "1rem 1.25rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <p style={{ fontSize: 11, color: "var(--text-secondary)" }}>{label}</p>
        <Icon size={14} color="var(--accent-bright)" />
      </div>
      <p style={{ fontSize: 24, fontWeight: 700, color: "var(--text-primary)" }}>{value}</p>
    </div>
  );
}

export default function Memory() {
  const { data, loading, error, refetch } = useApi(getMemoryInsights);

  const collections = useMemo(() => {
    const raw = data?.collections ?? {};
    return Object.entries(raw).map(([name, value]) => ({
      name,
      count: value?.count ?? 0,
      sample: value?.sample ?? [],
    }));
  }, [data]);

  const totalRecords = collections.reduce((sum, item) => sum + item.count, 0);
  const pipelineSteps = [
    { name: "Detection", count: data?.collections?.detections?.count ?? 0, tone: "#3B82F6" },
    { name: "Analysis", count: data?.collections?.analysis?.count ?? 0, tone: "#F59E0B" },
    { name: "Decision", count: data?.collections?.decisions?.count ?? 0, tone: "#10B981" },
  ];

  return (
    <div className="page">
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>Memory Insights</h1>
          <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>Inspect the shared Qdrant/SQLite memory layer backing the pipeline.</p>
        </div>
        <button className="btn-ghost" onClick={refetch}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="grid-cards-sm" style={{ marginBottom: "1.5rem" }}>
        <SummaryCard label="Provider" value={data?.provider ?? "-"} icon={Database} />
        <SummaryCard label="Collections" value={collections.length} icon={Layers} />
        <SummaryCard label="Stored Records" value={totalRecords} icon={Database} />
      </div>

      {error && (
        <div style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: "var(--radius)", padding: "0.75rem 1rem", fontSize: 12, color: "#FCA5A5", marginBottom: "1rem" }}>
          {error}
        </div>
      )}

      <div className="card" style={{ padding: "1rem 1.25rem", marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.9rem" }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>Pipeline Overview</h2>
          <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>Detection → Analysis → Decision</span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "0.75rem" }}>
          {pipelineSteps.map((step, index) => (
            <div key={step.name} style={{ background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "0.8rem 0.9rem" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>{step.name}</span>
                <span style={{ color: step.tone, fontSize: 11, fontWeight: 700 }}>{step.count}</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--text-secondary)" }}>
                <span>{index === 0 ? "Ingress" : index === 1 ? "Reasoning" : "Action"}</span>
                {index < pipelineSteps.length - 1 && <ArrowRight size={12} color="var(--text-secondary)" />}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: "1.5rem" }}>
        {collections.map((collection) => (
          <div key={collection.name} className="card" style={{ padding: "1rem 1.25rem" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.85rem" }}>
              <h2 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>{collection.name}</h2>
              <span style={{ fontSize: 12, color: "var(--accent-bright)", fontWeight: 600 }}>{collection.count} records</span>
            </div>
            {collection.sample.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>No records stored in this collection yet.</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
                {collection.sample.map((item) => (
                  <div key={item.record_id} style={{ background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "0.7rem 0.8rem" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 4 }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--accent-bright)" }}>{item.record_id}</span>
                      <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>{item.record_type}</span>
                    </div>
                    <p style={{ fontSize: 12, color: "var(--text-primary)", marginBottom: 6, whiteSpace: "pre-wrap" }}>{formatValue(item.content)}</p>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10, color: "var(--text-secondary)" }}>
                        <Clock3 size={10} /> {item.created_at}
                      </span>
                      {item.tags?.length > 0 && (
                        <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10, color: "var(--text-secondary)" }}>
                          <Tag size={10} /> {item.tags.join(", ")}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="card" style={{ padding: "1.25rem" }}>
        <h2 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)", marginBottom: "0.75rem" }}>Recent Records</h2>
        {loading ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {Array.from({ length: 4 }).map((_, i) => <div key={i} className="skeleton" style={{ height: 60 }} />)}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.7rem" }}>
            {(data?.recent_records ?? []).map((record) => (
              <div key={record.record_id} style={{ background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "0.8rem 0.9rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 4 }}>
                  <span className="mono" style={{ fontSize: 11, color: "var(--accent-bright)" }}>{record.record_id}</span>
                  <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>{record.collection}</span>
                </div>
                <p style={{ fontSize: 12, color: "var(--text-primary)", marginBottom: 6, whiteSpace: "pre-wrap" }}>{formatValue(record.content)}</p>
                <p style={{ fontSize: 10, color: "var(--text-secondary)" }}>Entity: {record.entity_id} • Type: {record.record_type}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
