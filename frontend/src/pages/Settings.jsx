import { useState } from "react";
import { Save, CheckCircle2 } from "lucide-react";

export default function Settings() {
  const [apiUrl, setApiUrl] = useState(import.meta.env.VITE_API_BASE_URL || "http://localhost:8000");
  const [saved, setSaved] = useState(false);

  function handleSave(e) {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  }

  return (
    <div className="page">
      <div style={{ marginBottom:"1.5rem" }}>
        <h1 style={{ fontSize:20, fontWeight:700, color:"var(--text-primary)", marginBottom:4 }}>Settings</h1>
        <p style={{ fontSize:12, color:"var(--text-secondary)" }}>Platform preferences and backend connection settings.</p>
      </div>

      <div style={{ maxWidth:520 }}>
        <div className="card" style={{ padding:"1.5rem" }}>
          <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)", marginBottom:"1.25rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
            Backend Connection
          </h2>
          <form onSubmit={handleSave} style={{ display:"flex", flexDirection:"column", gap:"1rem" }}>
            <div>
              <label style={{ display:"block", fontSize:11, color:"var(--text-secondary)", marginBottom:6 }}>
                API Base URL
              </label>
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                className="input-base"
              />
              <p style={{ fontSize:11, color:"var(--text-muted)", marginTop:6 }}>
                Set via <code style={{ fontFamily:"monospace", color:"var(--cyan)" }}>VITE_API_BASE_URL</code> in your <code style={{ fontFamily:"monospace", color:"var(--cyan)" }}>.env</code> file.
              </p>
            </div>

            <div style={{ display:"flex", alignItems:"center", gap:"0.75rem" }}>
              <button type="submit" className="btn-primary">
                <Save size={12} />
                Save Settings
              </button>
              {saved && (
                <div style={{ display:"flex", alignItems:"center", gap:4 }}>
                  <CheckCircle2 size={13} color="#10B981" />
                  <span style={{ fontSize:12, color:"#10B981" }}>Saved</span>
                </div>
              )}
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
