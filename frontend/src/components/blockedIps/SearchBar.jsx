import { Search } from "lucide-react";

export default function SearchBar({ searchTerm, setSearchTerm }) {
  return (
    <div style={{
      display:"flex", alignItems:"center", gap:8,
      padding:"0.5rem 0.875rem",
      borderRadius:"var(--radius)",
      background:"var(--bg-input)",
      border:"1px solid var(--border-strong)",
      flex:1, maxWidth:380,
    }}>
      <Search size={13} color="var(--text-muted)" />
      <input
        type="text"
        placeholder="Search by IP, country, or reason…"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        style={{
          background:"transparent", border:"none", outline:"none",
          fontSize:13, color:"var(--text-primary)", width:"100%",
        }}
      />
    </div>
  );
}
