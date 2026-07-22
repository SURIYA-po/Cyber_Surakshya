import { useState } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";

export default function MainLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div style={{ display:"flex", height:"100vh", overflow:"hidden", background:"var(--bg-base)" }}>
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div style={{ flex:1, minWidth:0, display:"flex", flexDirection:"column", overflow:"hidden" }}>
        <Navbar onMenuClick={() => setSidebarOpen(true)} />
        <main className="bg-grid" style={{ flex:1, overflowY:"auto" }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
