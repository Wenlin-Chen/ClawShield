import { NavLink, Route, Routes } from "react-router-dom";
import DashboardPage from "./pages/DashboardPage";
import InjectionInspectorPage from "./pages/InjectionInspectorPage";
import RuntimeSimulatorPage from "./pages/RuntimeSimulatorPage";
import SkillScannerPage from "./pages/SkillScannerPage";

function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="eyebrow">Local MVP</p>
          <h1>agent-shield</h1>
          <p className="sidebar-copy">
            Agent antivirus and EDR controls for local OpenClaw-like agents.
          </p>
        </div>
        <nav className="nav">
          <NavLink to="/">Dashboard</NavLink>
          <NavLink to="/scanner">Skill Scanner</NavLink>
          <NavLink to="/runtime">Runtime Broker</NavLink>
          <NavLink to="/injection">Injection Firewall</NavLink>
        </nav>
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/scanner" element={<SkillScannerPage />} />
          <Route path="/runtime" element={<RuntimeSimulatorPage />} />
          <Route path="/injection" element={<InjectionInspectorPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;

