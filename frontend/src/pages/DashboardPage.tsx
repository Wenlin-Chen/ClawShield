import { useEffect, useState } from "react";
import { getEvents, getFindings, loadDemoData } from "../api/client";
import EventTimeline from "../components/EventTimeline";
import FindingsTable from "../components/FindingsTable";
import StatCard from "../components/StatCard";
import type { EventRecord, FindingRecord } from "../types/api";

function DashboardPage() {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [status, setStatus] = useState("Load demo data to populate the audit timeline.");
  const [loading, setLoading] = useState(true);

  async function refresh() {
    setLoading(true);
    try {
      const [eventsData, findingsData] = await Promise.all([getEvents(), getFindings()]);
      setEvents(eventsData);
      setFindings(findingsData);
      setStatus("Audit trail refreshed.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function handleLoadDemo() {
    setLoading(true);
    try {
      const result = await loadDemoData();
      setStatus(result.message);
      await refresh();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed to load sample data.");
      setLoading(false);
    }
  }

  const blockedEvents = events.filter((event) => event.decision === "block").length;
  const highFindings = findings.filter((finding) =>
    ["high", "critical"].includes(finding.severity),
  ).length;

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Audit Console</p>
          <h2>Recent sessions, alerts, and blocked actions</h2>
        </div>
        <div className="actions">
          <button onClick={() => void handleLoadDemo()}>Load demo data</button>
          <button className="button-secondary" onClick={() => void refresh()}>
            Refresh
          </button>
        </div>
      </header>

      <div className="stats-grid">
        <StatCard label="Stored events" value={events.length} />
        <StatCard label="Blocked actions" value={blockedEvents} tone="danger" />
        <StatCard label="High findings" value={highFindings} tone="warning" />
      </div>

      <p className="status">{loading ? "Loading..." : status}</p>

      <div className="grid-two">
        <section className="card panel">
          <h3>Recent findings</h3>
          <FindingsTable findings={findings.slice(0, 8)} />
        </section>
        <section className="panel">
          <h3>Session timeline</h3>
          <EventTimeline events={events.slice(0, 6)} />
        </section>
      </div>
    </section>
  );
}

export default DashboardPage;

