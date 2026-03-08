import { useEffect, useState } from "react";
import { clearHistory, getEvents, getFindings } from "../api/client";
import EventTimeline from "../components/EventTimeline";
import FindingsTable from "../components/FindingsTable";
import StatCard from "../components/StatCard";
import type { EventRecord, FindingRecord } from "../types/api";

function DashboardPage() {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [status, setStatus] = useState("No audit history yet. Scans and policy checks will appear here.");
  const [loading, setLoading] = useState(true);

  async function refresh() {
    setLoading(true);
    try {
      const [eventsData, findingsData] = await Promise.all([getEvents(), getFindings()]);
      setEvents(eventsData);
      setFindings(findingsData);
      setStatus(
        eventsData.length || findingsData.length
          ? "Audit trail refreshed."
          : "No audit history yet. Scans and policy checks will appear here.",
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function handleClearHistory() {
    const confirmed = window.confirm(
      "Warning: this will permanently delete all stored audit events and findings. Continue?",
    );
    if (!confirmed) {
      return;
    }

    setLoading(true);
    try {
      const result = await clearHistory();
      setEvents([]);
      setFindings([]);
      setStatus(
        `${result.message} Removed ${result.cleared_events} event(s) and ${result.cleared_findings} finding(s).`,
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed to clear history.");
    } finally {
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
          <button className="button-secondary" onClick={() => void refresh()}>
            Refresh
          </button>
          <button className="button-danger" onClick={() => void handleClearHistory()}>
            Clear history
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
