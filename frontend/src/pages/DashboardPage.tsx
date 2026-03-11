import { useEffect, useMemo, useState } from "react";
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
  const [sessionFilter, setSessionFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState<"all" | "allow" | "warn" | "block">("all");
  const [severityFilter, setSeverityFilter] = useState<"all" | "low" | "medium" | "high" | "critical">("all");

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

  const filteredEvents = useMemo(() => {
    const normalizedSession = sessionFilter.trim().toLowerCase();
    return events.filter((event) => {
      const matchesSession = !normalizedSession
        || (event.session_id ?? "").toLowerCase().includes(normalizedSession)
        || event.actor.toLowerCase().includes(normalizedSession)
        || event.target_resource.toLowerCase().includes(normalizedSession)
        || event.task.toLowerCase().includes(normalizedSession);
      const matchesDecision = decisionFilter === "all" || event.decision === decisionFilter;
      return matchesSession && matchesDecision;
    });
  }, [decisionFilter, events, sessionFilter]);

  const filteredFindings = useMemo(() => {
    const normalizedSession = sessionFilter.trim().toLowerCase();
    return findings.filter((finding) => {
      const matchesSession = !normalizedSession
        || (finding.session_id ?? "").toLowerCase().includes(normalizedSession)
        || finding.category.toLowerCase().includes(normalizedSession)
        || finding.description.toLowerCase().includes(normalizedSession)
        || finding.evidence.toLowerCase().includes(normalizedSession);
      const matchesSeverity = severityFilter === "all" || finding.severity === severityFilter;
      return matchesSession && matchesSeverity;
    });
  }, [findings, sessionFilter, severityFilter]);

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

      <section className="card form-card">
        <div className="split">
          <div>
            <p className="eyebrow">Audit filters</p>
            <h3>Session drill-down and quick search</h3>
          </div>
          <button
            className="button-secondary"
            type="button"
            onClick={() => {
              setSessionFilter("");
              setDecisionFilter("all");
              setSeverityFilter("all");
            }}
          >
            Reset filters
          </button>
        </div>
        <div className="filter-grid">
          <label>
            Search session, actor, task, target, finding text
            <input
              placeholder="session-001, web-agent, credentials"
              value={sessionFilter}
              onChange={(event) => setSessionFilter(event.target.value)}
            />
          </label>
          <label>
            Event decision
            <select
              value={decisionFilter}
              onChange={(event) =>
                setDecisionFilter(event.target.value as "all" | "allow" | "warn" | "block")
              }
            >
              <option value="all">All decisions</option>
              <option value="allow">Allow</option>
              <option value="warn">Warn</option>
              <option value="block">Block</option>
            </select>
          </label>
          <label>
            Finding severity
            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value as "all" | "low" | "medium" | "high" | "critical")
              }
            >
              <option value="all">All severities</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
        </div>
        <p className="status">
          Showing {Math.min(filteredFindings.length, 8)} of {filteredFindings.length} filtered finding(s) and{" "}
          {Math.min(filteredEvents.length, 6)} of {filteredEvents.length} filtered event(s).
        </p>
      </section>

      <p className="status">{loading ? "Loading..." : status}</p>

      <div className="grid-two">
        <section className="card panel">
          <h3>Recent findings</h3>
          <FindingsTable findings={filteredFindings.slice(0, 8)} />
        </section>
        <section className="panel">
          <h3>Session timeline</h3>
          <EventTimeline events={filteredEvents.slice(0, 6)} />
        </section>
      </div>
    </section>
  );
}

export default DashboardPage;
