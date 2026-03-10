import { useEffect, useState, type FormEvent } from "react";
import { sanitizeSkillPath, scanSkillByPath, scanSkillUpload } from "../api/client";
import DecisionBadge from "../components/DecisionBadge";
import FindingsTable from "../components/FindingsTable";
import type { SkillScanAnalysisMode, SkillScanResponse } from "../types/api";

const SAVED_SKILL_PATH_KEY = "clawshield:last-skill-path";

function SkillScannerPage() {
  const [path, setPath] = useState("");
  const [upload, setUpload] = useState<File | null>(null);
  const [result, setResult] = useState<SkillScanResponse | null>(null);
  const [analysisMode, setAnalysisMode] = useState<SkillScanAnalysisMode>("rule_mode");
  const [status, setStatus] = useState(
    "Scan a local skill directory, a single skill file, or upload a zip or skill file.",
  );
  const [sanitizeConfirmed, setSanitizeConfirmed] = useState(false);

  useEffect(() => {
    const savedPath = window.localStorage.getItem(SAVED_SKILL_PATH_KEY);
    if (savedPath) {
      setPath(savedPath);
    }
  }, []);


  async function handleSanitize() {
    if (!result || !path.trim()) {
      setStatus("Run a path-based scan before sanitizing risky lines.");
      return;
    }
    if (!sanitizeConfirmed) {
      setStatus("Confirm removal before sanitizing high-risk findings.");
      return;
    }

    setStatus("Removing high-risk lines and rescanning...");
    try {
      const response = await sanitizeSkillPath(path.trim(), true);
      setResult(response.rescanned);
      setStatus(
        `Removed ${response.removed_lines} high-risk line(s). Skipped ${response.skipped_findings} finding(s) without exact line numbers.`,
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Sanitization failed.");
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!upload && !path.trim()) {
      setStatus("Provide a local path or upload a zip or skill file before scanning.");
      return;
    }
    setStatus("Scanning skill...");
    try {
      const normalizedPath = path.trim();
      const response = upload
        ? await scanSkillUpload(upload, analysisMode)
        : await scanSkillByPath(normalizedPath, analysisMode);
      setResult(response);
      setStatus(`Scan complete for ${response.scanned_path}.`);
      if (!upload && normalizedPath) {
        window.localStorage.setItem(SAVED_SKILL_PATH_KEY, normalizedPath);
      }
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Scan failed.");
    }
  }

  const highRiskFindings = result?.findings.filter((finding) => finding.severity === "high" || finding.severity === "critical") ?? [];

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Pre-install Review</p>
          <h2>Skill scanner</h2>
        </div>
      </header>

      <form className="card form-card" onSubmit={handleSubmit}>
        <label>
          Skill directory or file path
          <input
            placeholder="/absolute/path/to/skill-or-file"
            value={path}
            onChange={(event) => setPath(event.target.value)}
          />
        </label>
        <label>
          Analysis mode
          <select value={analysisMode} onChange={(event) => setAnalysisMode(event.target.value as SkillScanAnalysisMode)}>
            <option value="rule_mode">Rule mode (deterministic signatures)</option>
            <option value="agent_mode">Agent mode (LLM reviewer)</option>
          </select>
        </label>
        <label>
          Or upload a zip archive or individual skill file
          <input
            type="file"
            accept=".zip,.py,.sh,.ps1,.js,.ts,.json,.yaml,.yml,.toml,.md,.txt"
            onChange={(event) => setUpload(event.target.files?.[0] ?? null)}
          />
        </label>
        <div className="actions">
          <button type="submit">Run scan</button>
          <button
            className="button-secondary"
            type="button"
            onClick={() => {
              setUpload(null);
              setPath("");
              setSanitizeConfirmed(false);
              window.localStorage.removeItem(SAVED_SKILL_PATH_KEY);
              setStatus("Cleared the current scanner inputs and saved path.");
            }}
          >
            Clear input
          </button>
        </div>
        {result && !upload && highRiskFindings.length > 0 ? (
          <div className="stack">
            <label>
              <input
                type="checkbox"
                checked={sanitizeConfirmed}
                onChange={(event) => setSanitizeConfirmed(event.target.checked)}
              />
              I reviewed the high-risk findings and want ClawShield to remove matching lines.
            </label>
            <button className="button-secondary" type="button" onClick={handleSanitize}>
              Remove high-risk lines
            </button>
          </div>
        ) : null}
        <p className="status">{status}</p>
      </form>

      {result ? (
        <section className="card panel">
          <div className="split">
            <div>
              <p className="eyebrow">Recommendation</p>
              <h3>{result.scanned_path}</h3>
            </div>
            <div className="stack-right">
              <DecisionBadge label={result.recommendation} />
              <strong className="score-pill">Risk score: {result.score}</strong>
            </div>
          </div>
          <p>Scanned files: {result.scanned_files}</p>
          <p>Analysis mode: {result.analysis_mode}</p>
          {result.analysis_summary ? <p>{result.analysis_summary}</p> : null}
          <FindingsTable findings={result.findings} />
        </section>
      ) : null}
    </section>
  );
}

export default SkillScannerPage;
