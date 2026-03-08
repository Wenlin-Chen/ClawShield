import { useState, type FormEvent } from "react";
import { scanSkillArchive, scanSkillByPath } from "../api/client";
import DecisionBadge from "../components/DecisionBadge";
import FindingsTable from "../components/FindingsTable";
import type { SkillScanResponse } from "../types/api";

function SkillScannerPage() {
  const [path, setPath] = useState("");
  const [archive, setArchive] = useState<File | null>(null);
  const [result, setResult] = useState<SkillScanResponse | null>(null);
  const [status, setStatus] = useState("Scan a local skill directory or upload a zip archive.");

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("Scanning skill...");
    try {
      const response = archive ? await scanSkillArchive(archive) : await scanSkillByPath(path);
      setResult(response);
      setStatus(`Scan complete for ${response.scanned_path}.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Scan failed.");
    }
  }

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
          Skill directory path
          <input
            placeholder="/absolute/path/to/skill"
            value={path}
            onChange={(event) => setPath(event.target.value)}
          />
        </label>
        <label>
          Or upload a zip archive
          <input
            type="file"
            accept=".zip"
            onChange={(event) => setArchive(event.target.files?.[0] ?? null)}
          />
        </label>
        <div className="actions">
          <button type="submit">Run scan</button>
        </div>
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
          <FindingsTable findings={result.findings} />
        </section>
      ) : null}
    </section>
  );
}

export default SkillScannerPage;
