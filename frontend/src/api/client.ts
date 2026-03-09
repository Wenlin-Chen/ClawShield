import type {
  ClearHistoryResponse,
  ContentCheckResponse,
  EventRecord,
  FindingRecord,
  PolicyDecisionResponse,
  RuntimeEventRequest,
  SkillScanAnalysisMode,
  SkillScanResponse,
} from "../types/api";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || "API request failed");
  }
  return response.json() as Promise<T>;
}

export function getEvents(): Promise<EventRecord[]> {
  return request<EventRecord[]>("/events");
}

export function getFindings(): Promise<FindingRecord[]> {
  return request<FindingRecord[]>("/findings");
}

export function clearHistory(): Promise<ClearHistoryResponse> {
  return request<ClearHistoryResponse>("/clear-history", { method: "POST" });
}

export function scanSkillByPath(path: string, analysisMode: SkillScanAnalysisMode = "rules"): Promise<SkillScanResponse> {
  return request<SkillScanResponse>("/scan-skill", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path, analysis_mode: analysisMode }),
  });
}

export function scanSkillUpload(file: File, analysisMode: SkillScanAnalysisMode = "rules"): Promise<SkillScanResponse> {
  const formData = new FormData();
  formData.append("upload", file);
  formData.append("analysis_mode", analysisMode);
  return request<SkillScanResponse>("/scan-skill", {
    method: "POST",
    body: formData,
  });
}

export function evaluateEvent(
  payload: RuntimeEventRequest,
): Promise<PolicyDecisionResponse> {
  return request<PolicyDecisionResponse>("/evaluate-event", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function checkContent(text: string, sessionId?: string, source?: string) {
  return request<ContentCheckResponse>("/check-content", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, session_id: sessionId, source }),
  });
}
