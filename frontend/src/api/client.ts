import type {
  ContentCheckResponse,
  DemoLoadResponse,
  EventRecord,
  FindingRecord,
  PolicyDecisionResponse,
  RuntimeEventRequest,
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

export function loadDemoData(): Promise<DemoLoadResponse> {
  return request<DemoLoadResponse>("/demo/load-sample-data", { method: "POST" });
}

export function scanSkillByPath(path: string): Promise<SkillScanResponse> {
  return request<SkillScanResponse>("/scan-skill", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  });
}

export function scanSkillArchive(file: File): Promise<SkillScanResponse> {
  const formData = new FormData();
  formData.append("archive", file);
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

