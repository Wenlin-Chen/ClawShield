export type Decision = "allow" | "warn" | "block";
export type Severity = "low" | "medium" | "high" | "critical";
export type Recommendation = "allow" | "warn" | "block";
export type SkillScanAnalysisMode = "rules" | "openclaw_agent";

export type ScanFinding = {
  category: string;
  severity: Severity;
  title: string;
  evidence: string;
  file_path: string;
  line_number: number | null;
  score: number;
};

export type SkillScanResponse = {
  analysis_mode: SkillScanAnalysisMode;
  analysis_summary: string | null;
  scan_id: string;
  scanned_path: string;
  scanned_files: number;
  score: number;
  recommendation: Recommendation;
  findings: ScanFinding[];
};

export type RuntimeEventRequest = {
  event_type: string;
  actor: string;
  task: string;
  target_resource: string;
  provenance: string;
  timestamp?: string;
  session_id?: string;
  command?: string;
  url?: string;
  payload_excerpt?: string;
  metadata?: Record<string, unknown>;
};

export type PolicyDecisionResponse = {
  decision: Decision;
  reasons: string[];
  matched_rules: string[];
  alert: {
    title: string;
    severity: Severity;
    description: string;
    evidence: string;
  } | null;
};

export type ContentCheckResponse = {
  check_id: string;
  injection_score: number;
  flags: string[];
  matched_patterns: string[];
};

export type FindingRecord = {
  id: number;
  reference_id: string | null;
  session_id: string | null;
  source_type: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  related_resource: string | null;
  score: number;
  recommendation: Recommendation | null;
  created_at: string;
};

export type EventRecord = {
  id: number;
  session_id: string | null;
  event_type: string;
  actor: string;
  task: string;
  target_resource: string;
  provenance: string;
  timestamp: string;
  command: string | null;
  url: string | null;
  payload_excerpt: string | null;
  metadata: Record<string, unknown>;
  decision: Decision;
  reasons: string[];
  matched_rules: string[];
  created_at: string;
};

export type ClearHistoryResponse = {
  message: string;
  cleared_events: number;
  cleared_findings: number;
};


export type SkillSanitizeResponse = {
  scan_id: string;
  sanitized_path: string;
  removed_lines: number;
  skipped_findings: number;
  original_scan: SkillScanResponse;
  rescanned: SkillScanResponse;
};
