export type View = "overview" | "alerts" | "cases" | "telemetry" | "rules";
export type Principal = {
  name: string;
  role: "admin" | "analyst" | "viewer";
  local?: boolean;
};
export type Event = {
  id: string;
  timestamp: string;
  received_at?: string;
  source: string;
  sensor: string;
  host: string;
  user: string | null;
  kind: string;
  process: string | null;
  command: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  fields: Record<string, unknown>;
  fingerprint?: string;
};
export type Alert = {
  id: string;
  case_id: string;
  rule_id: string;
  title: string;
  severity: string;
  confidence: number;
  timestamp: string;
  host: string;
  user: string | null;
  techniques: string[];
  event_ids: string[];
  explanation: string;
  correlation_reason: string;
};
export type Incident = {
  id: string;
  title: string;
  status: string;
  assignee: string | null;
  first_seen: string;
  last_seen: string;
  hosts: string[];
  users: string[];
  risk: number;
  checklist: Record<string, boolean>;
};
export type CaseDetail = Incident & {
  alerts: Alert[];
  timeline: Event[];
  notes: { id: string; author: string; text: string; created_at: string }[];
  evidence: { id: string; sha256: string; created_at: string }[];
  responses: {
    id: string;
    requested_by: string;
    approved_by: string | null;
    status: string;
    reason: string;
  }[];
};
export type Technique = {
  id: string;
  name: string;
  url?: string;
  tactics?: string[];
  alerts: number;
};
export type Stats = {
  events: number;
  alerts: number;
  open_cases: number;
  rules: number;
  severity: Record<string, number>;
  sources: { source: string; count: number; last_received: string | null }[];
  techniques: Technique[];
  hosts: { host: string; events: number; alerts: number }[];
  first_event: string | null;
  last_event: string | null;
  updated_at: string;
  scope: string;
};
export type Rule = {
  id: string;
  title: string;
  level: string;
  status: string;
  alert_count: number;
  falsepositives: string[];
  detection: Record<string, unknown>;
  techniques: Technique[];
  "x-sentinelforge": {
    confidence: number;
    explanation: string;
    required_telemetry: string[];
    validation: string;
    slug: string;
  };
};
export type Page<T> = { total: number; items: T[] };
export type ReplayResult = {
  accepted: number;
  duplicates: number;
  rejected: number;
  alerts_created: number;
};
