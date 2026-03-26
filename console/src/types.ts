export interface Metric {
  label: string;
  value: number;
  trend: string;
}

export interface Alert {
  id: string;
  host_id: string;
  rule_id: string;
  title: string;
  summary: string;
  severity: string;
  status: string;
  created_at: string;
}

export interface Finding {
  id: string;
  host_id: string;
  category: string;
  title: string;
  severity: string;
  status: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  host_id: string;
  cve_id: string;
  package_name: string;
  installed_version: string;
  fixed_version: string | null;
  severity: string;
  status: string;
  description?: string;
}

export interface Host {
  id: string;
  hostname: string | null;
  platform: string;
  ip_address: string | null;
  last_seen: string;
}

export interface ResponseAction {
  id: string;
  host_id: string;
  type: string;
  state: string;
  approval_mode: string;
  ttl: number;
  requested_by: string;
}

export interface DashboardSnapshot {
  metrics: Metric[];
  alerts: Alert[];
  findings: Finding[];
  vulnerabilities: Vulnerability[];
  hosts: Host[];
}
