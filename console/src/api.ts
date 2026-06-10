import type { DashboardSnapshot, ResponseAction } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
    ...options,
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export function fetchOverview() {
  return request<DashboardSnapshot>("/api/v1/overview");
}

export function fetchActions() {
  return request<ResponseAction[]>("/api/v1/actions");
}

export function createAction(payload: {
  host_id: string;
  type: string;
  parameters: Record<string, unknown>;
  approval_mode: "manual" | "automatic";
  ttl: number;
  requested_by: string;
}) {
  return request<{ action_id: string; state: string }>("/api/v1/actions", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function approveAction(actionId: string, approvedBy: string) {
  return request<{ action_id: string; state: string }>(`/api/v1/actions/${actionId}/approve`, {
    method: "POST",
    body: JSON.stringify({ approved_by: approvedBy }),
  });
}

export function websocketUrl() {
  const base = import.meta.env.VITE_WS_BASE_URL || `${window.location.origin}`;
  const wsBase = base.replace("http://", "ws://").replace("https://", "wss://");
  const token = import.meta.env.VITE_API_KEY;
  if (!token) {
    throw new Error("VITE_API_KEY environment variable is required. Set it to the SECOS_API_KEY value used by the server.");
  }
  return `${wsBase}/api/v1/ws/stream?token=${encodeURIComponent(token)}`;
}
