import {
  FormEvent,
  startTransition,
  useDeferredValue,
  useEffect,
  useState,
} from "react";
import type { ReactNode } from "react";
import { approveAction, createAction, fetchActions, fetchOverview, websocketUrl } from "./api";
import type { Alert, DashboardSnapshot, Finding, Host, ResponseAction, Vulnerability } from "./types";

const emptySnapshot: DashboardSnapshot = {
  metrics: [],
  alerts: [],
  findings: [],
  vulnerabilities: [],
  hosts: [],
};

function severityClass(severity: string) {
  return `severity severity-${severity.toLowerCase()}`;
}

function formatTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function App() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(emptySnapshot);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [filter, setFilter] = useState("");
  const [actionHost, setActionHost] = useState("");
  const [actionType, setActionType] = useState("isolate_host");
  const [actionParams, setActionParams] = useState('{"reason":"Analyst initiated containment"}');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const deferredFilter = useDeferredValue(filter.trim().toLowerCase());

  const load = async () => {
    try {
      const [overview, responseActions] = await Promise.all([fetchOverview(), fetchActions()]);
      startTransition(() => {
        setSnapshot(overview);
        setActions(responseActions);
        setActionHost((current) => current || overview.hosts[0]?.id || "");
      });
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load console data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    const interval = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    function connect() {
      const socket = new WebSocket(websocketUrl());
      let disconnected = false;

      socket.onopen = () => {
        setError(null);
        disconnected = false;
      };

      socket.onmessage = () => void load();

      socket.onerror = () => {
        disconnected = true;
        setError("Live stream disconnected. Polling continues.");
      };

      socket.onclose = () => {
        if (disconnected) {
          // Auto-reconnect after 5 seconds
          setTimeout(connect, 5000);
        }
      };

      return socket;
    }

    const socket = connect();
    return () => {
      socket.close();
    };
  }, []);

  const filteredAlerts = snapshot.alerts.filter((alert) => {
    if (!deferredFilter) return true;
    return [alert.title, alert.summary, alert.host_id, alert.rule_id]
      .join(" ")
      .toLowerCase()
      .includes(deferredFilter);
  });

  const pendingActions = actions.filter((action) => action.state === "pending_approval");

  const handleCreateAction = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const parsed = JSON.parse(actionParams) as Record<string, unknown>;
      await createAction({
        host_id: actionHost,
        type: actionType,
        parameters: parsed,
        approval_mode: "manual",
        ttl: 900,
        requested_by: "console-analyst",
      });
      await load();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Failed to create action");
    }
  };

  const handleApprove = async (actionId: string) => {
    try {
      await approveAction(actionId, "console-analyst");
      await load();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Failed to approve action");
    }
  };

  return (
    <div className="app-shell">
      <aside className="command-rail">
        <div className="rail-mark">SecOS Defender</div>
        <div className="rail-copy">
          <p className="eyebrow">Endpoint defense console</p>
          <h1>Analyst control room for live host risk.</h1>
          <p className="lede">
            A bright, forensic workspace for runtime detections, exposure tracking, and deliberate
            response.
          </p>
        </div>
        <div className="rail-block">
          <span className="rail-label">Search the active queue</span>
          <input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            className="search-input"
            placeholder="Host, title, or rule"
          />
        </div>
        <div className="rail-block status-block">
          <span className="rail-label">System state</span>
          <strong>{loading ? "Bootstrapping" : "Streaming"}</strong>
          <p>{error ?? "WebSocket-backed updates plus 15s polling safeguard."}</p>
        </div>
      </aside>

      <main className="main-stage">
        <section className="hero-band">
          <div className="hero-copy">
            <p className="eyebrow">Operational snapshot</p>
            <h2>Investigate what changed, then decide what moves.</h2>
          </div>
          <div className="hero-pulse">
            <span className="pulse-ring" />
            <span className="pulse-ring delay" />
            <span className="pulse-dot" />
          </div>
        </section>

        <section className="metric-strip">
          {snapshot.metrics.map((metric) => (
            <article key={metric.label} className="metric-unit">
              <p>{metric.label}</p>
              <strong>{metric.value}</strong>
              <span>{metric.trend}</span>
            </article>
          ))}
        </section>

        <section className="dashboard-grid">
          <div className="primary-column">
            <Panel
              title="Alert Ledger"
              caption="Real-time rule output from normalized endpoint telemetry"
              action={`${filteredAlerts.length} visible`}
            >
              <AlertTable alerts={filteredAlerts} />
            </Panel>

            <Panel
              title="Correlated Findings"
              caption="Deduplicated investigations across runtime and vulnerability evidence"
              action={`${snapshot.findings.length} tracked`}
            >
              <FindingList findings={snapshot.findings} />
            </Panel>
          </div>

          <div className="secondary-column">
            <Panel
              title="Exposure Watch"
              caption="Inventory-correlated package risk with remediation targets"
              action={`${snapshot.vulnerabilities.length} surfaced`}
            >
              <VulnerabilityList vulnerabilities={snapshot.vulnerabilities} />
            </Panel>

            <Panel title="Host Roster" caption="Endpoints reporting in this cycle" action={`${snapshot.hosts.length} hosts`}>
              <HostList hosts={snapshot.hosts} />
            </Panel>

            <Panel
              title="Response Queue"
              caption="Manual approval stays on by default"
              action={`${pendingActions.length} pending`}
            >
              <ActionComposer
                hosts={snapshot.hosts}
                actionHost={actionHost}
                actionType={actionType}
                actionParams={actionParams}
                onActionHost={setActionHost}
                onActionType={setActionType}
                onActionParams={setActionParams}
                onSubmit={handleCreateAction}
              />
              <ActionList actions={actions} onApprove={handleApprove} />
            </Panel>
          </div>
        </section>
      </main>
    </div>
  );
}

function Panel({
  title,
  caption,
  action,
  children,
}: {
  title: string;
  caption: string;
  action: string;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <header className="panel-header">
        <div>
          <p className="eyebrow">{title}</p>
          <h3>{caption}</h3>
        </div>
        <span className="panel-action">{action}</span>
      </header>
      {children}
    </section>
  );
}

function AlertTable({ alerts }: { alerts: Alert[] }) {
  if (!alerts.length) {
    return <EmptyState title="No live alerts" body="Ingest events or run the demo producer to populate the ledger." />;
  }

  return (
    <div className="table-shell">
      <table className="ledger-table">
        <thead>
          <tr>
            <th>Signal</th>
            <th>Host</th>
            <th>Rule</th>
            <th>Seen</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td>
                <span className={severityClass(alert.severity)}>{alert.severity}</span>
                <strong>{alert.title}</strong>
                <p>{alert.summary}</p>
              </td>
              <td>{alert.host_id}</td>
              <td>{alert.rule_id}</td>
              <td>{formatTime(alert.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingList({ findings }: { findings: Finding[] }) {
  if (!findings.length) {
    return <EmptyState title="No findings yet" body="Correlated findings appear here when detections or exposure rules aggregate." />;
  }

  return (
    <ul className="signal-list">
      {findings.map((finding) => (
        <li key={finding.id}>
          <div>
            <span className={severityClass(finding.severity)}>{finding.severity}</span>
            <strong>{finding.title}</strong>
            <p>
              {finding.category} on {finding.host_id}
            </p>
          </div>
          <time>{formatTime(finding.updated_at)}</time>
        </li>
      ))}
    </ul>
  );
}

function VulnerabilityList({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
  if (!vulnerabilities.length) {
    return <EmptyState title="No exposed packages" body="Send inventory reports to populate the vulnerability intelligence view." />;
  }

  return (
    <ul className="signal-list compact">
      {vulnerabilities.map((vulnerability) => (
        <li key={vulnerability.id}>
          <div>
            <span className={severityClass(vulnerability.severity)}>{vulnerability.severity}</span>
            <strong>{vulnerability.cve_id}</strong>
            <p>
              {vulnerability.package_name} {vulnerability.installed_version} on {vulnerability.host_id}
            </p>
          </div>
          <div className="fix-target">
            <span>Fix target</span>
            <strong>{vulnerability.fixed_version ?? "Unavailable"}</strong>
          </div>
        </li>
      ))}
    </ul>
  );
}

function HostList({ hosts }: { hosts: Host[] }) {
  if (!hosts.length) {
    return <EmptyState title="No reporting hosts" body="Heartbeats create the host roster and keep the stage live." />;
  }

  return (
    <ul className="host-list">
      {hosts.map((host) => (
        <li key={host.id}>
          <div>
            <strong>{host.hostname || host.id}</strong>
            <p>
              {host.platform} {host.ip_address ? `• ${host.ip_address}` : ""}
            </p>
          </div>
          <time>{formatTime(host.last_seen)}</time>
        </li>
      ))}
    </ul>
  );
}

function ActionComposer({
  hosts,
  actionHost,
  actionType,
  actionParams,
  onActionHost,
  onActionType,
  onActionParams,
  onSubmit,
}: {
  hosts: Host[];
  actionHost: string;
  actionType: string;
  actionParams: string;
  onActionHost: (value: string) => void;
  onActionType: (value: string) => void;
  onActionParams: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
}) {
  return (
    <form className="action-form" onSubmit={onSubmit}>
      <div className="field-row">
        <label>
          Host
          <select value={actionHost} onChange={(event) => onActionHost(event.target.value)}>
            {!hosts.length ? <option value="">No hosts yet</option> : null}
            {hosts.map((host) => (
              <option key={host.id} value={host.id}>
                {host.hostname || host.id}
              </option>
            ))}
          </select>
        </label>
        <label>
          Action
          <select value={actionType} onChange={(event) => onActionType(event.target.value)}>
            <option value="isolate_host">Isolate host</option>
            <option value="collect_artifacts">Collect artifacts</option>
            <option value="kill_process">Kill process</option>
          </select>
        </label>
      </div>
      <label>
        Parameters JSON
        <textarea value={actionParams} onChange={(event) => onActionParams(event.target.value)} rows={4} />
      </label>
      <button type="submit" disabled={!hosts.length || !actionHost}>
        Queue analyst action
      </button>
    </form>
  );
}

function ActionList({
  actions,
  onApprove,
}: {
  actions: ResponseAction[];
  onApprove: (actionId: string) => void;
}) {
  if (!actions.length) {
    return <EmptyState title="No response actions" body="Queue a reversible action to test the orchestration loop." />;
  }

  return (
    <ul className="action-list">
      {actions.map((action) => (
        <li key={action.id}>
          <div>
            <strong>{action.type}</strong>
            <p>
              {action.host_id} • {action.approval_mode} • {action.requested_by}
            </p>
          </div>
          <div className="action-controls">
            <span className={`state-pill state-${action.state.replaceAll("_", "-")}`}>{action.state}</span>
            {action.state === "pending_approval" ? (
              <button type="button" onClick={() => void onApprove(action.id)}>
                Approve
              </button>
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  );
}
