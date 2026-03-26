package api

import "time"

type PrincipalContext struct {
	Username string `json:"username,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

type ProcessContext struct {
	Name        string `json:"name,omitempty"`
	PID         int    `json:"pid,omitempty"`
	ParentPID   int    `json:"parent_pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	Path        string `json:"path,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

type NetworkContext struct {
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Direction string `json:"direction,omitempty"`
}

type FileContext struct {
	Path   string `json:"path,omitempty"`
	Action string `json:"action,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type RegistryContext struct {
	KeyPath   string `json:"key_path,omitempty"`
	ValueName string `json:"value_name,omitempty"`
	ValueData string `json:"value_data,omitempty"`
	Action    string `json:"action,omitempty"`
}

type NormalizedEvent struct {
	EventID    string                 `json:"event_id"`
	HostID     string                 `json:"host_id"`
	Platform   string                 `json:"platform"`
	Source     string                 `json:"source"`
	EventType  string                 `json:"event_type"`
	OccurredAt time.Time              `json:"occurred_at"`
	Severity   string                 `json:"severity"`
	Principal  PrincipalContext       `json:"principal,omitempty"`
	Process    ProcessContext         `json:"process,omitempty"`
	Network    NetworkContext         `json:"network,omitempty"`
	File       FileContext            `json:"file,omitempty"`
	Registry   RegistryContext        `json:"registry,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
	RawPayload map[string]interface{} `json:"raw_payload,omitempty"`
}

type EventBatch struct {
	BatchID string            `json:"batch_id"`
	Events  []NormalizedEvent `json:"events"`
}

type InventoryPackage struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Architecture string                 `json:"architecture,omitempty"`
	Source       string                 `json:"source,omitempty"`
	InstalledAt  *time.Time             `json:"installed_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type InventoryReport struct {
	HostID    string                 `json:"host_id"`
	Hostname  string                 `json:"hostname,omitempty"`
	Platform  string                 `json:"platform"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Packages  []InventoryPackage     `json:"packages"`
}

type Heartbeat struct {
	HostID       string                 `json:"host_id"`
	Hostname     string                 `json:"hostname,omitempty"`
	Platform     string                 `json:"platform"`
	AgentVersion string                 `json:"agent_version"`
	QueueDepth   int                    `json:"queue_depth"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	Status       string                 `json:"status"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type ResponseAction struct {
	ActionID     string                 `json:"action_id"`
	Type         string                 `json:"type"`
	HostID       string                 `json:"host_id"`
	Parameters   map[string]interface{} `json:"parameters"`
	ApprovalMode string                 `json:"approval_mode"`
	TTL          int                    `json:"ttl"`
	State        string                 `json:"state"`
}

type ActionResult struct {
	State  string                 `json:"state"`
	Result map[string]interface{} `json:"result"`
}
