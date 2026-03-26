package collectors

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/itsdikshitaa/secos-defender/agent/internal/api"
)

type FixtureCollector struct {
	eventsPath    string
	inventoryPath string
}

func NewFixtureCollector(eventsPath, inventoryPath string) *FixtureCollector {
	return &FixtureCollector{
		eventsPath:    eventsPath,
		inventoryPath: inventoryPath,
	}
}

func (c *FixtureCollector) CollectEvents(ctx context.Context, hostID, platform string) ([]api.NormalizedEvent, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if c.eventsPath == "" {
		return []api.NormalizedEvent{}, nil
	}
	contents, err := os.ReadFile(c.eventsPath)
	if err != nil {
		return nil, err
	}
	var events []api.NormalizedEvent
	if err := json.Unmarshal(contents, &events); err != nil {
		return nil, err
	}
	for idx := range events {
		if events[idx].HostID == "" {
			events[idx].HostID = hostID
		}
		if events[idx].Platform == "" {
			events[idx].Platform = platform
		}
		if events[idx].OccurredAt.IsZero() {
			events[idx].OccurredAt = time.Now().UTC()
		}
	}
	return events, nil
}

func (c *FixtureCollector) CollectInventory(ctx context.Context, hostID, hostname, platform string) (*api.InventoryReport, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if c.inventoryPath == "" {
		return nil, nil
	}
	contents, err := os.ReadFile(c.inventoryPath)
	if err != nil {
		return nil, err
	}
	var report api.InventoryReport
	if err := json.Unmarshal(contents, &report); err != nil {
		return nil, err
	}
	if report.HostID == "" {
		report.HostID = hostID
	}
	if report.Hostname == "" {
		report.Hostname = hostname
	}
	if report.Platform == "" {
		report.Platform = platform
	}
	return &report, nil
}
