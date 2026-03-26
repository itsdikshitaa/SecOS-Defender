package runner

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/itsdikshitaa/secos-defender/agent/internal/api"
	"github.com/itsdikshitaa/secos-defender/agent/internal/buffer"
	"github.com/itsdikshitaa/secos-defender/agent/internal/client"
	"github.com/itsdikshitaa/secos-defender/agent/internal/collectors"
	"github.com/itsdikshitaa/secos-defender/agent/internal/config"
)

type Runner struct {
	cfg       config.Config
	client    *client.Client
	buffer    *buffer.FileBuffer
	collector *collectors.FixtureCollector
}

func New(cfg config.Config, client *client.Client, buffer *buffer.FileBuffer, collector *collectors.FixtureCollector) *Runner {
	return &Runner{
		cfg:       cfg,
		client:    client,
		buffer:    buffer,
		collector: collector,
	}
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.sendInventory(ctx); err != nil {
		log.Printf("inventory sync failed: %v", err)
	}
	if err := r.sendHeartbeat(ctx); err != nil {
		log.Printf("heartbeat failed: %v", err)
	}
	if err := r.collectAndFlush(ctx); err != nil {
		log.Printf("initial collection failed: %v", err)
	}

	collectTicker := time.NewTicker(time.Duration(r.cfg.CollectIntervalSeconds) * time.Second)
	heartbeatTicker := time.NewTicker(time.Duration(r.cfg.HeartbeatIntervalSeconds) * time.Second)
	inventoryTicker := time.NewTicker(time.Duration(r.cfg.InventoryIntervalSeconds) * time.Second)
	defer collectTicker.Stop()
	defer heartbeatTicker.Stop()
	defer inventoryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-collectTicker.C:
			if err := r.collectAndFlush(ctx); err != nil {
				log.Printf("collect/flush failed: %v", err)
			}
			if err := r.pollAndReportActions(ctx); err != nil {
				log.Printf("action polling failed: %v", err)
			}
		case <-heartbeatTicker.C:
			if err := r.sendHeartbeat(ctx); err != nil {
				log.Printf("heartbeat failed: %v", err)
			}
		case <-inventoryTicker.C:
			if err := r.sendInventory(ctx); err != nil {
				log.Printf("inventory sync failed: %v", err)
			}
		}
	}
}

func (r *Runner) sendHeartbeat(ctx context.Context) error {
	size, _ := r.buffer.Size()
	return r.client.SendHeartbeat(ctx, api.Heartbeat{
		HostID:       r.cfg.HostID,
		Hostname:     r.cfg.Hostname,
		Platform:     r.cfg.Platform,
		AgentVersion: r.cfg.AgentVersion,
		QueueDepth:   size,
		Status:       "online",
		Metadata: map[string]interface{}{
			"transport": "https-json",
			"collector": "fixture",
		},
	})
}

func (r *Runner) sendInventory(ctx context.Context) error {
	report, err := r.collector.CollectInventory(ctx, r.cfg.HostID, r.cfg.Hostname, r.cfg.Platform)
	if err != nil || report == nil {
		return err
	}
	return r.client.SendInventory(ctx, *report)
}

func (r *Runner) collectAndFlush(ctx context.Context) error {
	events, err := r.collector.CollectEvents(ctx, r.cfg.HostID, r.cfg.Platform)
	if err != nil {
		return err
	}
	if len(events) > 0 {
		if err := r.buffer.Append(events); err != nil {
			return err
		}
	}
	queued, err := r.buffer.Load()
	if err != nil {
		return err
	}
	if len(queued) == 0 {
		return nil
	}
	if err := r.client.SendEvents(ctx, api.EventBatch{
		BatchID: fmt.Sprintf("%s-%d", r.cfg.HostID, time.Now().UnixNano()),
		Events:  queued,
	}); err != nil {
		return err
	}
	return r.buffer.Replace([]api.NormalizedEvent{})
}

func (r *Runner) pollAndReportActions(ctx context.Context) error {
	actions, err := r.client.PollActions(ctx, r.cfg.HostID)
	if err != nil {
		return err
	}
	for _, action := range actions {
		result := api.ActionResult{
			State: "completed",
			Result: map[string]interface{}{
				"message": "Fixture agent acknowledged and simulated execution.",
				"type":    action.Type,
			},
		}
		if err := r.client.ReportActionResult(ctx, action.ActionID, result); err != nil {
			return err
		}
	}
	return nil
}
