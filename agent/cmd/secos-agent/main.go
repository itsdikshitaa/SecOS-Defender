package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/therayyanawaz/secos-defender/agent/internal/buffer"
	"github.com/therayyanawaz/secos-defender/agent/internal/client"
	"github.com/therayyanawaz/secos-defender/agent/internal/collectors"
	"github.com/therayyanawaz/secos-defender/agent/internal/config"
	"github.com/therayyanawaz/secos-defender/agent/internal/runner"
)

func main() {
	configPath := flag.String("config", "", "path to agent config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	httpClient, err := client.New(cfg.APIBaseURL, cfg.TLS)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	queue := buffer.New(cfg.QueueFile)
	collector := collectors.NewFixtureCollector(cfg.FixtureEventsPath, cfg.FixtureInventoryPath)
	service := runner.New(cfg, httpClient, queue, collector)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := service.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("agent stopped with error: %v", err)
	}
}
