package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/therayyanawaz/secos-defender/agent/internal/api"
	"github.com/therayyanawaz/secos-defender/agent/internal/config"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string, tlsCfg config.TLSConfig) (*Client, error) {
	transport := &http.Transport{}
	if tlsCfg.CAFile != "" || (tlsCfg.CertFile != "" && tlsCfg.KeyFile != "") {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsCfg.CAFile != "" {
			ca, err := os.ReadFile(tlsCfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			tlsConfig.RootCAs = pool
		}
		if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: transport,
		},
	}, nil
}

func (c *Client) postJSON(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		contents, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(contents))
	}
	return nil
}

func (c *Client) SendHeartbeat(ctx context.Context, heartbeat api.Heartbeat) error {
	return c.postJSON(ctx, "/api/v1/agents/heartbeat", heartbeat)
}

func (c *Client) SendEvents(ctx context.Context, batch api.EventBatch) error {
	return c.postJSON(ctx, "/api/v1/ingest/events", batch)
}

func (c *Client) SendInventory(ctx context.Context, report api.InventoryReport) error {
	return c.postJSON(ctx, "/api/v1/ingest/inventory", report)
}

func (c *Client) PollActions(ctx context.Context, hostID string) ([]api.ResponseAction, error) {
	endpoint := c.baseURL + "/api/v1/actions/poll?host_id=" + url.QueryEscape(hostID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		contents, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(contents))
	}
	var actions []api.ResponseAction
	if err := json.NewDecoder(resp.Body).Decode(&actions); err != nil {
		return nil, err
	}
	return actions, nil
}

func (c *Client) ReportActionResult(ctx context.Context, actionID string, result api.ActionResult) error {
	return c.postJSON(ctx, "/api/v1/actions/"+actionID+"/result", result)
}
