package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/therayyanawaz/secos-defender/agent/internal/api"
	"github.com/therayyanawaz/secos-defender/agent/internal/config"
)

const (
	maxRetries  = 3
	baseBackoff = 500 * time.Millisecond
	maxBackoff  = 5 * time.Second
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func New(baseURL string, apiKey string, tlsCfg config.TLSConfig) (*Client, error) {
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
		apiKey:  apiKey,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}, nil
}

// doWithRetry performs an HTTP request with exponential backoff retry logic.
// The body bytes are saved upfront so the request body can be recreated on each retry attempt.
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	// Save original body bytes before the loop so retries can recreate the body
	var savedBody []byte
	if req.Body != nil {
		var err error
		savedBody, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(float64(baseBackoff) * math.Pow(2, float64(attempt-1)))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			time.Sleep(backoff + jitter)
		}

		// Recreate body from saved bytes for each attempt
		if savedBody != nil {
			req.Body = io.NopCloser(bytes.NewReader(savedBody))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// On 429 (rate limited) or 5xx, retry
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}

		return resp, nil
	}
	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
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
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.doWithRetry(req)
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

func (c *Client) getJSON(ctx context.Context, endpoint string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		contents, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(contents))
	}
	return json.NewDecoder(resp.Body).Decode(dest)
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
	var actions []api.ResponseAction
	if err := c.getJSON(ctx, endpoint, &actions); err != nil {
		return nil, err
	}
	return actions, nil
}

func (c *Client) ReportActionResult(ctx context.Context, actionID string, result api.ActionResult) error {
	return c.postJSON(ctx, "/api/v1/actions/"+actionID+"/result", result)
}
