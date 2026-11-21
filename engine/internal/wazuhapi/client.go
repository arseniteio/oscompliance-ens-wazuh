package wazuhapi

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
	"slices"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL  string
	user     string
	password string
	http     *http.Client

	mu    sync.Mutex
	token string
}

type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	OS   struct {
		Platform string `json:"platform"`
	} `json:"os"`
}

func New(baseURL, user, password, caFile, serverName string) (*Client, error) {

	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("wazuh api: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("wazuh api: no certificate in %s", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig

	return &Client{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		user:     user,
		password: password,
		http:     &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}, nil
}

type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("wazuh api: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) authenticate(ctx context.Context) (string, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" {
		return c.token, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.user, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("wazuh api: authenticate: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Status: resp.StatusCode, Body: string(body)}
	}

	c.token = strings.TrimSpace(string(body))
	return c.token, nil
}

func (c *Client) forget(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		c.token = ""
	}
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {

	for attempt := 0; ; attempt++ {

		token, err := c.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("wazuh api: %s %s: %w", method, path, err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.forget(token)
			// Wazuh revokes tokens issued in the same second as an RBAC change, such as engine-users.sh creating the engine role.
			select {
			case <-time.After(tokenRetryDelay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}
		if resp.StatusCode >= 300 {
			return nil, &Error{Status: resp.StatusCode, Body: string(out)}
		}

		return out, nil
	}
}

const agentsPage = 500

var tokenRetryDelay = 2 * time.Second

func (c *Client) GroupAgents(ctx context.Context, group string) ([]Agent, error) {

	var agents []Agent

	for offset := 0; ; offset += agentsPage {

		path := fmt.Sprintf("/groups/%s/agents?select=id,name,os.platform&limit=%d&offset=%d", url.PathEscape(group), agentsPage, offset)
		body, err := c.do(ctx, http.MethodGet, path, "", nil)
		if err != nil {
			return nil, err
		}

		var page struct {
			Data struct {
				AffectedItems      []Agent `json:"affected_items"`
				TotalAffectedItems int     `json:"total_affected_items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("wazuh api: agents of %s: %w", group, err)
		}

		agents = append(agents, page.Data.AffectedItems...)
		if len(page.Data.AffectedItems) < agentsPage || len(agents) >= page.Data.TotalAffectedItems {
			return agents, nil
		}
	}
}

type AgentMembership struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Group []string `json:"group"`
}

func (c *Client) AgentMemberships(ctx context.Context) ([]AgentMembership, error) {

	var agents []AgentMembership

	for offset := 0; ; offset += agentsPage {

		var page []AgentMembership
		total, err := c.items(ctx, "/agents?select=id,name,group", agentsPage, offset, &page)
		if err != nil {
			return nil, err
		}

		agents = append(agents, page...)
		if len(page) < agentsPage || len(agents) >= total {
			return agents, nil
		}
	}
}

func (c *Client) GroupNames(ctx context.Context) ([]string, error) {

	var names []string

	for offset := 0; ; offset += agentsPage {

		var page []struct {
			Name string `json:"name"`
		}
		total, err := c.items(ctx, "/groups?select=name", agentsPage, offset, &page)
		if err != nil {
			return nil, err
		}

		for _, g := range page {
			names = append(names, g.Name)
		}
		if len(page) < agentsPage || len(names) >= total {
			return names, nil
		}
	}
}

func (c *Client) CreateGroup(ctx context.Context, name string) error {

	body, err := json.Marshal(map[string]string{"group_id": name})
	if err != nil {
		return err
	}

	_, err = c.do(ctx, http.MethodPost, "/groups", "application/json", body)
	return err
}

const assignBatch = 500

func (c *Client) AssignAgents(ctx context.Context, group string, agentIDs []string) error {
	return c.changeGroup(ctx, http.MethodPut, group, agentIDs)
}

func (c *Client) RemoveAgents(ctx context.Context, group string, agentIDs []string) error {
	return c.changeGroup(ctx, http.MethodDelete, group, agentIDs)
}

func (c *Client) changeGroup(ctx context.Context, method, group string, agentIDs []string) error {

	for start := 0; start < len(agentIDs); start += assignBatch {

		batch := agentIDs[start:min(start+assignBatch, len(agentIDs))]
		path := fmt.Sprintf("/agents/group?group_id=%s&agents_list=%s", url.QueryEscape(group), url.QueryEscape(strings.Join(batch, ",")))
		body, err := c.do(ctx, method, path, "", nil)
		if err != nil {
			return err
		}

		var answer struct {
			Data struct {
				FailedItems []struct {
					Error struct {
						Message string `json:"message"`
					} `json:"error"`
					ID []string `json:"id"`
				} `json:"failed_items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &answer); err != nil {
			return fmt.Errorf("wazuh api: agents of group %s: %w", group, err)
		}
		if failed := answer.Data.FailedItems; len(failed) > 0 {
			return fmt.Errorf("wazuh api: agents of group %s: %v: %s", group, failed[0].ID, failed[0].Error.Message)
		}
	}

	return nil
}

func (c *Client) AgentName(ctx context.Context, agentID string) (string, error) {

	body, err := c.do(ctx, http.MethodGet, "/agents?agents_list="+url.QueryEscape(agentID)+"&select=name", "", nil)
	if err != nil {
		return "", err
	}

	var page struct {
		Data struct {
			AffectedItems []Agent `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return "", fmt.Errorf("wazuh api: agent %s: %w", agentID, err)
	}
	if len(page.Data.AffectedItems) == 0 {
		return "", fmt.Errorf("wazuh api: agent %s not found", agentID)
	}
	return page.Data.AffectedItems[0].Name, nil
}

func (c *Client) GroupConfiguration(ctx context.Context, group string) (string, error) {

	body, err := c.do(ctx, http.MethodGet, "/groups/"+url.PathEscape(group)+"/files/agent.conf?raw=true", "", nil)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (c *Client) PutGroupConfiguration(ctx context.Context, group, conf string) error {

	_, err := c.do(ctx, http.MethodPut, "/groups/"+url.PathEscape(group)+"/configuration", "application/xml", []byte(conf))
	return err
}

type Syscollector struct {
	OS           string
	Version      string
	Kernel       string
	Architecture string
	Cores        int
	MemoryKB     int64
	Packages     map[string]int
	Vendors      []string
	Addresses    []string
	Listening    int
	Processes    int
	HasOS        bool
	HasHardware  bool
}

const inventoryPage = 500

func (c *Client) AgentSyscollector(ctx context.Context, agentID string) (*Syscollector, error) {

	base := "/syscollector/" + url.PathEscape(agentID)
	out := &Syscollector{Packages: map[string]int{}}

	var system []struct {
		Architecture string `json:"architecture"`
		OS           struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		Release string `json:"release"`
	}
	if _, err := c.items(ctx, base+"/os", 0, 0, &system); err != nil {
		return nil, err
	}
	if len(system) > 0 {
		out.HasOS = true
		out.OS, out.Version, out.Kernel, out.Architecture = system[0].OS.Name, system[0].OS.Version, system[0].Release, system[0].Architecture
	}

	var hw []struct {
		CPU struct {
			Cores int `json:"cores"`
		} `json:"cpu"`
		RAM struct {
			Total int64 `json:"total"`
		} `json:"ram"`
	}
	if _, err := c.items(ctx, base+"/hardware", 0, 0, &hw); err != nil {
		return nil, err
	}
	if len(hw) > 0 {
		out.HasHardware = true
		out.Cores, out.MemoryKB = hw[0].CPU.Cores, hw[0].RAM.Total
	}

	for offset := 0; ; offset += inventoryPage {
		var page []struct {
			Format string `json:"format"`
			Vendor string `json:"vendor"`
		}
		total, err := c.items(ctx, base+"/packages?select=format,vendor", inventoryPage, offset, &page)
		if err != nil {
			return nil, err
		}
		for _, p := range page {
			out.Packages[p.Format]++
			if p.Vendor != "" && !slices.Contains(out.Vendors, p.Vendor) {
				out.Vendors = append(out.Vendors, p.Vendor)
			}
		}
		if len(page) < inventoryPage || offset+len(page) >= total {
			break
		}
	}

	var addresses []struct {
		Address string `json:"address"`
	}
	if _, err := c.items(ctx, base+"/netaddr?select=address", inventoryPage, 0, &addresses); err != nil {
		return nil, err
	}
	for _, a := range addresses {
		out.Addresses = append(out.Addresses, a.Address)
	}

	var none []struct{}
	var err error
	if out.Listening, err = c.items(ctx, base+"/ports?state=listening", 1, 0, &none); err != nil {
		return nil, err
	}
	if out.Processes, err = c.items(ctx, base+"/processes", 1, 0, &none); err != nil {
		return nil, err
	}

	return out, nil
}

func (c *Client) items(ctx context.Context, path string, limit, offset int, v any) (int, error) {

	if limit > 0 {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path = fmt.Sprintf("%s%slimit=%d&offset=%d", path, sep, limit, offset)
	}
	body, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return 0, err
	}

	var page struct {
		Data struct {
			AffectedItems      json.RawMessage `json:"affected_items"`
			TotalAffectedItems int             `json:"total_affected_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, fmt.Errorf("wazuh api: %s: %w", path, err)
	}
	if err := json.Unmarshal(page.Data.AffectedItems, v); err != nil {
		return 0, fmt.Errorf("wazuh api: %s: %w", path, err)
	}
	return page.Data.TotalAffectedItems, nil
}
