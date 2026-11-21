package source

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Manager struct {
	Daemons       map[string]string
	Rules         []Rule
	RuleExclude   []string
	Responses     []Response
	Email         Email
	Integrations  []Integration
	Vulnerability bool
	Version       string
	Installed     time.Time
}

type Rule struct {
	ID         int
	Level      int
	File       string
	Dir        string
	Groups     []string
	Mitre      []string
	Frequency  int
	Correlates bool
}

func (r Rule) Custom() bool { return r.Dir == "etc/rules" }

type Response struct {
	Command  string
	Rules    string
	Groups   string
	Level    string
	Location string
	Disabled bool
}

type Email struct {
	Enabled bool
	To      []string
	Level   int
}

type Integration struct {
	Name   string
	Level  int
	Groups string
}

var ErrNoManagerAPI = errors.New("the engine has no Wazuh API to read the manager (-wazuh-api)")

type freshCache[T any] struct {
	mu    sync.Mutex
	read  func(ctx context.Context) (T, error)
	at    time.Time
	value T
	err   error
}

func (c *freshCache[T]) get(ctx context.Context) (T, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.at) < managerFresh {
		return c.value, c.err
	}
	c.value, c.err = c.read(ctx)
	c.at = time.Now()
	return c.value, c.err
}

const managerFresh = 5 * time.Minute

func (s *Source) UseManager(read func(ctx context.Context) (*Manager, error)) {
	s.manager.read = read
}

func (s *Source) Manager(ctx context.Context) (*Manager, error) {
	if s.manager.read == nil {
		return nil, ErrNoManagerAPI
	}
	return s.manager.get(ctx)
}
