package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpcom3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpcom4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpeq2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpeq3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpeq4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpinfo6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mps1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mps2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mps3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mps4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpsw2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc5"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opcont3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp10"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp8"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp9"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opmon2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opmon3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opnub1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/groupconf"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/hostprofile"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/maturity"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/run"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/scope"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/store"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/wazuhapi"
)

var version = "dev"

const (
	passwordEnv    = "OSC_INDEXER_PASSWORD"
	apiPasswordEnv = "OSC_WAZUH_API_PASSWORD"
)

func main() {
	if err := runMain(); err != nil {
		slog.Error("oscompliance-engine", "error", err)
		os.Exit(1)
	}
}

func runMain() error {
	indexerURL := flag.String("indexer", "https://wazuh.indexer:9200", "indexer URLs, comma-separated; the next one is tried when one does not answer")
	user := flag.String("user", "admin", "indexer user; password in $"+passwordEnv+"; least privilege: catalog/wazuh/engine-role.json")
	caFile := flag.String("ca", "", "CA certificate for the indexer (PEM)")
	alerts := flag.String("alerts-index", "wazuh-alerts-*", "index pattern holding the facts")
	monitoring := flag.String("monitoring-index", "wazuh-monitoring-*", "index pattern listing the registered agents")
	states := flag.String("states-prefix", "wazuh-states-", "prefix of Wazuh's state indices (inventory)")
	verdicts := flag.String("verdicts-index", "oscompliance-verdicts", "index the verdicts are written to")
	configIndex := flag.String("config-index", "wazuh-ens-configuration", "plugin index holding the policy parameters")
	historyIndex := flag.String("history-index", "oscompliance-identity-history", "index of the per-account history (EV-08)")
	window := flag.Duration("window", 26*time.Hour, "only facts newer than this count")
	lookback := flag.Duration("lookback", 7*24*time.Hour, "agents with facts this recent are judged")
	interval := flag.Duration("interval", 0, "time between passes; 0 runs one pass and exits")
	apiURL := flag.String("wazuh-api", "", "Wazuh API URL; empty leaves the group configuration alone")
	apiUser := flag.String("wazuh-api-user", "oscompliance", "Wazuh API user; password in $"+apiPasswordEnv+"; least privilege: catalog/wazuh/engine-api-role.json")
	apiCA := flag.String("wazuh-api-ca", "", "certificate the Wazuh API is trusted with (PEM)")
	apiServerName := flag.String("wazuh-api-server-name", "", "name checked in the Wazuh API certificate, when it differs from the URL host")
	syncInterval := flag.Duration("sync-interval", 15*time.Minute, "minimum time between two group configuration syncs")
	syncApply := flag.Bool("sync-apply", false, "write the group configuration; without it the changes are only logged and recorded")
	configHistoryIndex := flag.String("config-history-index", "oscompliance-config-history", "index recording every group configuration change")
	hostProfileIndex := flag.String("host-profile-index", "oscompliance-host-profile", "index of what the engine deduces about each machine from the Wazuh inventory")
	profileGroups := flag.Bool("profile-groups", false, "put each machine in the Wazuh group ens-perfil-<id> of every profile it gets, with the label ens.perfil.<id>")
	onlyControls := flag.String("controls", "", "comma-separated controls to judge, such as op.acc.1; empty judges all of them")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	password := os.Getenv(passwordEnv)
	if password == "" {
		return fmt.Errorf("$%s is not set", passwordEnv)
	}
	if *lookback < *window {
		return fmt.Errorf("-lookback (%s) must not be shorter than -window (%s)", *lookback, *window)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := indexer.New(*indexerURL, *user, password, *caFile)
	if err != nil {
		return err
	}

	sink, err := store.NewVerdicts(ctx, client, *verdicts)
	if err != nil {
		return fmt.Errorf("verdicts index: %w", err)
	}

	hist, err := store.NewHistory(ctx, client, *historyIndex)
	if err != nil {
		return fmt.Errorf("history index: %w", err)
	}

	facts := source.New(client, *alerts, *monitoring, *states)

	profiles, err := store.NewHostProfiles(ctx, client, *hostProfileIndex)
	if err != nil {
		return fmt.Errorf("host profile index: %w", err)
	}

	var groups *groupSync
	var api *wazuhapi.Client
	if *apiURL != "" {
		apiPassword := os.Getenv(apiPasswordEnv)
		if apiPassword == "" {
			return fmt.Errorf("$%s is not set", apiPasswordEnv)
		}
		if api, err = wazuhapi.New(*apiURL, *apiUser, apiPassword, *apiCA, *apiServerName); err != nil {
			return err
		}
		history, err := store.NewConfigHistory(ctx, client, *configHistoryIndex)
		if err != nil {
			return fmt.Errorf("config history index: %w", err)
		}
		groups = &groupSync{api: api, history: history, every: *syncInterval, apply: *syncApply, profiles: *profileGroups,
			requests: func(ctx context.Context, now time.Time) (map[string]string, error) {
				return requestedGroups(ctx, facts, now.Add(-*window))
			}}
		facts.UseManagerInventory(func(ctx context.Context) (*source.Inventory, error) { return managerInventory(ctx, api) })
		facts.UseManager(func(ctx context.Context) (*source.Manager, error) { return managerState(ctx, api) })
		facts.UseManagerName(func(ctx context.Context) (string, error) { return api.AgentName(ctx, source.ManagerID) })
		facts.UseManagerNetwork(func(ctx context.Context, tools []string) (*source.Network, error) {
			return managerNetwork(ctx, api, tools)
		})
	}

	controls := []evaluator.Evaluator{
		opacc1.NewEvaluator(facts, hist),
		opacc2.NewEvaluator(facts),
		opacc3.NewEvaluator(facts),
		opacc4.NewEvaluator(facts),
		opacc5.NewEvaluator(facts),
		opacc6.NewEvaluator(facts, hist),
		opexp1.NewEvaluator(facts),
		opexp2.NewEvaluator(facts),
		opexp3.NewEvaluator(facts),
		opexp4.NewEvaluator(facts),
		opexp5.NewEvaluator(facts),
		opexp6.NewEvaluator(facts),
		opexp7.NewEvaluator(facts),
		opexp8.NewEvaluator(facts),
		opexp9.NewEvaluator(facts),
		opexp10.NewEvaluator(facts),
		mpinfo6.NewEvaluator(facts),
		opmon1.NewEvaluator(facts),
		opmon2.NewEvaluator(facts, sink),
		opmon3.NewEvaluator(facts),
		opcont2.NewEvaluator(facts),
		opcont3.NewEvaluator(facts),
		opnub1.NewEvaluator(facts),
		mpcom1.NewEvaluator(facts),
		mpcom3.NewEvaluator(facts),
		mpcom4.NewEvaluator(facts),
		mpeq2.NewEvaluator(facts),
		mpeq3.NewEvaluator(facts),
		mpeq4.NewEvaluator(facts),
		mps1.NewEvaluator(facts),
		mps2.NewEvaluator(facts),
		mps3.NewEvaluator(facts),
		mps4.NewEvaluator(facts),
		mpsw2.NewEvaluator(facts),
	}
	controls, err = selectControls(controls, *onlyControls)
	if err != nil {
		return err
	}
	if groups != nil {
		groups.controls = catalogControls(controls)
	}

	var current *params.Config
	cfg := run.Config{
		Window: *window, Lookback: *lookback, EngineVersion: version,
		Scope: func(ctx context.Context, since time.Time) (run.Scope, error) {
			memberships, err := groupMemberships(ctx, facts, api, since)
			if err != nil {
				return nil, err
			}
			machines := scope.MachinesOf(current, memberships)
			facts.UseExclusions(machines.Excluded)
			return machines, nil
		},
		Plan: func(agents []verdict.Agent) {
			facts.Plan(agents)
			hist.Plan(agents)
		},
		Flush: hist.Flush,
		WorkingDays: func(ctx context.Context, control string, now time.Time) (map[string]int, error) {
			return sink.WorkingDays(ctx, control, now, maturity.PeriodDays-1)
		},
	}

	for {

		var policy params.Lister
		loaded, err := params.Load(ctx, client, *configIndex)
		if errors.Is(err, params.ErrNotSaved) {
			slog.Info("parameters", "using", "catalog default", "reason", err.Error())
			loaded, err = params.Default(), nil
		}
		if err != nil {
			slog.Warn("parameters", "error", err)
			policy = params.Unavailable(err)
		} else {
			if platforms, err := facts.Platforms(ctx, time.Now().Add(-*lookback)); err != nil {
				slog.Warn("inventory platforms", "error", err)
			} else {
				loaded.UseInventoryTypes(platforms)
			}
			custom, err := params.LoadProfiles(ctx, client, *configIndex)
			if err != nil {
				slog.Warn("profiles", "error", err)
			}
			loaded.UseProfiles(custom)
			loaded.UseHostFacts(profileHosts(ctx, facts, profiles, time.Now().Add(-*lookback)))
			policy, current = loaded, loaded
			cfg.Assessments = loaded.Maturity.Assessments
			cfg.Scales = loaded.Maturity.Scales
			groups.run(ctx, loaded, time.Now())
		}

		if current == nil {
			slog.Error("pass", "error", "the ENS scope has never been read: nothing to judge yet")
			if *interval == 0 {
				return errors.New("the ENS scope could not be read")
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(*interval):
			}
			continue
		}

		start, before := time.Now(), client.Requests()
		n, err := run.Once(ctx, facts, controls, policy, sink, cfg, time.Now())
		took, requests := time.Since(start).Round(time.Millisecond), client.Requests()-before
		if err != nil {
			slog.Error("pass", "verdicts", n, "seconds", took.Seconds(), "requests", requests, "error", err)
		} else {
			slog.Info("pass", "verdicts", n, "seconds", took.Seconds(), "requests", requests)
		}

		if *interval == 0 {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*interval):
		}
	}
}

func selectControls(all []evaluator.Evaluator, names string) ([]evaluator.Evaluator, error) {

	if names == "" {
		return all, nil
	}

	byName := make(map[string]evaluator.Evaluator, len(all))
	for _, ev := range all {
		byName[ev.Control()] = ev
	}

	var selected []evaluator.Evaluator
	for _, name := range strings.Split(names, ",") {
		ev, ok := byName[strings.TrimSpace(name)]
		if !ok {
			return nil, fmt.Errorf("-controls: unknown control %q", name)
		}
		selected = append(selected, ev)
	}

	return selected, nil
}

func catalogControls(judged []evaluator.Evaluator) []catalog.Control {

	var out []catalog.Control
	for _, ev := range judged {
		if control, ok := catalog.LookupControl(ev.Control()); ok {
			out = append(out, control)
		}
	}

	return out
}

type groupSync struct {
	api      *wazuhapi.Client
	controls []catalog.Control
	history  *store.ConfigHistory
	requests func(ctx context.Context, now time.Time) (map[string]string, error)
	every    time.Duration
	apply    bool
	profiles bool
	last     time.Time
}

func (g *groupSync) run(ctx context.Context, policy *params.Config, now time.Time) {

	if g == nil || now.Sub(g.last) < g.every {
		return
	}
	g.last = now

	if policy.Scope.ControlGroups {
		changes, err := groupconf.CreateExclusionGroups(ctx, g.api, g.controls, g.apply, now)
		g.record(ctx, changes, err)
	}

	groups := policy.Groups()
	if len(groups) == 0 {
		slog.Warn("group configuration", "error", "the ENS scope names no Wazuh group: the engine only configures a scope by group")
		return
	}

	changes, err := groupconf.CreateGroups(ctx, g.api, groups, g.apply, now)
	g.record(ctx, changes, err)

	if requests, err := g.requests(ctx, now); err != nil {
		slog.Warn("group requests", "error", err)
	} else {
		changes, err := groupconf.Assign(ctx, g.api, requests, groups, g.apply, now)
		g.record(ctx, changes, err)
		if outside := groupconf.OutOfScope(requests, groups); len(outside) > 0 {
			slog.Warn("group requests", "error", "agents ask to join groups outside the ENS scope", "groups", outside)
		}
	}

	changes, err = groupconf.Sync(ctx, g.api, policy, groups, g.apply, now)
	g.record(ctx, changes, err)

	if g.profiles && policy.KnowsHosts() {
		changes, err = groupconf.PublishProfiles(ctx, g.api, policy.ProfileMembers(), g.apply, now)
		g.record(ctx, changes, err)
	}
}

// The Wazuh API answers with the groups an agent is in now; the monitoring
// index only samples them every few minutes, so a fresh exclusion can be missing.
func groupMemberships(ctx context.Context, facts *source.Source, api *wazuhapi.Client, since time.Time) (map[string]source.Reporting, error) {

	if api == nil {
		return facts.FleetReporting(ctx, since)
	}

	agents, err := api.AgentMemberships(ctx)
	if err != nil {
		return nil, fmt.Errorf("group memberships: %w", err)
	}

	out := make(map[string]source.Reporting, len(agents))
	for _, a := range agents {
		out[a.ID] = source.Reporting{Name: a.Name, Groups: a.Group}
	}
	return out, nil
}

func requestedGroups(ctx context.Context, facts *source.Source, since time.Time) (map[string]string, error) {

	passes, err := facts.AgentPasses(ctx, since)
	if err != nil {
		return nil, err
	}

	requests := map[string]string{}
	for agentID, pass := range passes {
		if pass.RequestedGroup != "" {
			requests[agentID] = pass.RequestedGroup
		}
	}

	return requests, nil
}

func (g *groupSync) record(ctx context.Context, changes []groupconf.Change, err error) {

	for _, c := range changes {
		slog.Info("group configuration", "group", c.Group, "agents", c.Agents, "applied", c.Applied)
		if err := g.history.Write(ctx, c); err != nil {
			slog.Warn("group configuration history", "group", c.Group, "error", err)
		}
	}
	if err != nil {
		slog.Error("group configuration", "error", err)
	}
}

func profileHosts(ctx context.Context, facts *source.Source, profiles *store.HostProfiles, since time.Time) map[string]catalog.HostFacts {

	reporting, err := facts.FleetReporting(ctx, since)
	if err != nil {
		slog.Warn("host profiles", "error", err)
		return nil
	}

	signals := catalog.Signals()
	exact, prefixes := signals.PackageNames()
	inventories, err := facts.HostInventories(ctx, exact, prefixes)
	if err != nil {
		slog.Warn("host profiles", "error", err)
		return nil
	}

	if _, ok := reporting[source.ManagerID]; !ok {
		reporting[source.ManagerID] = source.Reporting{}
	}

	now := time.Now()
	out := make([]hostprofile.Profile, 0, len(reporting))
	hosts := make(map[string]catalog.HostFacts, len(reporting))
	for id, r := range reporting {
		p := hostprofile.Build(verdict.Agent{ID: id, Name: r.Name}, r.Groups, inventories[id], signals, now, version)
		out = append(out, p)
		hosts[id] = p.Facts()
	}

	if err := profiles.Write(ctx, out); err != nil {
		slog.Warn("host profiles", "error", err)
	} else {
		slog.Info("host profiles", "machines", len(out))
	}
	return hosts
}

func managerInventory(ctx context.Context, api *wazuhapi.Client) (*source.Inventory, error) {

	s, err := api.AgentSyscollector(ctx, source.ManagerID)
	if err != nil {
		return nil, err
	}

	inv := &source.Inventory{Packages: s.Packages, Vendors: s.Vendors, Addresses: s.Addresses, Listening: s.Listening, Processes: s.Processes}
	if s.HasOS {
		inv.System = &source.System{OS: s.OS, Version: s.Version, Kernel: s.Kernel, Architecture: s.Architecture}
	}
	if s.HasHardware {
		inv.Hardware = &source.Hardware{Cores: s.Cores, MemoryMB: int(s.MemoryKB / 1024)}
	}
	return inv, nil
}
