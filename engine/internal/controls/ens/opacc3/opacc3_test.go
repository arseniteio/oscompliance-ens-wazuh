package opacc3

import (
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var p03 = ParseFunctions([]string{
	"desarrollo | /usr/bin/git",
	"Operación | /usr/bin/systemctl | /usr/bin/crontab",
	"configuracion | /usr/bin/vim",
	"mantenimiento | /usr/bin/apt",
	"auditoria | /usr/sbin/ausearch",
})

func names(agentID, uid string) (string, bool) {
	m := map[string]string{"1000": "ana", "1001": "bob", "1002": "carla"}
	n, ok := m[uid]
	return n, ok
}

func exec(agent, auid, exe string) source.ActionCount {
	return source.ActionCount{AgentID: agent, AUID: auid, Exe: exe, Key: "oscompliance_exec", Count: 1}
}

func TestNormalizeAndPairs(t *testing.T) {

	if normalize(" Auditoría ") != "auditoria" || normalize("OPERACIÓN") != "operacion" {
		t.Error("accents and case")
	}

	pairs := ParsePairs([]string{"desarrollo | operación", "* | auditoría"})
	if p, ok := declared(pairs, requirementPair["EV-01"]); !ok || p.Right != "operacion" {
		t.Errorf("accented pair: %+v %v", p, ok)
	}
	if p, ok := declared(pairs, requirementPair["EV-05"]); !ok || p.Left != "auditoria" || p.Right != "*" {
		t.Errorf("reversed wildcard: %+v %v", p, ok)
	}
}

func TestJudgePair(t *testing.T) {

	pairs := ParsePairs([]string{"desarrollo | operacion", "configuracion | mantenimiento"})

	fleet := BuildFleet([]source.ActionCount{
		exec("001", "1000", "/usr/bin/git"),
		exec("002", "1000", "/usr/bin/systemctl"),
		exec("001", "1001", "/usr/bin/git"),
		{AgentID: "001", User: "carla", Exe: "/usr/bin/apt install x", Key: "sudo", Count: 1},
	}, p03, nil, names)

	in := Input{AgentID: "001", Fleet: fleet, Functions: p03, Pairs: pairs}
	check(t, "cross-machine", JudgePair("EV-01", in), verdict.NonCompliant, "", "ana: desarrollo (/usr/bin/git) + operacion (/usr/bin/systemctl)")

	in.AgentID = "003"
	check(t, "not active here", JudgePair("EV-01", in), verdict.Compliant, "", "no account holds")

	in.AgentID = "001"
	check(t, "maintenance only", JudgePair("EV-04", in), verdict.Compliant, "", "")
	check(t, "pair not declared", JudgePair("EV-02", in), verdict.NotEvaluable, verdict.CauseConfiguration, "autorizacion | control")

	in.Chain = catalog.Says("chain.auditd", "state", catalog.Says("auditd.absent"), "error", "")
	check(t, "blind silence", JudgePair("EV-04", in), verdict.NotEvaluable, verdict.CauseCollection, "auditd absent")
	check(t, "a breach stands", JudgePair("EV-01", in), verdict.NonCompliant, "", "ana")

	check(t, "params", JudgePair("EV-01", Input{Problem: catalog.Says("param.not_set", "param", "P-03")}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-03")
}

func TestJudgeTasks(t *testing.T) {

	tasks, problems := ParseTasks([]string{"Despliegue | 2 | /usr/local/bin/deploy"})
	if len(problems) > 0 {
		t.Fatal(problems)
	}

	alone := BuildFleet([]source.ActionCount{exec("001", "1000", "/usr/local/bin/deploy")}, p03, tasks, names)
	check(t, "one person", JudgeTasks(Input{AgentID: "001", Fleet: alone, Tasks: tasks}), verdict.NonCompliant, "", "Despliegue (1 of 2 people: ana)")

	two := BuildFleet([]source.ActionCount{exec("001", "1000", "/usr/local/bin/deploy"), exec("002", "1001", "/usr/local/bin/deploy")}, p03, tasks, names)
	check(t, "two people", JudgeTasks(Input{AgentID: "001", Fleet: two, Tasks: tasks}), verdict.Compliant, "", "2 of 2")
	check(t, "not run here", JudgeTasks(Input{AgentID: "009", Fleet: two, Tasks: tasks}), verdict.Compliant, "", "no critical task run")

	_, problems = ParseTasks([]string{"Despliegue | 2", "Backup | 1 | x"})
	check(t, "rows unusable", JudgeTasks(Input{TaskProblems: problems}), verdict.NotEvaluable, verdict.CauseConfiguration, "no indicator")
}

func TestJudgeAuditors(t *testing.T) {

	fleet := BuildFleet([]source.ActionCount{
		exec("001", "1002", "/usr/sbin/ausearch"),
		exec("001", "1002", "/usr/bin/apt"),
	}, p03, nil, names)

	check(t, "P-05 account maintains", JudgeAuditors(Input{AgentID: "001", Fleet: fleet, Auditors: []string{"carla"}}), verdict.NonCompliant, "", "audit account carla also does mantenimiento")
	check(t, "wildcard", JudgeAuditors(Input{AgentID: "001", Fleet: fleet, Pairs: ParsePairs([]string{"auditoria | *"})}), verdict.NonCompliant, "", "carla")
	check(t, "nothing declared", JudgeAuditors(Input{AgentID: "001", Fleet: fleet}), verdict.NotEvaluable, verdict.CauseConfiguration, "")
}

func TestInventoryAndSecurity(t *testing.T) {

	fleet := BuildFleet([]source.ActionCount{
		exec("001", "1000", "/usr/bin/git"),
		{AgentID: "001", AUID: "1001", Path: "/var/log/audit/audit.log", Key: "oscompliance_read", Count: 2},
		exec("001", "7777", "/usr/bin/git"),
	}, p03, nil, names)

	check(t, "unnamed uid", JudgeInventory(Input{AgentID: "001", Fleet: fleet}), verdict.NotEvaluable, verdict.CauseEvidence, "1 actions")
	check(t, "security", JudgeSecurity(Input{AgentID: "001", Fleet: fleet}), verdict.Compliant, "", "bob /var/log/audit/audit.log")

	named := BuildFleet([]source.ActionCount{exec("001", "1000", "/usr/bin/git")}, p03, nil, names)
	check(t, "inventory", JudgeInventory(Input{AgentID: "001", Fleet: named}), verdict.Compliant, "", "ana (desarrollo)")
}

func TestChain(t *testing.T) {

	config := &fact.WazuhAgentConfig{Status: fact.SourceRead, Localfiles: []fact.AgentLocalfile{{Location: "/var/log/audit/audit.log", Format: "audit"}}}
	running := &fact.AuditWatchSnapshot{Auditd: fact.AuditdRunning,
		ExecLoaded: []string{"/usr/bin/git", "/usr/bin/systemctl", "/usr/bin/crontab", "/usr/bin/vim", "/usr/bin/apt", "/usr/sbin/ausearch"}}

	if c := Chain(running, config, p03); !c.IsZero() {
		t.Errorf("complete chain: %q", c)
	}
	partial := *running
	partial.ExecLoaded = partial.ExecLoaded[:2]
	if c := Chain(&partial, config, p03); !strings.Contains(c.Render("en"), "/usr/bin/vim") {
		t.Errorf("unwatched: %q", c)
	}
	if c := Chain(&fact.AuditWatchSnapshot{Auditd: fact.AuditdAbsent}, config, p03); !strings.Contains(c.Render("en"), "absent") {
		t.Errorf("no auditd: %q", c)
	}
	if c := Chain(running, &fact.WazuhAgentConfig{Status: fact.SourceRead}, p03); !strings.Contains(c.Render("en"), "auditd audit log") {
		t.Errorf("no audit localfile: %q", c)
	}
}
