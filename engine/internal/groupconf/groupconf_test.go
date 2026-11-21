package groupconf

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/wazuhapi"
)

func policyOf(t *testing.T, doc string) *params.Config {
	t.Helper()
	var c params.Config
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

const fleet = `{
  "scope": {"mode": "group", "groupIds": ["ens"]},
  "controls": [
    {"controlId": "op.acc.2", "parameters": [
      {"id": "P-02", "value": ["/etc/passwd", "/srv/app/config"]},
      {"id": "P-06", "value": ["admin | /srv/datos | r,w"]},
      {"id": "P-08", "value": ["/etc/ssh | 0755 | root"]}
    ]},
    {"controlId": "op.acc.3", "parameters": [
      {"id": "P-03", "value": ["desarrollo | /usr/bin/git | /srv/repos", "operacion | systemctl"]}
    ]},
    {"controlId": "op.acc.4", "parameters": [{"id": "P-07", "value": ["/datos/rrhh | rrhh"]}]},
    {"controlId": "op.acc.5", "parameters": [{"id": "P-02", "value": ["sede | web01 | /var/log/sede/auth.json"]}]},
    {"controlId": "op.exp.2", "parameters": [{"id": "P-08", "value": ["/etc/shadow | 640 | root", "/etc/ssh | 755 | root"]}]},
    {"controlId": "op.exp.3", "parameters": [
      {"id": "P-04", "value": ["/etc/ssh"]},
      {"id": "P-07", "value": ["sistema | git:/etc/ | git interno", "copias | /var/backups/etc-*.tgz | NAS", "otra | en la nube | x"]}
    ]}
  ],
  "agents": {"003": {"controls": {"op.acc.2": {"parameters": {"P-08": ["/opt/other | 0700 | root"]}}}}}
}`

func TestForAgent(t *testing.T) {

	m := ForAgent(policyOf(t, fleet), "001", "web01", "linux")

	if strings.Join(m.FIM, ",") != "/srv/app/config,/var/ossec/etc" {
		t.Errorf("FIM: only what Wazuh does not watch by default, and the agent configuration: %v", m.FIM)
	}
	if strings.Join(m.Paths.ACL, ",") != "/etc/shadow,/etc/ssh" {
		t.Errorf("ACL: %v", m.Paths.ACL)
	}
	if strings.Join(m.Paths.Backup, ",") != "/var/backups/etc-*.tgz,git:/etc" {
		t.Errorf("backup sources: git directories and absolute patterns of op.exp.3 P-07: %v", m.Paths.Backup)
	}
	if strings.Join(m.Paths.Exec, ",") != "/usr/bin/git" {
		t.Errorf("exec: binaries of P-03: %v", m.Paths.Exec)
	}
	if strings.Join(m.Paths.Audit, ",") != "/etc/ssh" {
		t.Errorf("audit: only the paths whose changes are audited, op.exp.3 P-04: %v", m.Paths.Audit)
	}
	want := "/datos/rrhh,/etc/audit,/srv/datos,/srv/repos,/var/log/audit,/var/ossec/etc"
	if strings.Join(m.Paths.Read, ",") != want {
		t.Errorf("read: %v", m.Paths.Read)
	}
	if len(m.Services) != 1 || m.Services[0].Log != "/var/log/sede/auth.json" {
		t.Errorf("services of web01: %v", m.Services)
	}
	if len(ForAgent(policyOf(t, fleet), "002", "db01", "linux").Services) != 0 {
		t.Error("a service belongs only to the machine its row names")
	}
}

func TestReadWinsOverChange(t *testing.T) {

	m := ForAgent(policyOf(t, `{"controls": [
    {"controlId": "op.acc.4", "parameters": [{"id": "P-07", "value": ["/etc/shadow | rrhh"]}]},
    {"controlId": "op.exp.3", "parameters": [{"id": "P-04", "value": ["/etc/shadow", "/etc/group"]}]}
  ]}`), "001", "web01", "linux")

	if strings.Join(m.Paths.Audit, ",") != "/etc/group" || !slices.Contains(m.Paths.Read, "/etc/shadow") {
		t.Errorf("a path audited for reads is not repeated as a change watch: audit %v, read %v", m.Paths.Audit, m.Paths.Read)
	}
}

func TestRegion(t *testing.T) {

	policy := policyOf(t, fleet)
	agents := []Agent{
		{Name: "web01", Machine: ForAgent(policy, "001", "web01", "linux")},
		{Name: "db01", Machine: ForAgent(policy, "002", "db01", "linux")},
		{Name: "odd01", Machine: ForAgent(policy, "003", "odd01", "linux")},
	}
	region := Region(agents)

	var root struct {
		Blocks []struct {
			Name     string `xml:"name,attr"`
			Comments string `xml:",comment"`
			Logs     []struct {
				Location string `xml:"location"`
			} `xml:"localfile"`
		} `xml:"agent_config"`
	}
	if err := xml.Unmarshal([]byte("<root>"+region+"</root>"), &root); err != nil {
		t.Fatalf("not XML: %v\n%s", err, region)
	}

	names := []string{}
	for _, b := range root.Blocks {
		names = append(names, b.Name)
	}
	if strings.Join(names, ",") != ",odd01,web01" {
		t.Fatalf("one common block, then only the machines that differ: %v", names)
	}
	if !strings.Contains(root.Blocks[0].Comments, `"acl_paths":["/etc/shadow","/etc/ssh"]`) || len(root.Blocks[0].Logs) != 2 {
		t.Errorf("common block: %s", region)
	}
	if !strings.Contains(root.Blocks[1].Comments, `"/opt/other"`) {
		t.Errorf("odd01 carries its own paths: %s", region)
	}
	if strings.Contains(root.Blocks[2].Comments, "acl_paths") || len(root.Blocks[2].Logs) != 1 {
		t.Errorf("web01 only adds its service log: %s", region)
	}
}

func TestMerge(t *testing.T) {

	admin := "<agent_config>\n  <localfile><location>/var/log/app.log</location></localfile>\n</agent_config>\n"
	first := Region([]Agent{{Name: "a", Machine: Machine{}}})

	once := Merge(admin, first)
	if !strings.HasPrefix(once, admin) || Current(once) != first {
		t.Fatalf("appended after what the administrator wrote:\n%s", once)
	}

	second := Region([]Agent{{Name: "a", Machine: Machine{Paths: Paths{ACL: []string{"/x"}}}}})
	twice := Merge(once, second)
	if !strings.HasPrefix(twice, admin) || Current(twice) != second || strings.Count(twice, begin) != 1 {
		t.Fatalf("the region is replaced, never repeated:\n%s", twice)
	}
}

func TestCommentNeverHoldsDoubleHyphen(t *testing.T) {
	var b strings.Builder
	writePaths(&b, Paths{ACL: []string{"/srv/a--b"}})
	inside := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(b.String()), "<!--"), "-->")
	if strings.Contains(inside, "--") {
		t.Errorf("an XML comment cannot hold --: %s", b.String())
	}
	var p Paths
	body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(inside), pathsMarker))
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.ACL[0] != "/srv/a--b" {
		t.Errorf("the path survives: %v %v", p, err)
	}
}

type fakeAPI struct {
	agents map[string][]wazuhapi.Agent
	conf   map[string]string
	puts   int
}

func (f *fakeAPI) GroupAgents(_ context.Context, g string) ([]wazuhapi.Agent, error) {
	return f.agents[g], nil
}

func (f *fakeAPI) GroupConfiguration(_ context.Context, g string) (string, error) {
	return f.conf[g], nil
}

func (f *fakeAPI) PutGroupConfiguration(_ context.Context, g, c string) error {
	f.puts++
	f.conf[g] = c
	return nil
}

func TestSync(t *testing.T) {

	policy := policyOf(t, fleet)
	api := &fakeAPI{
		agents: map[string][]wazuhapi.Agent{"ens": {{ID: "001", Name: "web01"}, {ID: "002", Name: "db01"}}},
		conf:   map[string]string{"ens": "<agent_config>\n</agent_config>\n"},
	}
	now := time.Date(2026, 10, 28, 8, 0, 0, 0, time.UTC)

	planned, err := Sync(context.Background(), api, policy, policy.Groups(), false, now)
	if err != nil || len(planned) != 1 || planned[0].Applied || api.puts != 0 {
		t.Fatalf("without apply nothing is written: %v %v %d", planned, err, api.puts)
	}

	applied, err := Sync(context.Background(), api, policy, policy.Groups(), true, now)
	if err != nil || len(applied) != 1 || !applied[0].Applied || api.puts != 1 {
		t.Fatalf("applied: %v %v %d", applied, err, api.puts)
	}

	api.conf["ens"] = strings.ReplaceAll(api.conf["ens"], "\n", "\n    ")
	again, err := Sync(context.Background(), api, policy, policy.Groups(), true, now)
	if err != nil || len(again) != 0 || api.puts != 1 {
		t.Errorf("nothing changed, nothing written, however the manager indents it: %v %v %d", again, err, api.puts)
	}
}

type fakeMaker struct {
	names   []string
	created []string
	failing string
	denied  bool
	tries   int
}

func (f *fakeMaker) GroupNames(context.Context) ([]string, error) { return f.names, nil }

func (f *fakeMaker) CreateGroup(_ context.Context, name string) error {
	f.tries++
	if f.denied {
		return &wazuhapi.Error{Status: http.StatusForbidden, Body: "Permission denied: Resource type: *:*"}
	}
	if name == f.failing {
		return errors.New("forbidden")
	}
	f.created = append(f.created, name)
	return nil
}

func TestCreateExclusionGroups(t *testing.T) {
	controls := []catalog.Control{{Control: "op.acc.1"}, {Control: "op.acc.2"}, {Control: "op.acc.3"}}
	now := time.Now()

	dry := &fakeMaker{names: []string{"ens", "ens-excluir-op.acc.1"}}
	changes, err := CreateExclusionGroups(context.Background(), dry, controls, false, now)
	if err != nil || len(changes) != 2 || changes[0].Applied || len(dry.created) != 0 {
		t.Errorf("without apply: %v %v created %v", changes, err, dry.created)
	}

	api := &fakeMaker{names: []string{"ens", "ens-excluir-op.acc.1"}, failing: "ens-excluir-op.acc.3"}
	changes, err = CreateExclusionGroups(context.Background(), api, controls, true, now)
	if err == nil {
		t.Error("want the failed group reported")
	}
	if len(changes) != 1 || !changes[0].Applied || changes[0].Group != "ens-excluir-op.acc.2" {
		t.Errorf("changes %v", changes)
	}
}

func TestCreateGroupsStopsAtTheFirstDenial(t *testing.T) {
	controls := []catalog.Control{{Control: "op.acc.1"}, {Control: "op.acc.2"}, {Control: "op.acc.3"}}

	api := &fakeMaker{denied: true}
	changes, err := CreateExclusionGroups(context.Background(), api, controls, true, time.Now())
	if err == nil || !strings.Contains(err.Error(), "group:create") {
		t.Errorf("want one error naming the missing permission, got %v", err)
	}
	if api.tries != 1 || len(changes) != 0 {
		t.Errorf("tries %d, changes %v", api.tries, changes)
	}
}

func TestWindowsMachine(t *testing.T) {

	m := ForAgent(policyOf(t, `{"controls": [
    {"controlId": "op.exp.10", "parameters": [{"id": "P-02", "value": ["C:\\ProgramData\\ssh\\ | Administradores", "/etc/ssh | 600 | root"]}]},
    {"controlId": "op.exp.3", "parameters": [{"id": "P-04", "value": ["C:/Windows/System32/drivers/etc/hosts"]}]},
    {"controlId": "op.acc.2", "parameters": [{"id": "P-02", "value": ["C:\\Windows\\System32\\drivers\\etc\\hosts", "D:\\App\\conf"]}]}
  ]}`), "009", "dc01", "windows")

	if !m.Windows || !slices.Equal(m.Paths.Keys, []string{`C:\ProgramData\ssh`}) {
		t.Errorf("keys %v", m.Paths.Keys)
	}
	if !slices.Contains(m.Paths.Read, `C:\Program Files (x86)\ossec-agent\client.keys`) || slices.Contains(m.Paths.Read, "/var/ossec/etc") {
		t.Errorf("read watches %v", m.Paths.Read)
	}
	if !slices.Equal(m.Paths.Audit, []string{`C:\Windows\System32\drivers\etc\hosts`}) || len(m.Paths.Exec) != 0 {
		t.Errorf("audit %v exec %v", m.Paths.Audit, m.Paths.Exec)
	}
	if !slices.Contains(m.FIM, `D:\App\conf`) || slices.Contains(m.FIM, `C:\Windows\System32\drivers\etc\hosts`) {
		t.Errorf("FIM %v", m.FIM)
	}
}

func TestMixedGroupSeparatesTheOperatingSystems(t *testing.T) {

	policy := policyOf(t, fleet)
	region := Region([]Agent{
		{Name: "web01", Machine: ForAgent(policy, "001", "web01", "linux")},
		{Name: "dc01", Machine: ForAgent(policy, "009", "dc01", "windows")},
	})

	var root struct {
		Blocks []struct {
			Name string `xml:"name,attr"`
			OS   string `xml:"os,attr"`
			Logs []struct {
				Location string `xml:"location"`
			} `xml:"localfile"`
		} `xml:"agent_config"`
	}
	if err := xml.Unmarshal([]byte("<root>"+region+"</root>"), &root); err != nil {
		t.Fatalf("not XML: %v\n%s", err, region)
	}
	if len(root.Blocks) < 2 || root.Blocks[0].OS != "Linux" || root.Blocks[1].OS != "Windows" {
		t.Fatalf("one block per operating system first:\n%s", region)
	}
	for _, l := range root.Blocks[1].Logs {
		if strings.HasPrefix(l.Location, "/") {
			t.Errorf("Windows block reads a Linux file %s", l.Location)
		}
	}
	if root.Blocks[1].Logs[0].Location != WindowsFactsLog {
		t.Errorf("Windows facts file missing:\n%s", region)
	}
}
