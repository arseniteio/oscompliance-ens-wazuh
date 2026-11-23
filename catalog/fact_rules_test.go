package catalog

import (
	"os"
	"regexp"
	"testing"
)

func TestRule119007MatchesWindowsAgentEvents(t *testing.T) {

	rules, err := os.ReadFile("wazuh/oscompliance_facts_rules.xml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<rule id="119007".*?<location type="pcre2">([^<]+)</location>`).FindSubmatch(rules)
	if m == nil {
		t.Fatal("rule 119007 has no pcre2 location")
	}
	location := regexp.MustCompile(string(m[1]))

	// analysisd matches an agent event against "(name) ip->path"; wazuh-logtest uses the bare path.
	for _, l := range []string{`(dc01) any->C:\ProgramData\oscompliance\facts.ndjson`, `(dc01) 10.0.0.5->C:\ProgramData\oscompliance\facts.ndjson`, `C:\ProgramData\oscompliance\facts.ndjson`} {
		if !location.MatchString(l) {
			t.Errorf("rule 119007 misses %s", l)
		}
	}
	for _, l := range []string{`(dc01) any->EventChannel`, `(dc01) any->C:\ProgramData\oscompliance\facts.ndjson.old`, `journald`} {
		if location.MatchString(l) {
			t.Errorf("rule 119007 accepts %s", l)
		}
	}
}
