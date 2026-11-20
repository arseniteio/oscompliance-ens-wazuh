package opexp10

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Store struct {
	Path  string
	Mode  uint64
	Owner string
}

func ParseStores(rows []string) []Store {
	var out []Store
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 3 {
			c = append(c, "")
		}
		mode, err := strconv.ParseUint(strings.TrimSpace(c[1]), 8, 32)
		if err != nil {
			mode = 0o600
		}
		if p := strings.TrimRight(strings.TrimSpace(c[0]), "/"); p != "" {
			out = append(out, Store{Path: p, Mode: mode, Owner: strings.TrimSpace(c[2])})
		}
	}
	return out
}

func under(path, root string) bool { return path == root || strings.HasPrefix(path, root+"/") }

func storeOf(stores []Store, path string) (Store, bool) {
	best, found := Store{}, false
	for _, s := range stores {
		if under(filepath.Dir(path), s.Path) && len(s.Path) > len(best.Path) {
			best, found = s, true
		}
	}
	return best, found
}

type Keys struct {
	Snapshot     *fact.KeySnapshot
	Keys         []fact.KeyRecord
	Certificates []fact.CertificateRecord
}

func (k Keys) gap() (verdict.Judgement, bool) {
	switch {
	case k.Snapshot == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.KeySnapshotFact)), true
	case k.Snapshot.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("keys", k.Snapshot.Status, k.Snapshot.Error)), true
	case len(k.Keys) < k.Snapshot.Keys:
		return passes.Gap(verdict.CauseCollection, passes.Incomplete(k.Snapshot.RunID, len(k.Keys), k.Snapshot.Keys, fact.KeyRecordFact)), true
	case len(k.Certificates) < k.Snapshot.Certificates:
		return passes.Gap(verdict.CauseCollection, passes.Incomplete(k.Snapshot.RunID, len(k.Certificates), k.Snapshot.Certificates, fact.CertificateRecordFact)), true
	}
	return verdict.Judgement{}, false
}

func JudgeEV01(accesses []source.AuditAccess, accounts opacc4.Accounts, stores []Store, allowed []string, problem, chain catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	var others []string
	var unnamed []string
	count := 0
	for _, a := range accesses {
		if a.Success != "yes" || !slices.ContainsFunc(stores, func(s Store) bool { return under(a.Path, s.Path) }) {
			continue
		}
		count++
		who := opacc4.Person(a, accounts)
		switch {
		case who == "":
			unnamed = append(unnamed, a.Path)
		case !slices.Contains(allowed, who):
			others = append(others, who+" ("+a.Path+")")
		}
	}
	slices.Sort(others)
	switch {
	case len(others) > 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.unauthorised_access", "list", slices.Compact(others)))
	case len(unnamed) > 0:
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opexp3.edits_unnamed", "paths", unnamed))
	case !chain.IsZero():
		return passes.Gap(verdict.CauseCollection, chain)
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.accesses_authorised", "count", count))
}

func JudgeEV02(k Keys, stores []Store, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := k.gap(); found {
		return j
	}
	var outside []string
	for _, key := range k.Keys {
		if _, ok := storeOf(stores, key.Path); !ok {
			outside = append(outside, key.Path)
		}
	}
	slices.Sort(outside)
	if len(outside) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.keys_outside", "list", outside)).Counting(len(k.Keys)-len(outside), len(k.Keys))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.keys_inside", "count", len(k.Keys))).Counting(len(k.Keys), len(k.Keys))
}

func authorised(name string, algorithms []string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return slices.ContainsFunc(algorithms, func(a string) bool {
		a = strings.ToLower(strings.TrimSpace(a))
		return a != "" && (strings.Contains(name, a) || strings.Contains(a, name))
	})
}

func Algorithms(rows []string) []string {
	var out []string
	for _, r := range rows {
		c := strings.Split(r, "|")
		if len(c) >= 2 && strings.TrimSpace(c[1]) != "" {
			out = append(out, strings.TrimSpace(c[1]))
		}
	}
	return out
}

func JudgeEV03(settings opacc6.Settings, algorithms []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if gap, found := settings.Gap(); found {
		return gap
	}
	sshd := settings.SSHD()
	if sshd.Status != fact.SourceRead {
		if sshd.Status == "" {
			return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.no_sshd"))
		}
		return passes.Gap(verdict.CauseCollection, passes.Source("sshd -T", sshd.Status, sshd.Error))
	}

	var bad []string
	checked := 0
	for _, key := range []string{"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"} {
		for _, a := range strings.Split(sshd.Get(key), ",") {
			if a = strings.TrimSpace(a); a == "" {
				continue
			}
			checked++
			if !authorised(a, algorithms) && !slices.Contains(bad, a) {
				bad = append(bad, a)
			}
		}
	}
	if len(bad) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.algorithms_unauthorised", "list", bad))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.algorithms_authorised", "count", checked))
}

func JudgeEV04(logins []source.Login, algorithms []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	var bad []string
	checked := 0
	for _, l := range logins {
		if l.KeyType == "" {
			continue
		}
		checked++
		if !authorised(l.KeyType, algorithms) && !slices.Contains(bad, l.KeyType) {
			bad = append(bad, l.KeyType)
		}
	}
	if len(bad) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.keys_used_unauthorised", "list", bad))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.keys_used", "count", checked))
}

func Operation(rows []string, machine string) bool {
	for _, r := range rows {
		c := strings.Split(r, "|")
		if len(c) >= 2 && strings.EqualFold(strings.TrimSpace(c[0]), machine) {
			f := strings.ToLower(strings.TrimSpace(c[1]))
			return strings.HasPrefix(f, "explotaci")
		}
	}
	return false
}

func JudgeEV05(operation bool, accesses []source.AuditAccess, accounts opacc4.Accounts, chain catalog.Message) verdict.Judgement {

	if !operation {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.not_operation"))
	}
	var runs []string
	for _, a := range accesses {
		if a.Key == "oscompliance_exec" && (strings.HasSuffix(a.Path, "/ssh-keygen") || strings.HasSuffix(a.Path, "/openssl") || strings.HasSuffix(a.Exe, "/ssh-keygen") || strings.HasSuffix(a.Exe, "/openssl")) {
			who := opacc4.Person(a, accounts)
			runs = append(runs, a.Time.UTC().Format("2006-01-02 15:04")+" "+filepath.Base(a.Path)+" ("+who+")")
		}
	}
	switch {
	case len(runs) > 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.generated_in_operation", "list", runs))
	case !chain.IsZero():
		return passes.Gap(verdict.CauseCollection, chain)
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.no_generation"))
}

func JudgeEV06(k Keys, inventory []string, machine string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := k.gap(); found {
		return j
	}
	var present []string
	retired := 0
	for _, r := range inventory {
		c := strings.Split(r, "|")
		for len(c) < 7 {
			c = append(c, "")
		}
		name, location, state, print := strings.TrimSpace(c[0]), strings.TrimSpace(c[3]), strings.ToLower(strings.TrimSpace(c[5])), strings.TrimSpace(c[6])
		if state != "retirada" {
			continue
		}
		retired++
		for _, key := range k.Keys {
			if (print != "" && key.Fingerprint == print) || (location != "" && key.Path == location) {
				present = append(present, name+" ("+key.Path+")")
			}
		}
	}
	if len(present) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.retired_present", "list", present))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.retired_absent", "count", retired))
}

func JudgeEV07(k Keys, noticeDays int, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := k.gap(); found {
		return j
	}
	var bad, soon []string
	for _, c := range k.Certificates {
		end, err := time.Parse(time.RFC3339, c.NotAfter)
		sig := strings.ToUpper(c.Signature)
		switch {
		case err == nil && end.Before(now):
			bad = append(bad, c.Path+" (caducado "+end.Format("2006-01-02")+")")
		case c.KeyAlgo == "RSA" && c.KeyBits < 2048:
			bad = append(bad, c.Path+" (RSA "+strconv.Itoa(c.KeyBits)+")")
		case strings.Contains(sig, "MD5") || strings.Contains(sig, "SHA1"):
			bad = append(bad, c.Path+" ("+c.Signature+")")
		case err == nil && end.Sub(now) < time.Duration(noticeDays)*24*time.Hour:
			soon = append(soon, c.Path+" ("+end.Format("2006-01-02")+")")
		}
	}
	slices.Sort(bad)
	slices.Sort(soon)
	if len(bad) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.certificates_bad", "list", bad)).Counting(len(k.Certificates)-len(bad), len(k.Certificates))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.certificates_good", "count", len(k.Certificates), "soon", soon)).Counting(len(k.Certificates), len(k.Certificates))
}

func JudgeEV08(k Keys, stores []Store, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := k.gap(); found {
		return j
	}
	var open []string
	for _, key := range k.Keys {
		mode, _ := strconv.ParseUint(key.Mode, 8, 32)
		store, ok := storeOf(stores, key.Path)
		max, owner := uint64(0o600), ""
		if ok {
			max, owner = store.Mode, store.Owner
		}
		user, _, _ := strings.Cut(key.Owner, ":")
		switch {
		case mode&^max != 0:
			open = append(open, key.Path+" ("+key.Mode+")")
		case owner != "" && owner != key.Owner && (strings.Contains(owner, ":") || owner != user):
			open = append(open, key.Path+" ("+key.Owner+")")
		}
	}
	slices.Sort(open)
	if len(open) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp10.keys_open", "list", open)).Counting(len(k.Keys)-len(open), len(k.Keys))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp10.keys_protected", "count", len(k.Keys))).Counting(len(k.Keys), len(k.Keys))
}
