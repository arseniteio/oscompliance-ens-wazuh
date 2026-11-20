package mpinfo6

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/groupconf"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Copy struct {
	Name   string
	Source string
	Hours  int
	Days   int
}

func ParseCopies(rows []string) []Copy {
	var out []Copy
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 4 {
			c = append(c, "")
		}
		for i := range c {
			c[i] = strings.TrimSpace(c[i])
		}
		src := groupconf.Source(c[1])
		if src == "" {
			continue
		}
		name := c[0]
		if name == "" {
			name = src
		}
		hours, _ := strconv.Atoi(c[2])
		days, _ := strconv.Atoi(c[3])
		out = append(out, Copy{Name: name, Source: src, Hours: hours, Days: days})
	}
	return out
}

func Read(b *fact.BackupSnapshot, copies []Copy) (map[string]fact.BackupSource, verdict.Judgement, bool) {

	switch {
	case b == nil:
		return nil, passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.BackupSnapshotFact)), false
	case b.Status != fact.SourceRead:
		return nil, passes.Gap(verdict.CauseCollection, passes.Source("backup_sources", b.Status, b.Error)), false
	}

	read := map[string]fact.BackupSource{}
	for _, s := range b.Sources {
		read[s.Source] = s
	}
	for _, c := range copies {
		s, ok := read[c.Source]
		switch {
		case !ok:
			return nil, passes.Gap(verdict.CauseCollection, catalog.Says("mpinfo6.not_read", "source", c.Source)), false
		case s.Status == fact.SourceError:
			return nil, passes.Gap(verdict.CauseCollection, passes.Source(c.Source, s.Status, s.Error)), false
		}
	}
	return read, verdict.Judgement{}, true
}

func newest(s fact.BackupSource) time.Time {
	t, _ := time.Parse(time.RFC3339, s.Newest)
	return t
}

func oldest(s fact.BackupSource) time.Time {
	t, _ := time.Parse(time.RFC3339, s.Oldest)
	return t
}

func isGit(source string) bool { return strings.HasPrefix(source, "git:") }

func JudgeEV01(copies []Copy, read map[string]fact.BackupSource) verdict.Judgement {

	var failed, done []catalog.Message
	for _, c := range copies {
		s := read[c.Source]
		switch {
		case s.Status == fact.SourceAbsent || newest(s).IsZero():
			failed = append(failed, catalog.Says("mpinfo6.item_none", "name", c.Name, "source", c.Source))
		case !isGit(c.Source) && s.Files > 0 && s.NewestBytes == 0:
			failed = append(failed, catalog.Says("mpinfo6.item_empty", "name", c.Name, "date", day(newest(s))))
		default:
			done = append(done, catalog.Says("mpinfo6.item_date", "name", c.Name, "date", day(newest(s))))
		}
	}
	if len(failed) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpinfo6.copies_failed", "met", len(done), "total", len(copies), "list", failed)).Counting(len(done), len(copies))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpinfo6.copies_done", "count", len(done), "list", done)).Counting(len(done), len(copies))
}

func JudgeEV02(copies []Copy, read map[string]fact.BackupSource, hours, margin int, now time.Time) verdict.Judgement {

	var late, fresh []catalog.Message
	for _, c := range copies {
		limit := c.Hours
		if limit == 0 {
			limit = hours
		}
		if limit == 0 {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("mpinfo6.no_interval", "name", c.Name))
		}
		limit += margin

		t := newest(read[c.Source])
		if t.IsZero() {
			late = append(late, catalog.Says("mpinfo6.item_none", "name", c.Name, "source", c.Source))
			continue
		}
		age := int(now.Sub(t).Hours())
		item := catalog.Says("mpinfo6.item_age", "name", c.Name, "date", day(t), "hours", age, "max", limit)
		if age > limit {
			late = append(late, item)
		} else {
			fresh = append(fresh, item)
		}
	}
	if len(late) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpinfo6.copies_late", "met", len(fresh), "total", len(copies), "list", late)).Counting(len(fresh), len(copies))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpinfo6.copies_fresh", "list", fresh)).Counting(len(fresh), len(copies))
}

func JudgeEV03(copies []Copy, read map[string]fact.BackupSource, days int, now time.Time) verdict.Judgement {

	var short, kept []catalog.Message
	for _, c := range copies {
		limit := c.Days
		if limit == 0 {
			limit = days
		}
		if limit == 0 {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("mpinfo6.no_retention", "name", c.Name))
		}

		s := read[c.Source]
		t := oldest(s)
		if t.IsZero() {
			short = append(short, catalog.Says("mpinfo6.item_none", "name", c.Name, "source", c.Source))
			continue
		}
		if s.Truncated {
			return passes.Gap(verdict.CauseEvidence, catalog.Says("mpinfo6.truncated", "name", c.Name))
		}
		age := int(now.Sub(t).Hours() / 24)
		item := catalog.Says("mpinfo6.item_kept", "name", c.Name, "date", day(t), "days", age, "min", limit)
		if age < limit {
			short = append(short, item)
		} else {
			kept = append(kept, item)
		}
	}
	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpinfo6.retention_short", "met", len(kept), "total", len(copies), "list", short)).Counting(len(kept), len(copies))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpinfo6.retention_kept", "list", kept)).Counting(len(kept), len(copies))
}

func JudgeEV04(copies []Copy, read map[string]fact.BackupSource, keys []fact.BackupKey, wanted []string, allowed []string) verdict.Judgement {

	ok := func(name string) bool { return slices.Contains(allowed, name) }

	var open []catalog.Message
	for _, c := range copies {
		s := read[c.Source]
		if s.Status != fact.SourceRead {
			continue
		}
		user, group, _ := strings.Cut(s.Owner, ":")
		switch {
		case s.OtherReadable > 0:
			open = append(open, catalog.Says("mpinfo6.item_others", "name", c.Name, "count", s.OtherReadable))
		case user != "" && !ok(user):
			open = append(open, catalog.Says("mpinfo6.item_owner", "name", c.Name, "owner", user))
		case s.GroupReadable > 0 && !ok(group):
			open = append(open, catalog.Says("mpinfo6.item_group", "name", c.Name, "group", group, "count", s.GroupReadable))
		}
	}

	found := map[string]fact.BackupKey{}
	for _, k := range keys {
		found[k.Path] = k
	}
	for _, path := range wanted {
		k, seen := found[path]
		switch {
		case !seen:
			return passes.Gap(verdict.CauseCollection, catalog.Says("mpinfo6.not_read", "source", path))
		case k.Status == fact.SourceAbsent:
			open = append(open, catalog.Says("item.absent", "path", path))
		case k.Status != fact.SourceRead:
			return passes.Gap(verdict.CauseCollection, passes.Source(path, k.Status, k.Error))
		default:
			user, _, _ := strings.Cut(k.Owner, ":")
			mode, _ := strconv.ParseUint(k.Mode, 8, 32)
			if mode&0o077 != 0 || !ok(user) {
				open = append(open, catalog.Says("item.path_mode", "path", path, "mode", k.Mode+" "+k.Owner))
			}
		}
	}

	if len(open) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpinfo6.access_open", "list", open))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpinfo6.access_closed", "copies", len(copies), "keys", len(wanted)))
}

func Restores(rows []string, machine string) []string {
	var out []string
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 4 {
			c = append(c, "")
		}
		if strings.EqualFold(strings.TrimSpace(c[1]), machine) && strings.EqualFold(strings.TrimSpace(c[3]), "correcta") {
			out = append(out, r)
		}
	}
	return out
}

var remoteFilesystems = []string{"nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "lustre", "davfs", "afs",
	"fuse.sshfs", "fuse.s3fs", "fuse.rclone", "fuse.gcsfuse", "fuse.glusterfs", "fuse.cephfs", "fuse.davfs2", "fuse.goofys", "fuse.mountpoint-s3"}

func Remote(s fact.BackupSource) bool {
	return slices.Contains(remoteFilesystems, s.Filesystem) || strings.Contains(s.Device, ":") || strings.HasPrefix(s.Device, "//")
}

func JudgeEV06(copies []Copy, read map[string]fact.BackupSource) verdict.Judgement {

	var local []catalog.Message
	for _, c := range copies {
		s := read[c.Source]
		if s.Status == fact.SourceRead && !newest(s).IsZero() && Remote(s) {
			return verdict.Explain(verdict.Compliant, "", catalog.Says("mpinfo6.offsite", "name", c.Name, "device", s.Device, "filesystem", s.Filesystem))
		}
		local = append(local, catalog.Says("mpinfo6.item_where", "name", c.Name, "device", s.Device, "filesystem", s.Filesystem))
	}
	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpinfo6.no_offsite", "list", local))
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }
