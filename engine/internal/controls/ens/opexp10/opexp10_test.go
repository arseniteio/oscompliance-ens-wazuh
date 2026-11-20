package opexp10

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var stores = ParseStores([]string{"/etc/ssh | 600 | root", "/etc/ssl/private | 640 | root:ssl-cert"})

func keys(k []fact.KeyRecord, c []fact.CertificateRecord) Keys {
	return Keys{Snapshot: &fact.KeySnapshot{Status: fact.SourceRead, Keys: len(k), Certificates: len(c)}, Keys: k, Certificates: c}
}

func TestKeys(t *testing.T) {

	k := keys([]fact.KeyRecord{
		{Path: "/etc/ssh/ssh_host_ed25519_key", Mode: "0600", Owner: "root:root", Fingerprint: "SHA256:aaa"},
		{Path: "/etc/ssl/private/web.key", Mode: "0644", Owner: "root:ssl-cert"},
		{Path: "/home/ana/backup/id_rsa", Mode: "0600", Owner: "ana:ana", Fingerprint: "SHA256:old"},
	}, nil)

	check(t, "outside", JudgeEV02(k, stores, catalog.Message{}), verdict.NonCompliant, "", "/home/ana/backup/id_rsa")
	check(t, "open", JudgeEV08(k, stores, catalog.Message{}), verdict.NonCompliant, "", "/etc/ssl/private/web.key (0644)")
	check(t, "retired", JudgeEV06(k, []string{"clave antigua | ssh | fichero | | ana | retirada | SHA256:old"}, "web01", catalog.Message{}), verdict.NonCompliant, "", "clave antigua")
	check(t, "no retired", JudgeEV06(k, []string{"host | ssh | fichero | | root | activa | SHA256:aaa"}, "web01", catalog.Message{}), verdict.Compliant, "", "0 retired")
}

func TestJudgeEV07(t *testing.T) {

	k := keys(nil, []fact.CertificateRecord{
		{Path: "/etc/ssl/a.crt", NotAfter: "2026-01-01T00:00:00Z", KeyAlgo: "ECDSA", KeyBits: 256, Signature: "ECDSA-SHA256"},
		{Path: "/etc/ssl/b.crt", NotAfter: "2027-06-01T00:00:00Z", KeyAlgo: "RSA", KeyBits: 1024, Signature: "SHA256-RSA"},
		{Path: "/etc/ssl/c.crt", NotAfter: "2026-11-10T00:00:00Z", KeyAlgo: "RSA", KeyBits: 4096, Signature: "SHA256-RSA"},
	})
	check(t, "bad", JudgeEV07(k, 30, catalog.Message{}, now), verdict.NonCompliant, "", "a.crt (caducado 2026-01-01)")
	check(t, "soon", JudgeEV07(keys(nil, k.Certificates[2:]), 30, catalog.Message{}, now), verdict.Compliant, "", "c.crt (2026-11-10)")
}

func TestAlgorithms(t *testing.T) {

	allowed := Algorithms([]string{"cifrado | chacha20-poly1305 | 256", "cifrado | aes256-gcm | 256", "mac | hmac-sha2-512 | ", "kex | curve25519 | ", "firma | ssh-ed25519 | "})
	sshd := fact.ConfigFile{Source: "/usr/sbin/sshd -T", Kind: fact.ConfigKindCommand, Status: fact.SourceRead, Entries: []fact.ConfigEntry{
		{Key: "ciphers", Value: "chacha20-poly1305@openssh.com,aes128-ctr"},
		{Key: "macs", Value: "hmac-sha2-512-etm@openssh.com"},
		{Key: "kexalgorithms", Value: "curve25519-sha256"},
	}}
	settings := opacc6.Settings{Snapshot: &fact.ConfigSnapshot{RecordsEmitted: 1}, Files: []fact.ConfigFile{sshd}}
	check(t, "configured", JudgeEV03(settings, allowed, catalog.Message{}), verdict.NonCompliant, "", "aes128-ctr")

	check(t, "used", JudgeEV04([]source.Login{{KeyType: "ED25519"}, {KeyType: "RSA"}}, allowed, catalog.Message{}), verdict.NonCompliant, "", "RSA")
}

func TestAccesses(t *testing.T) {

	accounts := opacc4.Accounts{IdentityRecords: []fact.IdentityRecord{{AccountName: "root", UID: 0}, {AccountName: "ana", UID: 1001}}}
	accesses := []source.AuditAccess{
		{Key: "oscompliance_read", Success: "yes", AUID: "1001", Path: "/etc/ssl/private/web.key"},
		{Key: "oscompliance_exec", Success: "yes", AUID: "0", Path: "/usr/bin/ssh-keygen", Time: now},
	}
	check(t, "unauthorised", JudgeEV01(accesses, accounts, stores, []string{"root"}, catalog.Message{}, catalog.Message{}), verdict.NonCompliant, "", "ana (/etc/ssl/private/web.key)")
	check(t, "generated", JudgeEV05(true, accesses, accounts, catalog.Message{}), verdict.NonCompliant, "", "ssh-keygen (root)")
	check(t, "generation machine", JudgeEV05(Operation([]string{"web01 | generacion | HSM"}, "web01"), accesses, accounts, catalog.Message{}), verdict.Compliant, "", "")
}

func TestJudgeEV07CountsCertificates(t *testing.T) {
	k := keys(nil, []fact.CertificateRecord{
		{Path: "/etc/ssl/a.crt", NotAfter: "2026-01-01T00:00:00Z", KeyAlgo: "ECDSA", KeyBits: 256, Signature: "ECDSA-SHA256"},
		{Path: "/etc/ssl/b.crt", NotAfter: "2028-06-01T00:00:00Z", KeyAlgo: "RSA", KeyBits: 4096, Signature: "SHA256-RSA"},
	})
	if got := JudgeEV07(k, 30, catalog.Message{}, now).Tally; got == nil || got.Met != 1 || got.Total != 2 {
		t.Errorf("tally %+v", got)
	}
}
