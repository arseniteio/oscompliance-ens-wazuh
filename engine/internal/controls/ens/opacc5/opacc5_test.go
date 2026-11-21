package opacc5

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return now.Add(-d) }

const day = 24 * time.Hour

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func sede(oldest time.Duration) Service {
	return Service{Name: "sede", Declared: true, Span: source.ServiceSpan{Oldest: ago(oldest), Newest: ago(time.Minute), Count: 100}}
}

func event(tipo, user, result string, at time.Time) source.ServiceEvent {
	return source.ServiceEvent{Time: at, Service: "sede", Tipo: tipo, Usuario: user, Resultado: result}
}

func TestServices(t *testing.T) {

	logs := []fact.ServiceLog{{Service: "sede", Path: "/var/log/sede.json"}, {Service: "api", Path: "/var/log/api.json"}}
	spans := map[string]source.ServiceSpan{"sede": {Count: 3}}

	got := Services(declaredNames([]string{"sede | web01 | /var/log/sede.json", "portal | WEB01 | /x", "otro | db01 | /y"}, "web01"), logs, spans)

	if len(got) != 3 || got[0].Name != "api" || got[0].Declared || got[1].Name != "portal" || got[1].Log != nil || !got[2].Declared || got[2].Span.Count != 3 {
		t.Errorf("services: %+v", got)
	}
}

func TestJudgeEV01(t *testing.T) {

	disk := sede(10 * day)
	disk.Log = &fact.ServiceLog{EarliestEvent: ago(400 * day).Format(time.RFC3339)}

	check(t, "no service", JudgeEV01(EV01Input{Now: now, MinDays: 365}), verdict.NotEvaluable, verdict.CauseConfiguration, "no external-user service")
	check(t, "index too short", JudgeEV01(EV01Input{Services: []Service{sede(30 * day)}, Now: now, MinDays: 365}), verdict.NonCompliant, "", "sede (30 days")
	check(t, "disk reaches further", JudgeEV01(EV01Input{Services: []Service{disk}, Now: now, MinDays: 365}), verdict.Compliant, "", "sede (400 days")
	check(t, "nothing known", JudgeEV01(EV01Input{Services: []Service{{Name: "sede"}}, Now: now, MinDays: 365}), verdict.NotEvaluable, verdict.CauseEvidence, "no event")
	check(t, "P-08 missing", JudgeEV01(EV01Input{MinDaysProblem: catalog.Says("param.not_set", "param", "P-08")}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-08")
}

func TestJudgeEV02(t *testing.T) {

	good := map[string]Policy{"sede": {Service: "sede", Found: true, Lockout: "activado", MaxAttempts: 5, Reactivation: "intervencion"}}
	services := []Service{sede(day)}

	var events []source.ServiceEvent
	for i := 0; i < 6; i++ {
		events = append(events, event("autenticacion", "c1", "fallo", ago(time.Hour-time.Duration(i)*time.Minute)))
	}
	for i := 0; i < 3; i++ {
		events = append(events, event("autenticacion", "c2", "fallo", ago(50*time.Minute)))
	}
	events = append(events, event("autenticacion", "c2", "exito", ago(49*time.Minute)))
	for i := 0; i < 3; i++ {
		events = append(events, event("autenticacion", "c2", "fallo", ago(48*time.Minute)))
	}
	for i := 0; i < 5; i++ {
		events = append(events, event("autenticacion", "c3", "fallo", ago(40*time.Minute)))
	}
	events = append(events, event("bloqueo", "c3", "", ago(39*time.Minute)))
	for i := 0; i < 20; i++ {
		events = append(events, event("autenticacion", "c3", "fallo", ago(38*time.Minute)))
	}

	check(t, "c1 run", JudgeEV02(EV02Input{Services: services, Policies: good, Events: events, MaxAttempts: 5}), verdict.NonCompliant, "", "sede c1: 6 failures in a row")
	got := JudgeEV02(EV02Input{Services: services, Policies: good, Events: events[6:], MaxAttempts: 5})
	check(t, "c2 reset, c3 locked", got, verdict.Compliant, "", "sede locks the account after 5")

	check(t, "lockout off", JudgeEV02(EV02Input{Services: services, Policies: map[string]Policy{"sede": {Found: true, Lockout: "desactivado"}}, MaxAttempts: 5}), verdict.NonCompliant, "", "lockout disabled")
	check(t, "too many", JudgeEV02(EV02Input{Services: services, Policies: map[string]Policy{"sede": {Found: true, Lockout: "activado", MaxAttempts: 10}}, MaxAttempts: 5}), verdict.NonCompliant, "", "10 attempts, P-03 allows 5")
	check(t, "automatic", JudgeEV02(EV02Input{Services: services, Policies: map[string]Policy{"sede": {Found: true, Lockout: "activado", MaxAttempts: 3, Reactivation: "automatica"}}, MaxAttempts: 5}), verdict.NonCompliant, "", "automatically")
	check(t, "undeclared", JudgeEV02(EV02Input{Services: services, MaxAttempts: 5}), verdict.NotEvaluable, verdict.CauseEvidence, "no lockout policy")

	p := Policies([]source.ServiceEvent{
		{Service: "sede", Tipo: "politica", Bloqueo: "activado", MaxIntentos: "10"},
		{Service: "sede", Tipo: "politica", Bloqueo: "activado", MaxIntentos: "0"},
	})
	if p["sede"].Lockout != "desactivado" {
		t.Errorf("max 0 is no limit: %+v", p["sede"])
	}
}

func TestJudgeEV03(t *testing.T) {

	services := []Service{sede(day)}
	var failures []source.ServiceEvent
	for i := 0; i < 8; i++ {
		f := event("autenticacion", "x", "fallo", ago(time.Hour-time.Duration(i)*time.Minute))
		f.Origen = "198.51.100.9"
		failures = append(failures, f)
	}
	burst := []source.Burst{{Service: "sede", Key: "198.51.100.9", AtMost: 8, Total: 8}}
	spread := []source.Burst{{Service: "sede", Key: "198.51.100.9", AtMost: 8, Total: 8}}
	slow := make([]source.ServiceEvent, len(failures))
	copy(slow, failures)
	for i := range slow {
		slow[i].Time = ago(time.Duration(i) * time.Hour)
	}

	check(t, "burst", JudgeEV03(EV03Input{Services: services, Bursts: burst, Failures: failures, MaxAttempts: 5}), verdict.NonCompliant, "", "198.51.100.9: 8 failures")
	check(t, "bound too high, exact count fine", JudgeEV03(EV03Input{Services: services, Bursts: spread, Failures: slow, MaxAttempts: 5}), verdict.Compliant, "", "")
	check(t, "silent and blind", JudgeEV03(EV03Input{Services: services, MaxAttempts: 5}), verdict.NotEvaluable, verdict.CauseCollection, "sede")
	check(t, "silent and reaching", JudgeEV03(EV03Input{Services: services, Reaching: map[string]bool{"sede": true}, MaxAttempts: 5}), verdict.Compliant, "", "")
}

func TestJudgeEV04(t *testing.T) {

	accounts := []source.ServiceAccount{
		{Service: "sede", User: "fresh", LastSuccess: ago(day), LastChange: ago(30 * day)},
		{Service: "sede", User: "gone", LastSuccess: ago(200 * day), LastDisabled: ago(100 * day)},
	}
	old := append(accounts, source.ServiceAccount{Service: "sede", User: "old", LastSuccess: ago(day), LastChange: ago(120 * day)})
	never := append(accounts, source.ServiceAccount{Service: "sede", User: "never", LastSuccess: ago(day)})

	check(t, "fresh, gone skipped", JudgeEV04(EV04Input{Services: []Service{sede(10 * day)}, Accounts: accounts, Now: now, MaxAge: 90}), verdict.Compliant, "", "1 account")
	check(t, "old", JudgeEV04(EV04Input{Services: []Service{sede(10 * day)}, Accounts: old, Now: now, MaxAge: 90}), verdict.NonCompliant, "", "sede old (changed 120 days ago)")
	check(t, "never changed, young index", JudgeEV04(EV04Input{Services: []Service{sede(10 * day)}, Accounts: never, Now: now, MaxAge: 90}), verdict.NotEvaluable, verdict.CauseEvidence, "never")
	check(t, "never changed, old index", JudgeEV04(EV04Input{Services: []Service{sede(200 * day)}, Accounts: never, Now: now, MaxAge: 90}), verdict.NonCompliant, "", "no change in the 200 days")
}

func TestJudgeEV05(t *testing.T) {

	notice := func(user string, at time.Time) source.ServiceEvent {
		e := event("notificacion_compromiso", user, "", at)
		e.Referencia = "INC-1"
		return e
	}

	onTime := []source.ServiceEvent{notice("a", ago(50*time.Hour)), event("inhabilitacion", "a", "", ago(40*time.Hour))}
	late := []source.ServiceEvent{notice("b", ago(100*time.Hour)), event("inhabilitacion", "b", "", ago(60*time.Hour))}
	pending := []source.ServiceEvent{notice("c", ago(30*time.Hour))}

	check(t, "on time", JudgeEV05(EV05Input{Services: []Service{sede(day)}, Events: onTime, Now: now, MaxHours: 24}), verdict.Compliant, "", "sede a (compromise notice INC-1): 10.0 hours")
	check(t, "late", JudgeEV05(EV05Input{Services: []Service{sede(day)}, Events: late, Now: now, MaxHours: 24}), verdict.NonCompliant, "", "40.0 hours")
	check(t, "pending past deadline", JudgeEV05(EV05Input{Services: []Service{sede(day)}, Events: pending, Now: now, MaxHours: 24}), verdict.NonCompliant, "", "still enabled")
	check(t, "no notice", JudgeEV05(EV05Input{Services: []Service{sede(day)}, Now: now, MaxHours: 24}), verdict.NotEvaluable, verdict.CauseEvidence, "no compromise")
}

func TestJudgeEV06(t *testing.T) {

	for msg, want := range map[string]string{
		"Usuario o contraseña incorrectos":        "",
		"El usuario no existe":                    "usuario_inexistente",
		"Contraseña incorrecta":                   "credencial_incorrecta",
		"La cuenta está bloqueada":                "estado_de_cuenta",
		"java.lang.NullPointerException at Login": "traza_tecnica",
		"Invalid username or password":            "",
	} {
		if got := RevealingPattern(msg); got != want {
			t.Errorf("%q: got %q, want %q", msg, got, want)
		}
	}

	services := []Service{sede(day)}
	check(t, "revealing", JudgeEV06(EV06Input{Services: services, Messages: []source.MessageCount{{Service: "sede", Message: "El usuario no existe", Count: 4}}, EverLogged: map[string]bool{"sede": true}}), verdict.NonCompliant, "", "usuario_inexistente")
	check(t, "fine", JudgeEV06(EV06Input{Services: services, Messages: []source.MessageCount{{Service: "sede", Message: "Usuario o contraseña incorrectos"}}, EverLogged: map[string]bool{"sede": true}}), verdict.Compliant, "", "")
	check(t, "never logged", JudgeEV06(EV06Input{Services: services}), verdict.NotEvaluable, verdict.CauseEvidence, "sede")
}

func TestJudgeEV07(t *testing.T) {

	for factors, want := range map[string]string{
		"password": "R1", "otp+password": "R2", "certificado+pin": "R3", "biometria+tarjeta": "R4",
		"certificado": "", "password+webauthn": "",
	} {
		if got := Reinforcement(strings.Split(factors, "+")); got != want {
			t.Errorf("%s: got %q, want %q", factors, got, want)
		}
	}

	services := []Service{sede(day)}
	check(t, "R2 used", JudgeEV07(EV07Input{Services: services, Methods: []source.MethodCount{{Service: "sede", Factors: "otp+password", Count: 9}}, Mechanism: "R2"}), verdict.Compliant, "", "9 successful logins")
	check(t, "password alone under R2", JudgeEV07(EV07Input{Services: services, Methods: []source.MethodCount{{Service: "sede", Factors: "otp+password", Count: 9}, {Service: "sede", Factors: "password", Count: 1}}, Mechanism: "R2"}), verdict.NonCompliant, "", "sede password (R1, 1 login)")
	check(t, "no factors", JudgeEV07(EV07Input{Services: services, Methods: []source.MethodCount{{Service: "sede", Count: 2}}, Mechanism: "R2"}), verdict.NotEvaluable, verdict.CauseEvidence, "")
	check(t, "no logins", JudgeEV07(EV07Input{Services: services, Mechanism: "R2"}), verdict.NotEvaluable, verdict.CauseCollection, "")
}

func TestJudgeEV08(t *testing.T) {

	services := []Service{sede(day)}
	rows := []string{"FNMT-RCM | ocsp, crl"}

	check(t, "admitted", JudgeEV08(EV08Input{Services: services, Rows: rows, Certificates: []source.CertificateCount{{Service: "sede", Issuer: "FNMT-RCM", Revocation: "ocsp", Count: 3}}}), verdict.Compliant, "", "3 certificate logins")
	check(t, "not checked", JudgeEV08(EV08Input{Services: services, Rows: rows, Certificates: []source.CertificateCount{{Service: "sede", Issuer: "FNMT-RCM", Revocation: "ninguna", Count: 1}}}), verdict.NonCompliant, "", "crl | ocsp")
	check(t, "unknown issuer", JudgeEV08(EV08Input{Services: services, Rows: rows, Certificates: []source.CertificateCount{{Service: "sede", Issuer: "ACME CA", Revocation: "ocsp", Count: 1}}}), verdict.NonCompliant, "", "not admitted")
	check(t, "none", JudgeEV08(EV08Input{Services: services, Rows: rows}), verdict.NotEvaluable, verdict.CauseCollection, "")
}

func TestJudgeEV09(t *testing.T) {

	log := func(inode uint64, size int64, status string, rotated ...fact.LogFile) fact.ServiceLog {
		return fact.ServiceLog{Service: "sede", Path: "/var/log/sede.json", Status: status, Inode: inode, Size: size, Modified: ago(2 * time.Minute).Format(time.RFC3339), Rotated: rotated}
	}
	pass := func(ts time.Time, logs ...fact.ServiceLog) LogPass {
		p := LogPass{Logs: logs}
		p.Snapshot.TS = ts.Format(time.RFC3339)
		return p
	}

	service := sede(day)
	service.Log = &fact.ServiceLog{Status: fact.SourceRead, Size: 10, Modified: ago(2 * time.Minute).Format(time.RFC3339)}

	grow := []LogPass{pass(ago(2*time.Hour), log(10, 100, "read")), pass(ago(time.Hour), log(10, 200, "read"))}
	rotated := []LogPass{pass(ago(2*time.Hour), log(10, 100, "read")), pass(ago(time.Hour), log(11, 5, "read", fact.LogFile{Path: "/var/log/sede.json.1", Inode: 10}))}
	lost := []LogPass{pass(ago(2*time.Hour), log(10, 100, "read")), pass(ago(time.Hour), log(11, 5, "read"))}
	truncated := []LogPass{pass(ago(2*time.Hour), log(10, 100, "read")), pass(ago(time.Hour), log(10, 5, "read"))}
	gone := []LogPass{pass(ago(2*time.Hour), log(10, 100, "read")), pass(ago(time.Hour), log(0, 0, "absent"))}

	check(t, "grows", JudgeEV09(EV09Input{Services: []Service{service}, Passes: grow}), verdict.Compliant, "", "2 reads")
	check(t, "rotated", JudgeEV09(EV09Input{Services: []Service{service}, Passes: rotated}), verdict.Compliant, "", "")
	check(t, "replaced", JudgeEV09(EV09Input{Services: []Service{service}, Passes: lost}), verdict.NonCompliant, "", "without a rotated copy")
	check(t, "truncated", JudgeEV09(EV09Input{Services: []Service{service}, Passes: truncated}), verdict.NonCompliant, "", "truncated")
	check(t, "disappeared", JudgeEV09(EV09Input{Services: []Service{service}, Passes: gone}), verdict.NonCompliant, "", "disappeared")
	check(t, "first read", JudgeEV09(EV09Input{Services: []Service{service}, Passes: grow[:1]}), verdict.NotEvaluable, verdict.CauseCollection, "two reads")

	late := service
	late.Span.Newest = ago(3 * time.Hour)
	check(t, "not reaching Wazuh", JudgeEV09(EV09Input{Services: []Service{late}, Passes: grow}), verdict.NonCompliant, "", "newest event in Wazuh")

	declared := Service{Name: "portal", Declared: true}
	check(t, "declared, not read", JudgeEV09(EV09Input{Services: []Service{declared}, Passes: grow}), verdict.NonCompliant, "", "does not collect its log")
}

func TestDecisions(t *testing.T) {

	reqs := []string{"op.acc.5.1", "op.acc.5.8", "op.acc.5.r1.1", "op.acc.5.r2.1"}
	services := []Service{sede(day)}

	d := Decisions(DecisionInput{Level: "MEDIO", Mechanism: "R2", Services: services, LastAccess: true}, reqs)
	if _, ok := d["op.acc.5.r2.1"]; ok {
		t.Error("r2.1 applies under R2: no decision expected")
	}
	if d["op.acc.5.r1.1"].Status != verdict.NotApplicable || d["op.acc.5.r3.3"].Status != verdict.NotApplicable {
		t.Errorf("other mechanisms: %+v", d)
	}
	if _, ok := d["op.acc.5.r5.2"]; ok {
		t.Error("P-09 yes leaves r5.2 to P-ATT")
	}

	d = Decisions(DecisionInput{Level: "MEDIO", Mechanism: "R1", Services: services, LastAccess: false}, reqs)
	check(t, "R1 above BAJO", d["op.acc.5.r1.1"], verdict.NonCompliant, "", "only allows at BAJO")
	check(t, "P-09 no", d["op.acc.5.r5.2"], verdict.NonCompliant, "", "P-09")

	d = Decisions(DecisionInput{Level: "BAJO", Mechanism: "R1", Services: services, LastAccess: true,
		Policies: map[string]Policy{"sede": {Found: true, Complexity: "desactivada", MinLength: 8}}}, reqs)
	check(t, "R1 weak complexity", d["op.acc.5.r1.2"], verdict.NonCompliant, "", "complexity off")

	d = Decisions(DecisionInput{MechanismProblem: catalog.Says("param.not_set", "param", "P-01"), Services: services, ProcedureProblem: catalog.Says("param.not_set", "param", "P-04"), LastAccessProblem: catalog.Says("param.not_set", "param", "P-09")}, reqs)
	check(t, "no P-01", d["op.acc.5.r3.3"], verdict.NotEvaluable, verdict.CauseConfiguration, "P-01")
	check(t, "no P-04", d["op.acc.5.8"], verdict.NotEvaluable, verdict.CauseConfiguration, "P-04")

	d = Decisions(DecisionInput{Services: services, ProcedureProblem: catalog.Says("param.not_set", "param", "P-04"), Evidence: map[string]verdict.Judgement{"EV-03": {Status: verdict.NonCompliant}}}, reqs)
	if _, ok := d["op.acc.5.8"]; ok {
		t.Error("a measured failure of EV-03 decides .8 before P-04")
	}

	exclusion := ParseExclusion([]string{"No external users | DA-2026 | https://intranet.example.org/da.pdf | 2026-09-01 | RS"})
	if exclusion == nil {
		t.Fatal("P-DA not parsed")
	}
	d = Decisions(DecisionInput{Exclusion: exclusion}, reqs)
	if len(d) != len(reqs) || d["op.acc.5.1"].Status != verdict.NotApplicable {
		t.Errorf("P-DA without services: %+v", d)
	}
	d = Decisions(DecisionInput{Exclusion: exclusion, Services: services, Mechanism: "R2", LastAccess: true}, reqs)
	if d["op.acc.5.1"].Status == verdict.NotApplicable {
		t.Error("P-DA with a service is contradicted")
	}

	if ParseExclusion([]string{"motivo | ref | https://EJEMPLO.invalido/x.pdf"}) != nil {
		t.Error("an example link is not usable")
	}
}

func TestRevealingInvalidUser(t *testing.T) {
	if RevealingPattern("Invalid user.") != "usuario_inexistente" {
		t.Error("a bare invalid user reveals the account does not exist")
	}
}
