package opacc1

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/history"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Inventory struct {
	Current *fact.IdentitySnapshot

	Records []fact.IdentityRecord

	UIDMin int

	UIDMinProblem catalog.Message

	Today time.Time
}

func (in Inventory) people() []fact.IdentityRecord {

	var people []fact.IdentityRecord

	for _, record := range in.Records {
		if record.UID >= in.UIDMin {
			people = append(people, record)
		}
	}

	return people
}

func inventoryGap(in Inventory) (verdict.Judgement, bool) {

	if !in.UIDMinProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.UIDMinProblem), true
	}

	return identityGap(in.Current, in.Records)
}

func JudgeEV01(in Inventory) verdict.Judgement {

	if gap, found := inventoryGap(in); found {
		return gap
	}

	byUID := map[int][]string{}

	for _, record := range in.Records {
		byUID[record.UID] = append(byUID[record.UID], record.AccountName)
	}

	var uids []int

	for uid, names := range byUID {
		if len(names) > 1 {
			uids = append(uids, uid)
		}
	}

	sort.Ints(uids)

	var shared []catalog.Message

	for _, uid := range uids {
		shared = append(shared, catalog.Says("opacc1.uid_shared_by", "uid", uid, "accounts", byUID[uid]))
	}

	if len(shared) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev01.shared_uids", "uids", shared))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev01.unique",
		"accounts", len(in.Records), "people", len(in.people()), "uid_min", in.UIDMin))
}

func notEvaluable(cause verdict.Cause, m catalog.Message) verdict.Judgement {
	return passes.Gap(cause, m)
}

type EV02Input struct {
	Current *fact.IdentitySnapshot

	Records []fact.IdentityRecord

	Previous *fact.IdentitySnapshot

	PreviousRecords []fact.IdentityRecord
}

type IdentityChanges struct {
	Created  []string
	Deleted  []string
	Modified []string
}

func DiffIdentities(previous, current []fact.IdentityRecord) IdentityChanges {

	before := byAccountName(previous)
	after := byAccountName(current)

	var changes IdentityChanges

	for name, record := range after {

		old, existed := before[name]

		if !existed {
			changes.Created = append(changes.Created, name)
		} else if !sameIdentity(old, record) {
			changes.Modified = append(changes.Modified, name)
		}
	}

	for name := range before {
		if _, exists := after[name]; !exists {
			changes.Deleted = append(changes.Deleted, name)
		}
	}

	sort.Strings(changes.Created)
	sort.Strings(changes.Deleted)
	sort.Strings(changes.Modified)

	return changes
}

func sameIdentity(a, b fact.IdentityRecord) bool {
	return a.AccountName == b.AccountName && a.UID == b.UID && a.GID == b.GID &&
		a.Shell == b.Shell && a.PasswordState == b.PasswordState &&
		a.AccountExpires == b.AccountExpires && sameCount(a.AuthorizedKeys, b.AuthorizedKeys)
}

func sameCount(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func byAccountName(records []fact.IdentityRecord) map[string]fact.IdentityRecord {

	index := map[string]fact.IdentityRecord{}

	for _, record := range records {

		if _, seen := index[record.AccountName]; seen {
			continue
		}

		record.Envelope = fact.Envelope{}
		index[record.AccountName] = record
	}

	return index
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if gap, found := identityGap(in.Current, in.Records); found {
		return gap
	}

	received := len(in.Records)

	if in.Previous == nil {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev02.baseline", "accounts", received))
	}

	changes := DiffIdentities(in.PreviousRecords, in.Records)

	var parts []catalog.Message

	if len(changes.Created) > 0 {
		parts = append(parts, catalog.Says("opacc1.ev02.created", "accounts", changes.Created))
	}
	if len(changes.Deleted) > 0 {
		parts = append(parts, catalog.Says("opacc1.ev02.deleted", "accounts", changes.Deleted))
	}
	if len(changes.Modified) > 0 {
		parts = append(parts, catalog.Says("opacc1.ev02.modified", "accounts", changes.Modified))
	}

	if len(parts) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev02.unchanged", "run", in.Previous.RunID))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev02.changes", "run", in.Previous.RunID, "changes", parts))
}

func identityGap(current *fact.IdentitySnapshot, records []fact.IdentityRecord) (verdict.Judgement, bool) {
	return passes.IdentityGap(current, records)
}

type LoginInput struct {
	Forbidden params.Matcher

	ForbiddenProblem catalog.Message

	AuthSeen bool

	Logins []source.Login
}

func JudgeEV03(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-04", "opacc1.ev03.generic")
}

func JudgeEV05(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-03", "opacc1.ev05.service")
}

func noLoginIn(in LoginInput, paramID, kind string) verdict.Judgement {

	if !in.ForbiddenProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ForbiddenProblem)
	}

	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, catalog.Says("gap.no_auth_events"))
	}

	counts := map[string]int{}

	for _, login := range in.Logins {
		if in.Forbidden.Match(login.Account) {
			counts[strings.ToLower(login.Account)]++
		}
	}

	if len(counts) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says(kind+"_logged", "accounts", countList(counts)))
	}

	if len(in.Logins) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says(kind+"_no_logins", "param", paramID))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says(kind+"_none",
		"logins", len(in.Logins), "methods", byMethod(in.Logins), "param", paramID))
}

func byMethod(logins []source.Login) string {

	counts := map[string]int{}

	for _, login := range logins {
		counts[login.Method]++
	}

	var names []string

	for name := range counts {
		names = append(names, name)
	}

	sort.Strings(names)

	var parts []string

	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s %d", name, counts[name]))
	}

	return strings.Join(parts, ", ")
}

func countList(counts map[string]int) string {

	var names []string

	for name := range counts {
		names = append(names, name)
	}

	sort.Strings(names)

	var parts []string

	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s (%d)", name, counts[name]))
	}

	return strings.Join(parts, ", ")
}

const DefaultUIDMin = 1000

type EV04Input struct {
	Accounts        []fact.IdentityRecord
	AccountsProblem catalog.Message

	Declared    map[string]time.Time
	DeclaredSet bool

	DeadlineDays int
	UIDMin       int

	ConfigProblem catalog.Message

	Now time.Time
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if !in.AccountsProblem.IsZero() {
		return notEvaluable(verdict.CauseCollection, in.AccountsProblem)
	}

	today := in.Now.UTC().Truncate(24 * time.Hour)

	measured := 0
	var overdue []catalog.Message
	var unknown []string

	for _, account := range in.Accounts {

		if account.UID < in.UIDMin {
			continue
		}

		left, known := offboardingDate(account, in.Declared)

		if !known {
			continue
		}

		measured++

		disabled, known := IsDisabled(account, today)

		if disabled {
			continue
		}

		days := int(today.Sub(left.UTC().Truncate(24*time.Hour)).Hours() / 24)

		if days <= in.DeadlineDays {
			continue
		}

		if !known {
			unknown = append(unknown, account.AccountName)
			continue
		}

		overdue = append(overdue, catalog.Says("opacc1.account_days", "account", account.AccountName, "days", days))
	}

	if len(overdue) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev04.overdue", "days", in.DeadlineDays, "accounts", overdue)).Counting(measured-len(overdue)-len(unknown), measured)
	}

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence, catalog.Says("opacc1.ev04.keys_unknown", "accounts", unknown))
	}

	if measured == 0 && !in.DeclaredSet {
		return notEvaluable(verdict.CauseConfiguration, catalog.Says("opacc1.ev04.no_dates"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev04.in_time", "accounts", measured, "days", in.DeadlineDays)).Counting(measured, measured)
}

func offboardingDate(account fact.IdentityRecord, declared map[string]time.Time) (time.Time, bool) {

	if date, ok := declared[account.AccountName]; ok {
		return date, true
	}

	if account.AccountExpires == "" {
		return time.Time{}, false
	}

	date, err := time.Parse("2006-01-02", account.AccountExpires)

	return date, err == nil
}

func IsDisabled(account fact.IdentityRecord, today time.Time) (disabled, known bool) {

	if strings.HasSuffix(account.Shell, "/nologin") || strings.HasSuffix(account.Shell, "/false") {
		return true, true
	}

	if account.AccountExpires != "" {
		if expires, err := time.Parse("2006-01-02", account.AccountExpires); err == nil && !expires.After(today) {
			return true, true
		}
	}

	if account.PasswordState != fact.PasswordLocked && account.PasswordState != fact.PasswordMissing {
		return false, true
	}

	if account.AuthorizedKeys == nil {
		return false, false
	}

	return *account.AuthorizedKeys == 0, true
}

var DefaultPrivilegedGroups = []string{"sudo", "wheel", "admin"}

type EV06Input struct {
	Groups *fact.GroupSnapshot

	GroupRecords []fact.GroupRecord

	Accounts        []string
	AccountsProblem catalog.Message

	Privileged        []string
	PrivilegedDefault bool

	ConfigProblem catalog.Message

	AdminAffixes []AdminAffix

	AuthSeen bool
	Logins   []source.Login
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if gap, found := passes.GroupGap(in.Groups, in.GroupRecords); found {
		return gap
	}

	if !in.AccountsProblem.IsZero() {
		return notEvaluable(verdict.CauseCollection, in.AccountsProblem)
	}

	privileged := privilegedMembers(in)

	exists := map[string]bool{}

	for _, name := range in.Accounts {
		exists[name] = true
	}

	var structural []catalog.Message

	for _, name := range sortedKeys(privileged) {
		if hasAdminIdentity(name, exists, in.AdminAffixes) {
			continue
		}
		structural = append(structural, catalog.Says("opacc1.member_of", "account", name, "groups", privileged[name]))
	}

	usage := map[string]int{}

	for _, login := range in.Logins {
		if _, ok := privileged[login.Account]; ok {
			usage[login.Account]++
		}
	}

	var findings []catalog.Message

	if len(structural) > 0 {
		findings = append(findings, catalog.Says("opacc1.ev06.no_admin_identity", "accounts", structural))
	}

	if len(usage) > 0 {
		findings = append(findings, catalog.Says("opacc1.ev06.privileged_login", "accounts", countList(usage)))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings", "list", findings))
	}

	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, catalog.Says("opacc1.ev06.no_auth_events"))
	}

	code := "opacc1.ev06.separated"
	if in.PrivilegedDefault {
		code = "opacc1.ev06.separated_default"
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says(code, "members", len(privileged), "groups", in.Privileged))
}

func privilegedMembers(in EV06Input) map[string][]string {

	isPrivileged := map[string]bool{}

	for _, name := range in.Privileged {
		isPrivileged[name] = true
	}

	members := map[string][]string{}

	for _, group := range in.GroupRecords {

		if !isPrivileged[group.GroupName] {
			continue
		}

		for _, member := range group.Members {

			if isAdminAccount(member, in.AdminAffixes) {
				continue
			}

			members[member] = append(members[member], group.GroupName)
		}
	}

	return members
}

func hasAdminIdentity(person string, exists map[string]bool, affixes []AdminAffix) bool {
	return slices.ContainsFunc(affixes, func(a AdminAffix) bool { return exists[a.accountFor(person)] })
}

func isAdminAccount(account string, affixes []AdminAffix) bool {
	return slices.ContainsFunc(affixes, func(a AdminAffix) bool { return a.marks(account) })
}

func sortedKeys(m map[string][]string) []string {

	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

type EV07Input struct {
	Inventory Inventory

	Authorized []string

	AuthorizedProblem catalog.Message
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if !in.AuthorizedProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.AuthorizedProblem)
	}

	if gap, found := inventoryGap(in.Inventory); found {
		return gap
	}

	authorized := map[string]bool{}

	for _, name := range in.Authorized {
		authorized[name] = true
	}

	active := 0
	var missing, unknown []string

	for _, record := range in.Inventory.people() {

		disabled, known := IsDisabled(record, in.Inventory.Today)

		if disabled {
			continue
		}

		if !known {
			if !authorized[record.AccountName] {
				unknown = append(unknown, record.AccountName)
			}
			continue
		}

		active++

		if !authorized[record.AccountName] {
			missing = append(missing, record.AccountName)
		}
	}

	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev07.unlisted", "accounts", missing)).Counting(active-len(missing), active)
	}

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence, catalog.Says("opacc1.ev07.keys_unknown", "accounts", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev07.listed", "accounts", active)).Counting(active, active)
}

type EV08Input struct {
	Deleted []history.Account

	IdentityProblem catalog.Message

	RetentionDays int
	Declared      map[string]time.Time
	UIDMin        int

	ConfigProblem catalog.Message
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if !in.IdentityProblem.IsZero() {
		return notEvaluable(verdict.CauseCollection, in.IdentityProblem)
	}

	checked := 0
	var violations []catalog.Message
	var unknown []string

	for _, account := range in.Deleted {

		if account.UID < in.UIDMin || account.DeletedAt == nil {
			continue
		}

		if account.DisabledSince == nil && account.StateUnknown {
			unknown = append(unknown, account.AccountName)
			continue
		}

		if account.DisabledSince == nil {
			checked++
			violations = append(violations, catalog.Says("opacc1.ev08.deleted_enabled", "account", account.AccountName))
			continue
		}

		start, known := retentionStart(account, in.Declared)

		if !known {
			unknown = append(unknown, account.AccountName)
			continue
		}

		checked++

		days := int(account.DeletedAt.UTC().Truncate(24*time.Hour).Sub(start.UTC().Truncate(24*time.Hour)).Hours() / 24)

		if days < in.RetentionDays {
			violations = append(violations, catalog.Says("opacc1.account_days", "account", account.AccountName, "days", days))
		}
	}

	if len(violations) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev08.early", "days", in.RetentionDays, "accounts", violations)).Counting(checked-len(violations), checked)
	}

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence, catalog.Says("opacc1.ev08.unknown", "accounts", unknown))
	}

	if checked == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev08.none"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev08.kept", "accounts", checked, "days", in.RetentionDays)).Counting(checked, checked)
}

func retentionStart(account history.Account, declared map[string]time.Time) (time.Time, bool) {

	if date, ok := declared[account.AccountName]; ok {
		return date, true
	}

	if account.AccountExpires != "" {
		if date, err := time.Parse("2006-01-02", account.AccountExpires); err == nil {
			return date, true
		}
	}

	if account.DisabledObserved {
		return *account.DisabledSince, true
	}

	return time.Time{}, false
}
