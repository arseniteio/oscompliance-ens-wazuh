# Verdicts

Every pass of the engine writes three kinds of verdict to
`oscompliance-verdicts`, one per machine: evidence, requirement and control.
Schema: [`catalog/schemas/verdicts/verdict.v1.json`](../../catalog/schemas/verdicts/verdict.v1.json).

The rule behind every status: what cannot be proven does not comply.

## Evidence

An evidence is one measurable fact about a machine, such as "no UID is
shared" or "the authentication log reaches Wazuh".

| Status | Meaning |
|---|---|
| `COMPLIANT` | Measured and correct. |
| `NON_COMPLIANT` | Measured and wrong. The reason names what failed: the account, the file, the port. |
| `NOT_EVALUABLE` | Could not be measured. Always carries a cause. |
| `NOT_APPLICABLE` | Does not apply at the configured system category, the control is disabled, or the machine is out of the control's scope. |

| Cause | Meaning | Fixed by |
|---|---|---|
| `CONFIGURATION` | A parameter the evidence needs is missing or unusable. | Setting the parameter in Power ENS. |
| `COLLECTION` | A source did not arrive: no agent pass in the window, a file unreadable, a log that does not reach Wazuh, auditd not running. | Fixing the machine or its Wazuh agent. |
| `EVIDENCE` | The data arrived but cannot decide this case, for example an account whose state depends on keys an `AuthorizedKeysCommand` hides. | Reviewing the case by hand, or changing the system so it can be measured. |

A `CONFIGURATION` reason names the machine. When the gap is a parameter it
also names the parameter and either states that it has no value or gives the
value in force and where it comes from: the machine, a template, a profile or
the organisation. A list shows five items and counts the rest.

## Requirement

A requirement is one point of Annex II, such as op.acc.1.4 "account life
cycle". Its status comes from its evidences:

1. Not required at the configured system category, or the control disabled:
   `NOT_APPLICABLE`, out of the score.
2. No technical evidence: `COMPLIANT`, `attested`, when an attestation row
   (P-ATT: `requisito | referencia | enlace | fecha | responsable`) has a
   reference and a usable link (`http(s)://`, `file://`, `\\host` or an
   absolute path). Otherwise `NON_COMPLIANT`, not evidenced. A document never
   covers a requirement that has technical evidence.
3. Any evidence `NON_COMPLIANT`: `NON_COMPLIANT`, evidenced.
4. Any evidence `NOT_EVALUABLE`: `NON_COMPLIANT`, not evidenced
   (`evidenced: false`), listing each gap and its cause.
5. Every evidence `NOT_APPLICABLE`: `NOT_APPLICABLE`, out of the score.
6. Otherwise `COMPLIANT`.

`NOT_EVALUABLE` never reaches a requirement. An auditor sees a requirement as
compliant or not; `evidenced` tells a measured failure from a missing proof.

Some controls decide a requirement directly where the regulation asks for a
choice: op.acc.5 and op.acc.6 apply only the authentication mechanism the
organisation declares (R1 to R4), and op.acc.5 accepts a declaration of
applicability on machines with no external service.

## Control

A control is judged by its CMM level, not all or nothing. `score` is the share
of applicable requirements that comply, 0 to 100; the maturity scale turns it
into a level, and `compliance` carries the percentage, the level, the level
required and the category.

| Status | When |
|---|---|
| `COMPLIANT` | the level reaches the one required: L2 at BÁSICO, L3 at MEDIO, L4 at ALTO |
| `PARTIAL` | below the required level, above 0 % |
| `NON_COMPLIANT` | 0 % |
| `NOT_APPLICABLE` | nothing applies |

6 of 8 requirements is 75 %, L3: `COMPLIANT` on a MEDIO control.
`coverage` is the share of applicable requirements that were measured, as
opposed to failed for lack of proof. A control at 60 with coverage 100 is a
measured 60; at coverage 40 most of the gap is configuration or collection.

## Tallies

An evidence that judges a set of items carries `tally`: the items that meet
it, the items judged and the percentage, rounded down. mp.info.6 counts copies
in EV-01 (done), EV-02 (within their interval) and EV-03 (kept for their
retention), op.acc.1 counts accounts, op.exp.2 packages and op.exp.10
certificates and keys.

The `organization` verdict of each judged control also carries `tally`: the
machines whose control is `COMPLIANT` out of those it applies to.

`tally.level` maps the percentage to L0 to L5 with a scale in
`configuration.maturity.scales`:

```json
{ "controlId": "mp.info.6", "agentId": "001", "thresholds": [50, 70, 80, 90, 98] }
```

`thresholds` holds the minimum percentage for L1 to L5, in rising order. A
scale with `agentId` applies to that machine and takes precedence over the
scale of the control. Without a scale the engine uses the table
provided by a CCN auditor
([`catalog/maturity.json`](../../catalog/maturity.json)): 20, 40, 60, 80 and
100, with the name and meaning of each level. The required level per category comes from CCN-STIC
808 and lives in the same file, which Power ENS reads too: it applies the same
rule to a selection of machines, where the fleet percentage is the average of
its machines and a machine without a score counts as 0 %.

The level decides the status of a counted evidence. L2 meets a BÁSICO system,
L3 a MEDIO one and L4 an ALTO one, at the level the control is judged at. 36
good copies out of 40 is 90 %, L4: `COMPLIANT` on an ALTO system, with the
four failed copies still listed in the reason. NOT_EVALUABLE and
NOT_APPLICABLE judgements keep their status.

## Maturity

Anexo II, apdo. 6 values each measure as a process with the CMM levels L0 to
L5. The traffic light and the score above are operational indicators; the
maturity level is the ENS valuation.

The evidence can only show that a practice exists and that it repeats. Each
control verdict carries `maturity.accredited` for that machine:

| Level | Condition over the last 30 days, today included |
|---|---|
| L0 | no day with a requirement met with evidence |
| L1 | some such days, or not today |
| L2 | today and at least 27 of the 30 days |

`working_days` is the number of those days. L3 to L5 need a written,
measured and improved process. People declare them in Power ENS (`maturity`
in the configuration: level, target, author, date and references); the engine
never raises a level from the evidence above L2.

Each pass also writes `organization` verdicts, with `agent.id` set to
`organization`:

- one per judged control: the lowest accredited level of its machines, the
  declared level and target, the number of machines, and `incoherent` when
  the declared level is L3 or more and the evidence accredits L0 or L1;
- one per declared measure the engine does not judge, such as org.2: only the
  declared level;
- one with `control` `ENS`: the distribution of accredited and declared levels
  over the applicable measures, the measures without measurement, without a
  declared level and below their target, and two global levels. A global level
  is the highest one reached by at least 80 % of the measures; the accredited
  one counts only the measures the engine judges.

## Scope

Some measures apply only to some machines: mail protection to mail servers,
screen lock to workstations, laptop encryption to portable devices, backups
to the machines with declared copies. Each control page states its scope.
Machines outside it get `NOT_APPLICABLE`.

When the regulation requires a measure somewhere in the system and no
machine holds it, the system fails: the manager carries the
`NON_COMPLIANT` verdict, so a fleet cannot comply by declaring nothing.

## Which machines are judged

The machines of the ENS scope (`scope` in the Power ENS configuration): those
of its groups, by default `ens`, and the manager, which is in no group. With
`-wazuh-api` the engine reads each agent's groups from the Wazuh API at the
start of every pass; without it, from the last sample in `wazuh-monitoring-*`,
which can be some minutes behind a group change. If the groups cannot be read,
the pass judges nothing. When the scope or an exclusion depends on groups, an
agent whose groups are unknown is not judged in that pass and the pass ends
with an error that names it. A machine outside the scope gets no verdict and
counts for nothing in the controls that look at the whole fleet; it can still
be named in a parameter, such as a pre-production host. When the configuration
cannot be read the engine keeps the last scope it read, and judges nothing
until it has read one.

With `scope.controlGroups` on, a machine in the Wazuh group
`ens-excluir-<control>` (for example `ens-excluir-op.acc.1`) is out of that
control: its verdicts are `NOT_APPLICABLE` and name the group, and it does not
count as a machine where the control exists. Its facts keep arriving, so taking
it out of the group judges it again on the next pass. The manager is in no
group and cannot be excluded this way.

An agent of the scope that stops sending keeps its verdicts as `NOT_EVALUABLE`
by `COLLECTION` while Wazuh keeps it registered; it does not disappear from the
report.

## ENS systems

An installation can hold several ENS systems, each with its own category,
scope, parameters and maturity. The configuration saved in Power ENS before
systems existed is the `default` system; every other one has its own
`SYSTEM_CONFIGURATION` document. The engine judges each system in its own pass
and writes its id in the `system` field of every verdict. Verdicts without the
field belong to `default`. The organisation verdicts and the maturity count
per system.

Each machine belongs to one system. The systems other than `default` must name
groups or machines in their scope; they claim their machines first, and
`default` takes the rest of its own scope. A machine that two systems claim,
because both name it or one of its groups, is judged in neither and the pass
ends with an error that names it and the systems. The manager carries the
measures every system relies on, so each system judges it.

## Time

| Setting | Default | Meaning |
|---|---|---|
| window | 26 h | events newer than this count for event evidences (logins, failures, changes) |
| lookback | 7 days | machines with facts this recent are judged |
| interval | 15 min | time between passes |

Evidence verdicts are written per machine and agent pass; judging the same
pass again replaces them. Requirement and control verdicts keep the last of
each day, which gives the daily series the plugin draws.

## Reasons

Verdicts carry `reason_code` and `reason_args` along with an English
`reason`. The plugin renders the code in the user's language from
[`catalog/messages`](../../catalog/messages). Reasons name what was found:
"accounts with UID 1001: alice, backup", not "duplicate UIDs found".
