# op.exp.8 Registro de la actividad

op.exp.8 (activity logging) is where Wazuh is the control itself: every
machine keeps an audit log with the minimum fields and delivers it without
gaps, logs are reviewed, the clock is synchronised, retention and backups of
the indexer match what is declared, only authorised accounts read the logs,
and at ALTA the manager analyses and responds on its own.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.8. Definition: [`catalog/controls/ens/op.exp.8.json`](../../../catalog/controls/ens/op.exp.8.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 8.1 audit log with the minimum fields | B/M/A | EV-01, EV-03, EV-04, EV-13 |
| 8.2 activity logs on the servers | B/M/A | EV-02, EV-04 |
| r1.1 periodic review | M/A | EV-05 |
| r2.1 synchronised and protected time | M/A | EV-06 |
| r3.1 audited events and retention documented | M/A | EV-07 |
| r4.1 access to logs only for authorised staff | M/A | EV-08, EV-09, EV-13 |
| r5.1 analysis looking for compromise | A | EV-10 |
| r5.2 automatic collection, correlation and response | A | EV-11, EV-12 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `audit_watch_snapshot`, `wazuh_agent_config` ([op.acc.2](op.acc.2.md)) | auditd state, the logs Wazuh reads, FIM of the agent's own configuration | EV-01, EV-13 |
| audit alerts (`rule.groups: audit`) | the fields of recent records | EV-03 |
| `wazuh-monitoring-*` | status and keepalive of each agent every few minutes | EV-02, EV-04 |
| `time_sync` fact | the clock and its synchronisation | EV-06 |
| ISM policies of `wazuh-alerts-*` | when the indexer deletes alerts | EV-07 |
| indexer snapshots | the newest successful snapshot | EV-09 |
| `acl_snapshot`, `acl_record` ([op.acc.2](op.acc.2.md)) | owner, mode and ACL of the log paths of P-14 | EV-08 |
| `wazuh_agent_config` of the manager, additional fields | rule files of the ruleset and custom rules | EV-10 |
| active responses ([op.exp.6](op.exp.6.md)) | sent, installed and executed | EV-11, EV-12 |

The paths of P-14 reach the agent with the ACL paths of the group
configuration.

### `time_sync`

One per pass: `tool` (`chrony`, `timesyncd`, `none`), `status`,
`synchronised`, `offset` (seconds, chrony), `sources` (servers in use) and
`authenticated` (an `nts` or `key` source in chrony's configuration).

### `wazuh_agent_config`, additional fields

`ruleset_files`, the rule files of `ruleset/rules`, and `custom_rules`, the
files of `etc/rules`. Both are empty off the manager.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 auditable events `categoria_evento \| fuente \| nivel_minimo` | documentary | |
| P-02 servers in scope | documentary | |
| P-03 minimum fields by source | documentary | |
| P-04 days between log reviews | | EV-05 |
| P-05 time sources `fuente_tiempo \| metodo` | | EV-06 |
| P-06 maximum clock offset (s) | | EV-06 |
| P-07 retention by category `categoria_evento \| dias_retencion` | | EV-07 |
| P-08 accounts allowed to read the logs `cuenta \| permiso \| alcance_indices` | | EV-08 |
| P-09 log backups `alcance \| destino \| frecuencia \| acceso_restringido` | `frecuencia` in days | EV-09 |
| P-10 rule sets deployed `conjunto_reglas \| cobertura \| mapeo_attck` | `wazuh` or `propias` | EV-10 |
| P-11 automatic responses `accion \| disparador \| alcance \| reversion` | | EV-11 |
| P-12 hours a machine may stay silent | per machine; the organisation value is the fallback | EV-02, EV-04 |
| P-13 register of log reviews `fecha \| revisor \| alcance \| hallazgos` | | EV-05 |
| P-14 activity log paths | platform; built-in per system type | EV-08 |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp8`.

- EV-01 audit log. auditd running, and Wazuh reading the audit log and a
  system log (journald, syslog or auth.log): otherwise NON_COMPLIANT.
- EV-02 coverage. As op.exp.1 EV-04 with P-12.
- EV-03 fields. The audit alerts of the window must carry user (`auid`
  or `uid`), time, object (`file.name` or `exe`), type and result
  (`success`). No audit alert: NOT_EVALUABLE by COLLECTION.
- EV-04 continuity. A monitoring record of the window with the agent not
  active, or two records further apart than P-12: NON_COMPLIANT with the
  gaps.
- EV-05 review. P-13 against P-04 (`passes.Review`).
- EV-06 time. Synchronised, `|offset|` within P-06, a source among P-05,
  and authenticated when P-05 asks NTS or a key: otherwise NON_COMPLIANT.
  No synchronisation service: NON_COMPLIANT.
- EV-07 retention. The ISM policy of the alerts indices must not delete
  them before the longest retention of P-07. No policy: COMPLIANT, nothing is
  deleted.
- EV-08 log access. No log path of P-14 readable by everyone, and every
  account an ACL entry names in P-08: otherwise NON_COMPLIANT.
- EV-09 log backups. The newest successful snapshot of the indexer must be
  within the shortest `frecuencia` of P-09.
- EV-10 analysis. `wazuh` in P-10 needs the ruleset on the manager;
  `propias`, custom rule files beyond `local_rules.xml`.
- EV-11 automatic response. Every `accion` of P-11 must be an active
  response the manager sends the machine, with its script there.
- EV-12 responses executed. The active responses of the window are listed.
- EV-13 integrity of the logging system. The agent reporting and FIM
  watching `/var/ossec/etc`: otherwise NON_COMPLIANT.
