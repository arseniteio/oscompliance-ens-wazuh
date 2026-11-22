# op.mon.3 Vigilancia

op.mon.3 (monitoring) judges the collection of security events: whether the
manager receives them and each declared source sends them, whether they are
correlated, whether the exposure of each machine is measured, whether
network anomalies, query volumes and real-time alerts are covered, and the
periodic inspections.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.7.3. Definition: [`catalog/controls/ens/op.mon.3.json`](../../../catalog/controls/ens/op.mon.3.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 automatic collection | B/M/A | EV-01, EV-02 |
| r1.1 correlation | M/A | EV-03 |
| r2.1 exposure | M/A | EV-04 |
| r3.1 anomalous behaviour | A | EV-05 |
| r3.2 network APT | A | EV-06 |
| r4.1 digital observatories | A | EV-07 |
| r5.1 query limits | A | EV-08 |
| r5.2 real-time alerts | A | EV-09 |
| r6.1 configuration checks | A | EV-10 |
| r6.2 vulnerability analysis | A | EV-11 |
| r6.3 penetration tests | A | EV-12 |
| r7.1 metadata on interconnections | none | |

## Sources

| Source | Content | Used by |
|---|---|---|
| Wazuh API ([op.mon.1](op.mon.1.md)) | processes, rules, `global`, `alerts`, `integration`, `vulnerability-detection` | EV-01, EV-03, EV-04, EV-08, EV-09, EV-11 |
| `wazuh-monitoring-*` | last keepalive | EV-01 |
| `wazuh_agent_config` fact | localfiles, SCA enabled | EV-02, EV-04, EV-10 |
| alerts by `location` | newest event of each log of each machine, a week back | EV-02 |
| alerts in network detection groups ([op.mon.1](op.mon.1.md)) | | EV-06 |
| SCA summary alerts ([op.exp.2](op.exp.2.md)) | policies with a result | EV-04, EV-10 |
| `wazuh_agent_config` fact of the manager ([op.exp.8](op.exp.8.md)) | CDB lists and when they changed | EV-07 |
| `wazuh-states-inventory-packages-*` | packages inventoried | EV-04, EV-11 |

Wazuh leaves the manager's own inventory out of the state indices: the
packages of agent 000 are read through the API ([op.exp.1](op.exp.1.md)).

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 event sources `fuente \| sistema \| ubicacion \| max_horas` | `sistema` an agent name or `*` | EV-02 |
| P-02 correlation rules `conjunto \| minimo_reglas_correlacion` | | EV-03 |
| P-03 hours without events | per machine; the organisation value is the fallback | EV-01 |
| P-04 anomalous behaviours `tipo \| indicador \| fuente \| reglas` | | EV-05 |
| P-06 observatory `servicio \| proveedor \| alcance \| listas` | CDB list names | EV-07 |
| P-05 network probe `producto \| ubicacion \| dias_maximos_sin_alerta` | | EV-06 |
| P-07 query limits `sistema \| perfil \| umbral \| ventana \| reglas` | | EV-08 |
| P-08 real-time recipients `destinatario \| canal \| nivel` | `correo` or an integration name | EV-09 |
| P-09 inspection plan `tipo \| periodicidad_dias \| ejecutor` | | EV-10 to EV-12 |
| P-10 inspection register `fecha \| tipo \| alcance \| ejecutor \| hallazgos \| estado` | | EV-10 to EV-12 |
| P-11 days a CDB list of the observatory may go without update | | EV-07 |
| P-ATT documentary attestations | | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opmon3`.

- EV-01 collection. `wazuh-remoted`, `wazuh-analysisd` and `wazuh-db`
  running, and the machine's last keepalive within P-03 hours.
- EV-02 sources. Every source of P-01 for the machine (or `*`) must be a
  localfile of its agent with an event from that location within
  `max_horas` (24 when empty). No source for the machine: NOT_EVALUABLE.
- EV-03 correlation. Rules of level 1 or more with `frequency`,
  `if_matched_sid` or `if_matched_group` loaded; every set of P-02 with at
  least its number of them.
- EV-04 exposure. The vulnerability detector enabled, packages of the
  machine inventoried, SCA enabled and with a result for it.
- EV-05 anomalous behaviour. As mp.com.3 EV-04 for the behaviours of
  P-04.
- EV-06 network APT. A probe in P-05 whose network intrusion alerts are
  within its days (7 when empty).
- EV-07 cyber surveillance. Every CDB list of P-06 present on the
  manager and changed within P-11 days.
- EV-08 query limits. Every row of P-07 has a loaded rule with
  `frequency` and level 1 or more among its rules.
- EV-09 real-time alerts. `correo`: email notification on, recipients
  set and the email alert level at or under `nivel`; any other channel: an
  integration of that name at or under `nivel`.
- EV-10 configuration checks. COMPLIANT when SCA checks the machine
  continuously (EV-04's SCA and the machine reporting); else the newest
  `configuración` row of P-10 within its days of P-09.
- EV-11 vulnerability analysis. As EV-10, with the vulnerability
  detector over the machine's packages, or a `vulnerabilidades` row.
- EV-12 penetration tests. The newest `pentest` row of P-10 within its
  days of P-09.

## Not measured

- EV-13: no source produces a verdict for it.
- logcollector state files and agent databases: a source counts as collected when its events reach the alerts index.
