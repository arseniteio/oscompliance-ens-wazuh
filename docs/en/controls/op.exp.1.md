# op.exp.1 Inventario de activos

op.exp.1 (asset inventory) judges that every machine keeps a current
technical inventory, that it is still reporting, that nothing unknown talks
to it, that the declared inventory is reviewed, and that every machine has a
declared owner and nature.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.1. Definition: [`catalog/controls/ens/op.exp.1.json`](../../../catalog/controls/ens/op.exp.1.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 1.1 inventory with nature and owner | B/M/A | EV-01 to EV-07 |
| r1.1 labelling of equipment | none | |
| r2.1 continuous view of the state of the network | none | EV-04 |
| r3.1 critical assets | none | |
| r4.1 third-party software components | none | EV-02 |

No reinforcement is required at any category: they are NOT_APPLICABLE and
out of the score.

## Sources

The technical inventory is Wazuh's own. Syscollector keeps one document per
item in the state indices, so the engine reads it instead of the agent
emitting it again.

| Source | Content | Used by |
|---|---|---|
| `wazuh-states-inventory-system-*`, `-hardware-*` | OS, kernel, architecture, CPU, memory | EV-01 |
| `wazuh-states-inventory-packages-*` | installed packages | EV-02 |
| `wazuh-states-inventory-networks-*`, `-ports-*`, `-processes-*` | addresses, listening ports, processes | EV-03, EV-05 |
| Wazuh API `/syscollector/000/*` | the same inventory of the manager, which Wazuh does not index | EV-01 to EV-03, EV-05 |
| `wazuh-monitoring-*` | status, last keepalive and address of each agent | EV-01 to EV-05 |
| `listening_snapshot` fact ([op.acc.6](op.acc.6.md)) | the machine's own addresses | EV-05 |
| `wazuh_agent_config` fact | the agent's syscollector settings | EV-01 to EV-03 |
| `neighbour_snapshot` fact | the machine's neighbour table | EV-05 |
| dpkg and yum alerts (rules 2902, 2903, 2932, 2933, 2934) | packages installed, updated or removed | EV-06 |

The state indices carry no date, so freshness is proven by the settings and
the agent's contact: syscollector on, its scans on, its interval within
P-08, and the last keepalive within P-08.

### `wazuh_agent_config`, syscollector fields

| Field | Meaning |
|---|---|
| `syscollector_disabled` | `<disabled>yes</disabled>` in the wodle, or no wodle |
| `syscollector_interval` | seconds between scans |
| `syscollector_scans` | scans switched on: `hardware`, `os`, `network`, `packages`, `ports`, `processes` |

Read from `ossec.conf` and the shared `agent.conf`, the later winning, as
Wazuh merges them.

### `neighbour_snapshot`

One per pass, from `/proc/net/arp` (`Get-NetNeighbor` on Windows): `neighbours` with `ip`, `mac` and
`interface`, and `status` (`ok`, `unreadable`). Incomplete entries (MAC
`00:00:00:00:00:00`) are left out. Emitted only when it changes.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 declared assets `activo \| responsable \| rol \| naturaleza` | `activo` is the Wazuh agent name | EV-07 |
| P-02 assets without agent `activo \| tipo \| ip \| responsable` | | EV-05 |
| P-03 nature taxonomy | values of `naturaleza` and `tipo` | EV-07 |
| P-04 days between inventory reviews | | EV-06 |
| P-05 alert on a new asset | documentary | |
| P-06 critical assets | documentary, r3.1 | |
| P-08 hours an inventory may go without refresh | | EV-01 to EV-04 |
| P-09 register of inventory reviews `fecha \| alcance \| responsable` | | EV-06 |
| P-ATT documentary attestations | r1.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp1`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION.

- EV-01 hardware and OS. Needs the system document of the machine.
  Syscollector off, `os` or `hardware` off, or an interval above P-08:
  NON_COMPLIANT. Last keepalive older than P-08: NON_COMPLIANT. Otherwise
  COMPLIANT, with OS, kernel, architecture, cores and memory in the reason.
- EV-02 software. Same rule over the package documents and the
  `packages` scan; the reason gives the count by package type.
- EV-03 network. Same rule over addresses, listening ports and
  processes, and the `network`, `ports` and `processes` scans.
- EV-04 machine reporting. Status `active` and last keepalive within
  P-08: COMPLIANT. Otherwise NON_COMPLIANT with the last keepalive. The
  manager is always reporting.
- EV-05 unknown neighbours. Each neighbour IP must be an IP of P-02 or
  an address of any machine with an agent (network inventory, the address
  in monitoring, or the addresses its oscompliance agent reports). Unknown IPs: NON_COMPLIANT. None:
  COMPLIANT. No snapshot, or `unreadable`: NOT_EVALUABLE by COLLECTION.
- EV-06 inventory review. The newest date of P-09 not in the future
  must be within P-04 days: otherwise NON_COMPLIANT. No usable date:
  NOT_EVALUABLE by CONFIGURATION. The reason counts the package changes
  since that review.
- EV-07 declared owner and nature. The machine's agent name must be an
  `activo` of P-01, and when P-03 is set its `naturaleza` must be one of
  P-03: otherwise NON_COMPLIANT.

## Not measured

- Hardware vendor, model and serial number: they are not in Wazuh's hardware inventory.
- IPv6 neighbours.
