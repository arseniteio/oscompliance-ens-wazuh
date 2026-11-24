# Configuration

Three things are configured, in three places. The operator sets the engine's connection and timing once, with flags, `/etc/oscompliance/engine.conf` and `/etc/oscompliance/engine.env` on the master manager. The operator sets agent paths in `/etc/oscompliance/agent.json`, only on non-standard machines. The security officer sets the ENS policy (level, scope and every control parameter) in Power ENS at any time. It is stored in `wazuh-ens-configuration`.

Policy never lives on the machines. Agents hold paths only; every value that
decides compliance is a parameter in Power ENS, and the engine reloads it on
every pass.

## Engine

`oscompliance-engine` writes JSON logs to standard error. Without
`-interval` it runs one pass and exits.

| Flag | Default | Purpose |
|---|---|---|
| `-indexer` | `https://wazuh.indexer:9200` | indexer URLs, comma-separated; when one does not answer, the engine tries the next |
| `-user` | `admin` | indexer user; password in `OSC_INDEXER_PASSWORD` |
| `-ca` | system roots | CA certificate of the indexer (PEM) |
| `-wazuh-api` | empty | Wazuh API URL; empty disables everything read from or written to the API |
| `-wazuh-api-user` | `oscompliance` | API user; password in `OSC_WAZUH_API_PASSWORD` |
| `-wazuh-api-ca` | system roots | certificate the API is trusted with (PEM) |
| `-wazuh-api-server-name` | URL host | name checked in the API certificate |
| `-interval` | `0` | time between passes; `0` runs once |
| `-window` | `26h` | events newer than this count |
| `-lookback` | `168h` | agents with facts this recent are judged |
| `-sync-interval` | `15m` | minimum time between two group configuration syncs |
| `-sync-apply` | off | write the group configuration; without it changes are only logged and recorded |
| `-controls` | empty | comma-separated controls to judge; empty judges all of them |
| `-alerts-index` | `wazuh-alerts-*` | alerts index pattern |
| `-monitoring-index` | `wazuh-monitoring-*` | agent keepalive index pattern |
| `-states-prefix` | `wazuh-states-` | prefix of Wazuh's inventory and vulnerability indices |
| `-config-index` | `wazuh-ens-configuration` | Power ENS configuration index |
| `-verdicts-index` | `oscompliance-verdicts` | verdicts |
| `-history-index` | `oscompliance-identity-history` | per-account history |
| `-config-history-index` | `oscompliance-config-history` | group configuration changes |
| `-host-profile-index` | `oscompliance-host-profile` | what the engine deduces about each machine |
| `-profile-groups` | off | put each machine in the Wazuh group `ens-perfil-<id>` of every profile it gets; needs `-wazuh-api` and writes only with `-sync-apply` |

| Environment variable | Purpose |
|---|---|
| `OSC_INDEXER_PASSWORD` | indexer password |
| `OSC_WAZUH_API_PASSWORD` | Wazuh API password |

The window is 26 hours so that an hourly agent and a daily sweep always have
a pass inside it, with margin for a late cron run.

The systemd unit `oscompliance-engine.service` reads `/etc/oscompliance/engine.conf` and passes `OSC_INDEXER_URLS` to `-indexer` and `OSC_INDEXER_CA` to `-ca`. Without the file it uses `https://127.0.0.1:9200` and `/etc/wazuh-indexer/certs/root-ca.pem`. `install.sh server` writes the file from the Filebeat output of the manager: the hosts of `output.elasticsearch.hosts` in `/etc/filebeat/filebeat.yml` and `/etc/filebeat/certs/root-ca.pem`, else `/etc/wazuh-indexer/certs/root-ca.pem`.

```ini
OSC_INDEXER_URLS=https://10.0.0.1:9200,https://10.0.0.2:9200
OSC_INDEXER_CA=/etc/filebeat/certs/root-ca.pem
```

## Host profile

On every pass the engine works out what each machine is from the Wazuh inventory and writes it to `oscompliance-host-profile`, one document per agent. No agent sends anything new and nothing is configured on the machines.

| Field | Comes from |
|---|---|
| `distro`, `family` | `host.os.platform` or, failing that, `host.os.name` of `wazuh-states-inventory-system`, with the version cut to `major` or `major.minor` |
| `role` | `manager` for agent 000 or a machine with `wazuh-manager`; `workstation` for a machine with a display manager or desktop package; `server` otherwise |
| `services` | installed packages in `wazuh-states-inventory-packages`, such as `zimbra-core` or `slapd` |
| `groups` | the agent's Wazuh groups |
| `signals` | each deduction with the field or package it came from |

The rules are in [`catalog/host-signals.json`](../../catalog/host-signals.json). A package name ending in `*` matches by prefix. A service with `unless` is left out when one of those services is present, so the LDAP server bundled with Zimbra is not reported as OpenLDAP.

The host profile decides which [profiles](#profiles) a machine gets.

## Profiles

A profile gives parameter values to every machine whose host profile meets its conditions, so a value is set once per machine type instead of once per machine. Each profile is one document in `wazuh-ens-configuration` with `documentType` `PROFILE`. Power ENS shows profiles as groups and manages them in Configuración > Grupos y activos, which shows the machines each group reaches while it is edited, imports and exports YAML, and shows for each machine its groups and the origin of every value. `oscompliance-policy`, below, is the option for automation. The catalog ships `ubuntu`, `manager-wazuh` and `windows` in [`catalog/profiles/`](../../catalog/profiles/), with the same values as the built-in templates; a stored profile with the same `id` replaces the built-in one.

```yaml
id: web
name: Web servers
layer: service
match:
  - field: service
    op: has
    value: web
values:
  op.acc.1:
    P-03:
      - www-data
```

| Key | Meaning |
|---|---|
| `id` | lowercase letters, digits and hyphens |
| `layer` | `distro`, `role`, `service` or `site`, from least to most specific |
| `match` | conditions that must all hold: `distro`, `family`, `role` and `hostname` take `is`, `is_not`, `matches` (shell pattern such as `web-*`) or `in` (comma-separated list, for a group of machines chosen by hand); `service` and `group` take `has` or `has_not` |
| `values` | parameters by control, with the types of the [ENS policy](#ens-policy); `organisation` parameters are not accepted |
| `match_modes` | `regex` for a parameter given as a regular expression |
| `replace` | parameters, by control, for which this profile drops the values of less specific layers |

When several profiles match a machine, lists and tables add up from every layer and other values come from the most specific one. A value set for the machine itself, or a template assigned to it, comes first; a machine with the template `none` takes no profile. Without a host profile, which the engine writes on its next pass, a machine keeps the built-in template of its system type.

With `-profile-groups`, the engine also keeps one Wazuh group per profile, `ens-perfil-<id>`, with the machines that get it, and gives the group the label `ens.perfil.<id>`. Alerts then carry `agent.labels.ens.perfil.<id>`, and rules, dashboards or a group `agent.conf` can tell machines apart by profile. A machine that stops matching leaves the group; the manager is never added. A profile condition cannot use these groups.

For automation, `oscompliance-policy`, installed with the engine, reads profiles from YAML files and writes them. Its files use the same format as Exportar and Importar in Power ENS. It uses the indexer user and password, like the engine: run it on the manager with an admin user.

```bash
export OSC_INDEXER_PASSWORD='...'
oscompliance-policy check profiles/*.yaml
oscompliance-policy plan -ca /etc/wazuh-indexer/certs/root-ca.pem profiles/*.yaml
oscompliance-policy apply -ca /etc/wazuh-indexer/certs/root-ca.pem profiles/*.yaml
```

`check` validates the files without connecting. `plan` lists each profile as new, changed (with the parameters that change) or the same, and the stored profiles the files do not hold. `apply` writes the new and changed ones; the engine uses them from its next pass. `export` prints the stored profiles as YAML, all of them or the ones named, and with `-builtin` also the built-in ones, so the files can start from what is in use. `delete` removes stored profiles. `explain -agent 001` shows what the engine deduced about a machine, the profiles it gets and where each of its parameters comes from. `-indexer` takes the indexer URL, `https://localhost:9200` by default.

## Group configuration

With `-wazuh-api` and `-sync-apply`, the engine keeps a marked region in the
`agent.conf` of every Wazuh group named in the ENS scope:

```xml
<!-- oscompliance begin: written by oscompliance-engine from the ENS configuration, do not edit -->
<agent_config>
  <!-- oscompliance {"acl_paths":["/srv/data"],"audit_watches":["/etc/ssh"],"read_watches":["/srv/data"],"exec_watches":["/usr/bin/git"]} -->
  <localfile><log_format>json</log_format><location>/var/log/oscompliance/facts.ndjson</location></localfile>
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
</agent_config>
<agent_config name="sede-01">
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/sede/auth.json</location>
    <label key="oscompliance_service">sede</label>
  </localfile>
</agent_config>
<!-- oscompliance end -->
```

| Content | From |
|---|---|
| `acl_paths` | op.acc.2 P-08, op.exp.2 P-08 |
| `audit_watches` | op.exp.3 P-04: writes and attribute changes only |
| `read_watches` | op.acc.2 P-06, op.acc.3 P-03 paths and the security paths, op.acc.4 P-07, op.exp.10 P-02: reads by sessions with a login UID, plus writes, executions and attribute changes |
| `exec_watches` | op.acc.3 P-03 binaries |
| `backup_sources`, `backup_keys` | op.exp.3 P-07, mp.info.6 P-04 and P-08 |
| `key_stores` | op.exp.10 P-02 |
| FIM `<directories>` | op.acc.2 P-02 paths outside Wazuh's defaults |
| service localfiles | op.acc.5 P-02 |

What most machines of the group share goes to every agent; a machine that
needs other paths or has services of its own gets a block with its name.
Everything outside the markers is left untouched. Every change is recorded in
`oscompliance-config-history` with the region before and after; without
`-sync-apply` the change is recorded but not written.

On each group sync the engine also creates the groups of the ENS scope that do not exist, and adds to them the agents that ask for them. An agent asks with `wazuh_group` in its `agent.json`, which it sends as `requested_group` in every `agent_pass` fact. The engine reads the requests from the `agent_pass` facts inside its window, and adds an agent only to a group of the ENS scope. A request for any other group is ignored. Each assignment is recorded in `oscompliance-config-history`.

## Control groups

With the option on in Power ENS (`scope.controlGroups`), the engine creates one
Wazuh group per control, `ens-excluir-<control>`, on its next group sync. It
needs `-wazuh-api`, `-sync-apply` and `group:create` in its API role. Without
`group:create` the sync stops at the first group with one error; run
`catalog/wazuh/engine-users.sh` again to update the role. To take a machine out
of a control, add it to that group. Turning the option off ignores
the groups and deletes none of them. See [verdicts](verdicts.md).

## ENS systems

The engine reads every ENS system from the configuration index on each pass:
the `ACTIVE_CONFIGURATION` document is the `default` system, and each
`SYSTEM_CONFIGURATION` document, with `_id` `system-<id>`, is another one. An
id has 1 to 40 lowercase letters, digits or hyphens. A system with an invalid
id, a repeated id, no configuration or a scope that names neither groups nor
machines is left out with an error. The group sync takes the scope groups of
every system and writes each machine's group configuration with the parameters
of its system; when the memberships cannot be read it leaves the groups alone.
See [verdicts](verdicts.md).

## Agent

`/etc/oscompliance/agent.json` is optional. Without it the agent uses the
defaults; with it only the keys present change. An unknown key stops the
agent with an error. The file is read on every run.

| Key | Default | Purpose |
|---|---|---|
| `output` | `/var/log/oscompliance/facts.ndjson` | file the facts are appended to |
| `host` | system host name | host name written in every fact |
| `state` | `/var/lib/oscompliance/state.json` | what each collector last sent, to send only changes |
| `collectors` | all except `sweep` | collectors of the hourly pass |
| `sweep_timeout` | `15m` | time limit of the daily file system sweep |
| `audit_read_limit` | `60` | reads per minute a read watch may record before `-guard-audit` unloads it for one hour |
| `paths.passwd` | `/etc/passwd` | account database |
| `paths.shadow` | `/etc/shadow` | password aging and locking |
| `paths.group` | `/etc/group` | group database |
| `paths.sshd` | `/usr/sbin/sshd` | sshd binary, asked for its effective configuration |
| `paths.sudoers` | `/etc/sudoers` | main sudoers file; includes are followed |
| `paths.pam_dir` | `/etc/pam.d` | PAM configuration |
| `paths.wazuh_shared_conf` | `/var/ossec/etc/shared/agent.conf` | group configuration the engine writes |
| `paths.wazuh_client_keys` | `/var/ossec/etc/client.keys` | the agent's key, which names the machine in that configuration; empty on the manager |
| `wazuh_group` | empty | Wazuh group the machine asks the engine to add it to; set by `install.sh agent --group` |

`agent/agent.example.json` holds every key with its default.

| Flag | Purpose |
|---|---|
| `-config path` | read another file; it must exist |
| `-collect a,b` | run these collectors instead of the configured ones |
| `-full` | send everything, even what did not change |

Collectors: `identity`, `groups`, `umask`, `sudoers`, `config`, `pam`,
`authprobe`, `listening`, `services`, `wazuh`, `acl`, `audit`, `firewall`,
`neighbours`, `virtualization`, `packages`, `units`, `backups`, `updates`,
`transactions`, `snapshots`, `malware`, `timesync`, `keys`, `device` and
`sweep`. What each one reads is in [facts](facts.md).

Removing a collector from the list leaves the evidences that need it
NOT_EVALUABLE by COLLECTION. It never makes them pass.

## ENS policy

Set in Power ENS > Configuración and stored in the document
`active` of `wazuh-ens-configuration`.

Until a configuration is saved, the engine and the plugin use the catalog default, [`catalog/default-configuration.json`](../../catalog/default-configuration.json): category MEDIO and scope by group, with the `ens` group. Every control parameter is unset, so the evidences that need one are NOT_EVALUABLE by CONFIGURATION. The engine logs a `parameters` line with `catalog default` on each pass that uses it.

| Setting | Effect |
|---|---|
| System category | BÁSICO, MEDIO or ALTO (stored as `BAJO`, `MEDIO` or `ALTO`; the engine also reads `BÁSICO`); requirements outside it are NOT_APPLICABLE |
| Scope | the Wazuh groups audited |
| System type of each machine | picks its built-in parameter template |
| Control enabled | a disabled control is NOT_APPLICABLE everywhere |
| Control parameters | listed on each [control page](controls/README.md) |
| Dimension levels | C, I, T, A and D, BAJO, MEDIO or ALTO; a control applies at the highest level of its dimensions, and a dimension without a level takes the category |
| Level adjustments | judge one control, or one control on one machine, at a lower level than the category |

`levelAdjustments` lowers the level a control is judged at:

```json
{ "controlId": "op.acc.1", "agentId": "001", "level": "BAJO", "reason": "test environment, risk analysis of 2026-11" }
```

`agentId` is optional; an adjustment for a machine takes precedence over the one for the control. `reason` is required. An adjustment above the category, without a reason or with an unknown level is ignored. Requirements and evidences outside the adjusted level are NOT_APPLICABLE and their reason quotes the adjustment.

Every parameter has a class that decides where its value comes from:

| Class | Value |
|---|---|
| `organisation` | the control's common value; per-machine values are ignored |
| `system` | the machine's own value, else the template assigned to it, else its profiles, else the template of its system type (none when its type is `none`, «Sin plantilla»), else the common value |
| `platform` | as `system`; built-in templates per system type ship values for it |

Templates: the one assigned to the machine, built-in (`catalog/templates/`)
or custom; `none` disables it; with none assigned, the built-in template of the
machine's system type. The system type is the one set by hand, else the one
Wazuh's inventory platform implies (`catalog/system-types.json`).

Lists compare ignoring case. A parameter marked as a regular expression uses
RE2, matches the whole value, is case-sensitive and at most 512 characters
long. Tables are rows of cells separated by `|`.

A parameter that is not set gives NOT_EVALUABLE by CONFIGURATION on the
evidences that need it. The engine never applies a value nobody chose, except
the two product defaults that op.acc.1 documents (lowest UID of a person and
privileged groups), and the verdict says when it does.

## Parameters from a file

Values by machine type go in [profiles](#profiles). After the first save from Power ENS, which creates the configuration with the full catalog, the parameters can also be set from a JSON file with `config/set-parameters.py` of the power-ens-wazuh repository. It checks every value against the catalog, shows the plan and writes only with `--apply`. Each run keeps the previous version in the history, as a save from the dashboard does.

Run it from the `config/` folder of a full power-ens-wazuh clone, on a machine that reaches the indexer with its admin certificate. It needs `python3`. On Docker, add `ENS_OS_URL=https://127.0.0.1:9200` and the certificates of `config/wazuh_indexer_ssl_certs`.

```bash
export OS_CERT=/etc/wazuh-indexer/certs/admin.pem OS_KEY=/etc/wazuh-indexer/certs/admin-key.pem
python3 set-parameters.py /root/parameters.json
python3 set-parameters.py /root/parameters.json --apply
```

The file has one key per control with its organisation values, `agents` with the values per machine by Wazuh agent ID, and `organization` with the Datos de la organización items. Values follow the types above; a parameter that accepts a regular expression takes `{"value": "...", "matchMode": "regex"}`.

```json
{
  "op.acc.1": {"P-04": ["guest", "test"], "P-05": 2},
  "agents": {"001": {"op.acc.1": {"P-07": ["alice | web-01 | admin"]}}}
}
```

The first run must print the plan and no `ERROR`; each error names the control, the parameter and the reason. Write only the parameters the organisation decided: an empty value or `null` removes the current value. The file holds the organisation's policy, so keep it out of any repository and delete it when you finish.
