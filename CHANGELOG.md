# Changelog

All notable changes to OSCompliance ENS are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `catalog/maturity.json` holds the CCN maturity table (CCN-STIC 844 percentages, CCN-STIC 808 minimum per category) and the cases both the engine and Power ENS test their rule against.
- Control verdicts carry `compliance`: percentage, CMM level, required level and category.

- Verdicts carry `tally` when a judgement counts items: mp.info.6 EV-01, EV-02 and EV-03 count copies, and the `organization` verdict of each judged control counts the machines whose control is COMPLIANT.
- `configuration.maturity.scales` maps a tally percentage to a level L0 to L5, per control or per machine. No scale ships with the engine.
- The engine reads `BÁSICO` as the system category of rank 1.
- `configuration.levelAdjustments` lowers the level of a control, for all machines or for one, with a required reason.
- An attested requirement carries the links of its attestation in `reason_args.links`.
- op.acc.1 EV-04, EV-07 and EV-08, op.exp.2 EV-03 and EV-06 and op.exp.10 EV-02, EV-07 and EV-08 count their items.

### Changed

- A control is judged by its CMM level: COMPLIANT when its level reaches the one its level requires (L2 BÁSICO, L3 MEDIO, L4 ALTO), PARTIAL below it, NON_COMPLIANT at 0 %. Before, only a control with every requirement met was COMPLIANT.
- The default maturity scale is the CCN table, 10, 50, 80, 90 and 100 %, instead of 20, 40, 60, 80 and 100.
- A NOT_EVALUABLE reason caused by CONFIGURATION names the machine, the parameter and its value in force and origin, or that it has no value.
- Out-of-level reasons speak of the system category, BÁSICO, MEDIO or ALTO.
- A counted evidence is COMPLIANT when its CMM level reaches the one its level asks for: L2 for BÁSICO, L3 for MEDIO, L4 for ALTO. The default scale is 20, 40, 60, 80 and 100 %.
- A requirement whose evidences are all NOT_APPLICABLE is NOT_APPLICABLE instead of NON_COMPLIANT.
- A control applies at the highest declared level of its dimensions, as in the plugin, instead of the system category alone.
- Count placeholders take a singular and a plural noun (`{count#copia|copias}`), so reasons read "1 inicio de sesión" and "3 inicios de sesión".
- 100 reasons are rewritten in plain words: no internal fact names, configuration keys or run ids. Collection gaps name the fact type by its label, such as "el inventario de cuentas".

## [2.0.1] - 2026-11-19

### Added

- op.exp.6 EV-01 and mp.s.3 EV-06 count the Wazuh agent as the expected protection when op.exp.6 P-02 names `wazuh` or `wazuh-agent` and the agent read the Wazuh agent configuration of the machine. Before, `wazuh` in P-02 always showed as missing.
- The Windows template declares P-10 1000 and the privileged groups of op.acc.1 P-11, with their English and Spanish names.

### Fixed

- op.acc.1 EV-03, EV-05 and EV-06 judge a machine with no logins as compliant when the authentication probe reached Wazuh in the lookback, instead of NOT_EVALUABLE.
- Windows failures (4625) and lockouts (4740) leave out computer accounts and SYSTEM, LOCAL SERVICE, NETWORK SERVICE and ANONYMOUS LOGON, as logons already did.
- op.acc.2 EV-06 skips audited accesses without a path, such as some chmod or setxattr records, instead of turning NOT_EVALUABLE.
- The agent drops ARP entries without a resolved MAC, QEMU placeholder MACs, broadcast and multicast from `neighbour_snapshot`.
- The engine names agent 000 from the manager API: every node of a cluster has its own agent 000, and verdicts carried a worker's name.

## [2.0.0] - 2026-11-18

### Added

- Windows agent, not yet tested on a physical machine. `oscompliance-agent.exe` for Windows Server 2016 to 2025 and Windows 10 and 11 collects accounts and groups (SAM, or Active Directory on a domain controller), the security, audit and registry policy, BitLocker and the inactivity lock, Windows Firewall, Microsoft Defender, AppLocker, W32Time, Windows Update, services, listening ports, installed programs and ACLs, and writes them to `C:\ProgramData\oscompliance\facts.ndjson` with the existing fact types. `install.ps1` installs it with one PowerShell command, like `install.sh agent --group ens`. `make dist` packages it as `oscompliance-ens-wazuh-<version>-windows-amd64.zip`.
- On Windows the `audit` collector sets SACL entries on the read and change watches, and `-guard-audit` forwards event 4663 on them as the `file_access` fact. Rule 119007 decodes the Windows facts file and rule 119008 alerts when a read watch is suspended.
- The engine reads Windows logons from events 4624 of logon types 2, 10 and 11, failures from 4625 and lockouts from 4740. Remote Desktop counts as the remote channel `rdp`.
- op.acc.6 judges the Windows lockout and password policy from `secedit` when the machine has no PAM facts. op.exp.6 judges the signatures and settings of Microsoft Defender.
- Host profiles. The engine deduces each machine's distro, role (manager, server or workstation) and services from the Wazuh inventory on every pass and writes them to `oscompliance-host-profile`, named by `-host-profile-index`. The rules are in `catalog/host-signals.json`, including the Windows editions.
- Profiles give parameter values to every machine whose host profile meets their conditions, in four layers: distro, role, service and site. Lists add up across layers; other values come from the most specific layer. The catalog ships `ubuntu`, `manager-wazuh` and `windows`. A condition on `distro`, `family`, `role` or `hostname` takes `in` with a comma-separated list for a hand-picked group, and a machine of type `none` takes no type template.
- `-profile-groups` keeps one Wazuh group per profile, `ens-perfil-<id>`, with the machines that get it.
- `oscompliance-policy` checks, plans, applies, exports and deletes profiles written in YAML, and explains which profiles and values a machine gets.
- Maturity (RD 311/2022, Anexo II, apdo. 6). Each control verdict carries the CMM level its evidence accredits on that machine, L0 to L2 over 30 days. Each pass writes `organization` verdicts with the lowest level of each control, the declared level, target and author, the declared measures without engine, and the distribution and global level.
- op.mon.2 EV-01 reports each machine's implementation degree against the statement of applicability of P-01. EV-05 lists the controls with evidences not evaluable by configuration.
- `oscompliance-agent -guard-audit`, run by cron every 2 minutes, unloads for one hour a read watch that records more than `audit_read_limit` successful reads per minute (60 by default) over 5 minutes. The controls that judge those reads are NOT_EVALUABLE by COLLECTION until the suspension ends. Rule 119006 alerts at level 10 on every suspension.
- The agent unloads the `oscompliance_*` audit watches the group configuration no longer asks for, only while it holds the engine's block. `audit_watch_snapshot` lists them in `unloaded`.

### Changed

- The repository is now `arseniteio/oscompliance-ens-wazuh`. The Go module paths and the schema `$id` URLs follow it, and the packages are named `oscompliance-ens-wazuh-<version>-linux-<arch>.tar.gz`. `install.sh` downloads from the new repositories and expects the new plugin zip name.
- The group configuration splits the auditd watches in two. `audit_watches` records writes and attribute changes. `read_watches` records reads, only for sessions with a login UID (`auid!=-1`). The first pass of the new agent unloads the 1.2.0 read watches on machines of a group with the engine's block; elsewhere run `auditctl -D -k oscompliance_read` and `auditctl -D -k oscompliance_exec` once.
- The agent does not load a read watch on a file every process reads (`catalog.HotReadPaths`), and rule 119005 drops such reads on the manager. Agents of 1.2.0 loaded these watches and filled disks within minutes. `install.sh` checks rule IDs 119000 to 119008.
- The group configuration writes one `<agent_config os="...">` block per operating system when a group has Windows machines, so a mixed group does not send Linux files and watches to Windows agents.
- The accredited global maturity level leaves out the measures that are only declared.
- The installation guide lists the hardware the agent, the engine and the verdicts need, measured in the lab. The configuration guide presents Power ENS as the place to manage profiles and `oscompliance-policy` for automation. `CONTRIBUTING.md` and `CONTRIBUTING.es.md` explain how to propose a change.

### Fixed

- The read guard does not run on machines without auditd.
- The op.acc parameter labels carry their accents, and the BOE text of mp.eq.3.r1.1 and op.exp.10.r2.1 is literal.

## [1.2.0] - 2026-11-16

### Added

- `install.sh server` detects the node and installs only its part: rules, manager audit and engine on the master manager or single node, a restart once the rules of the release arrive on a worker, and the Power ENS plugin on a dashboard node.
- `install.sh server --only <components>` replaces the detection with a comma-separated list of `rules`, `audit`, `engine`, `plugin` and `worker`.
- `install.sh agent --group <name>` asks the engine to add the machine to a Wazuh group and reads the facts file through a localfile in the agent's own `ossec.conf` until the group configuration arrives.
- The agent sends `wazuh_group` from `agent.json` as `requested_group` in every `agent_pass` fact.
- The engine creates the groups of the ENS scope that do not exist and adds to them the agents that ask for them, never to a group outside the scope.
- The engine logs a warning for agents that ask for a group outside the ENS scope.
- `-indexer` accepts several comma-separated URLs and fails over to the next one when one does not answer.
- `catalog/default-configuration.json` holds the default ENS configuration: level MEDIO and the `ens` group in scope.

### Changed

- Until a configuration is saved in Power ENS, the engine judges with the catalog default, so the "Guardar configuración global" (save global configuration) step is no longer required for the first verdicts.
- The engine unit reads the indexer URLs and CA certificate from `/etc/oscompliance/engine.conf`, which `install.sh server` writes from the Filebeat output of the manager.
- `engine-users.sh` uses the indexer admin certificate when it is on the host and otherwise asks for the password of the indexer `admin` user, so no certificate is copied between hosts.
- `install.sh server` keeps the passwords of existing engine users on a rerun and updates their permissions.
- The Wazuh API role of the engine adds `group:modify_assignments` and `agent:modify_group`.
- `install.sh uninstall` removes from each node only what is installed there, and the rules only on the master.
- The installation guide covers distributed deployments, with the steps of each node type.
- `install.sh server` installs `jq` and `unzip` with the system package manager when they are missing.

### Fixed

- The engine logs in to the Wazuh API again when its token is revoked by a change of roles, as happens right after `engine-users.sh` creates them, instead of skipping the group configuration until the next sync.

## [1.1.0] - 2026-11-15

### Added

- `install.sh`, published with each release and included in each package. `install.sh server` installs the rules, the engine and its users and the Power ENS plugin on an all-in-one Wazuh server installed from packages, and audits the manager. `install.sh agent` installs the agent and runs its first pass once the group configuration arrives. `install.sh uninstall` removes both. It verifies every download against `SHA256SUMS`.

### Changed

- The installation guides download the release with `curl` and `sha256sum`, and building from source moves to its own section.

## [1.0.0] - 2026-11-13

First release.

### Added

- Agent `oscompliance-agent` for Linux amd64 and arm64. It writes facts about accounts, groups, PAM, sshd, sudoers, listening sockets, packages, backups and keys to `/var/log/oscompliance/facts.ndjson`, and judges nothing.
- Engine `oscompliance-engine`. Every 15 minutes it reads the facts, the Wazuh alerts and inventory, the Wazuh API and the parameters declared in Power ENS, and writes one verdict per evidence, requirement and control to the `oscompliance-verdicts` index.
- Catalog of 34 controls of Annex II of Real Decreto 311/2022, with one documentation page per control.
- Wazuh rules 119000 to 119004 for facts, the authentication probe, service events and audited accesses.
- `engine-users.sh`, which creates the engine users in the indexer and the Wazuh API with the permissions the engine needs.
- systemd unit for the engine and cron file for the agent.
- Packages for Linux amd64 and arm64 with a `SHA256SUMS` file.
- Support for Wazuh 4.14.7, 4.14.8 and 4.14.9, installed from packages or on Docker.

[Unreleased]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/arseniteio/oscompliance-ens-wazuh/releases/tag/v1.0.0
