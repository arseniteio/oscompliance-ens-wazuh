# Facts

A fact is one observation of a machine, written by `oscompliance-agent` as one JSON line in
`/var/log/oscompliance/facts.ndjson`. Facts carry no verdict, no evidence id and no requirement id:
the catalog maps facts to evidences and the engine judges them.

Schemas: [`catalog/schemas/facts`](../../catalog/schemas/facts) (JSON Schema). Go types:
[`catalog/fact`](../../catalog/fact). Examples: [`catalog/schemas/facts/examples`](../../catalog/schemas/facts/examples).

## Envelope

Every line carries these fields, with the payload next to them at the top level.

| Field | Meaning |
|---|---|
| `oscompliance` | Envelope version. Also the marker the Wazuh decoder keys on. |
| `fact` | Fact type. Selects the payload schema. |
| `ts` | Observation time, UTC, RFC 3339 with Z suffix. |
| `host` | Hostname of the observed system. |
| `agent_version` | Version of the oscompliance agent that emitted the fact. |
| `run_id` | Identifier of one collection pass. All facts of a pass share it; snapshot facts use it to prove completeness. |
| `records_run_id` | Set on a snapshot whose records did not change since an earlier pass: its records are those of that run, which the agent does not emit again. The agent emits every record at least every 3 days. |

```json
{"oscompliance":"1","fact":"group_record","ts":"2026-11-01T10:17:02Z","host":"web-01","agent_version":"1.0.0","run_id":"5f0c…","group_name":"sudo","gid":27,"members":["alice"]}
```

## Passes

- A collector emits its records first and a snapshot last. The snapshot carries `records_emitted`, so the engine can tell a complete pass from a partial one.
- A snapshot is emitted even when its source could not be read; its `status` and `error` say why, and the evidences that need it are NOT_EVALUABLE by COLLECTION.
- A collector whose output did not change sends nothing. `agent_pass` closes every pass and names, for each such collector, the earlier run whose records still hold. Everything is sent again at least every three days.
- The agent never sends a password hash, a private key, a file content or a configuration value the controls do not judge.

## Collectors

| Collector | Facts | Reads |
|---|---|---|
| `identity` | [identity_record](#identity_record), [identity_snapshot](#identity_snapshot) | /etc/passwd, /etc/shadow, `sshd -T -C user=<account>`, authorized_keys files, wtmp, lastlog |
| `groups` | [group_record](#group_record), [group_snapshot](#group_snapshot) | /etc/group |
| `umask` | [umask_snapshot](#umask_snapshot) | login.defs, /etc/profile, /etc/bash.bashrc, /etc/profile.d |
| `sudoers` | [sudo_grant](#sudo_grant), [sudoers_snapshot](#sudoers_snapshot) | /etc/sudoers and every included file |
| `config` | [config_file](#config_file), [config_snapshot](#config_snapshot) | login.defs, faillock.conf, pwquality.conf, pwhistory.conf, sshd_config, ssh_config, Postfix main.cf, `sshd -T`, `ssh -V`, smb.conf, vsftpd.conf |
| `pam` | [pam_rule](#pam_rule), [pam_snapshot](#pam_snapshot) | /etc/pam.d |
| `authprobe` | [auth_log_probe](#auth_log_probe) | writes one line to syslog (authpriv) |
| `listening` | [listening_socket](#listening_socket), [listening_snapshot](#listening_snapshot) | /proc/net, /proc/<pid>, `systemctl` |
| `services` | [service_log](#service_log), [service_log_snapshot](#service_log_snapshot) | the shared agent.conf, the declared service logs (metadata only) |
| `wazuh` | [wazuh_agent_config](#wazuh_agent_config) | ossec.conf and the shared agent.conf |
| `acl` | [acl_record](#acl_record), [acl_snapshot](#acl_snapshot) | mode, owner and ACL of the `acl_paths` |
| `audit` | [audit_watch_snapshot](#audit_watch_snapshot) | `auditctl -s`, `auditctl -l`; loads the requested watches |
| `firewall` | [firewall_snapshot](#firewall_snapshot) | `nft -j`, else `iptables -S` |
| `neighbours` | [neighbour_snapshot](#neighbour_snapshot) | /proc/net/arp |
| `virtualization` | [virtualization](#virtualization) | `systemd-detect-virt`, DMI, /proc/cpuinfo |
| `packages` | [package_selection](#package_selection) | `apt-mark showmanual`, `dnf repoquery --userinstalled` |
| `units` | [unit_snapshot](#unit_snapshot) | `systemctl` |
| `backups` | [backup_snapshot](#backup_snapshot) | metadata of the `backup_sources` and `backup_keys` |
| `updates` | [update_status](#update_status) | `apt-get -s` (a simulation, nothing downloaded), package list times |
| `transactions` | [package_transaction](#package_transaction), [transaction_snapshot](#transaction_snapshot) | /var/log/apt/history.log |
| `snapshots` | [snapshot_list](#snapshot_list) | LVM, ZFS and Btrfs snapshot lists |
| `malware` | [malware_protection](#malware_protection) | antimalware processes, ClamAV database and settings, fapolicyd, active response scripts, YARA |
| `timesync` | [time_sync](#time_sync) | chrony or systemd-timesyncd |
| `keys` | [key_record](#key_record), [certificate_record](#certificate_record), [key_snapshot](#key_snapshot) | PEM headers under fixed roots and the `key_stores`; never key material |
| `device` | [device_security](#device_security) | chassis, dconf, TMOUT, logind, root device, resolv.conf, load, memory, sysctl |
| `sweep` | [special_file](#special_file), [file_sweep_snapshot](#file_sweep_snapshot) | every local file system, metadata only (daily) |
| `every pass` | [agent_pass](#agent_pass) | closes the pass |

The Windows agent writes the same facts from Windows sources, plus [file_access](#file_access); its collectors are in [Windows agent](install-windows.md).

## Wazuh indexing

| Rule | Indexes |
|---|---|
| 119000 | any line of `facts.ndjson` with the envelope (level 0) |
| 119001 | a fact with a valid `fact` and `run_id` (level 3, group `oscompliance_fact`) |
| 119002 | the authentication probe (group `oscompliance_probe`) |
| 119003 | a JSON event of a declared external service (group `oscompliance_service`) |
| 119004 | an auditd record with an `oscompliance_*` key (group `oscompliance_audit`) |
| 119007 | any line of `C:\ProgramData\oscompliance\facts.ndjson` with the envelope (level 0), parent of 119001 |
| 119008 | event 1006 of the Windows agent: a read watch suspended for its volume (level 10, group `oscompliance_audit`) |

In `wazuh-alerts-*` every payload field sits under `data.` and scalars arrive as strings; the engine converts them back with the Go types. Field names avoid names Wazuh renames or maps as objects (`user`, `port`, `process`), which `catalog/fact` tests.

A field never changes its JSON type between versions: the alerts index maps it on first sight, and a different type would be rejected for the rest of the day. A changed shape gets a new name.

## Reference

### acl_record

Mode, owner and POSIX ACL of one path the manager asked the agent to watch (acl_paths of the group configuration the engine writes). Emitted before the acl_snapshot of the same run_id.

| Field | Type | Meaning |
|---|---|---|
| `path` | string |  |
| `status` | `read`, `absent`, `unreadable` |  |
| `error` | string |  |
| `mode` | string | Permission bits in octal, four digits (0750). |
| `owner` | string | Owner and group names, owner:group; numbers when they have no name. |
| `acl` | array | Extended ACL entries in setfacl short form, sorted: u:name:rwx, g:name:r-x, m::r-x, and d: for default entries. Empty when the path has no extended ACL. |

### acl_snapshot

Summary of one read of the paths of the group configuration, emitted after their acl_record facts.

| Field | Type | Meaning |
|---|---|---|
| `config` | string |  |
| `status` | `read`, `absent`, `unreadable` | read; absent (the group configuration carries no paths); unreadable. |
| `error` | string |  |
| `records_emitted` | integer |  |

### agent_pass

Last fact of every collection pass. A collector whose records and snapshot did not change since it last sent them sends nothing; in_force names, for every such collector that ran in the pass and for those that sent their facts, the snapshot that holds now. The engine takes a snapshot older than its window as current when the newest agent_pass in the window names it. The agent sends every collector in full at least every 3 days.

| Field | Type | Meaning |
|---|---|---|
| `in_force` | array | One "fact:run_id" per collector: the snapshot fact and the pass that sent it. |
| `requested_group` | string | Wazuh group the machine asks to join, from `wazuh_group` in `agent.json`, set by `install.sh agent --group`. The engine adds the agent to it when the group is in the ENS scope. Absent when no group is requested. |

### audit_watch_snapshot

The auditd watches the manager asked for in the group configuration the engine writes, and whether they are loaded. Paths in audit_watches get two watches, one per permission (w, a), with keys oscompliance_write and oscompliance_attr. Paths in read_watches get four, one per permission (r, w, x, a), with keys oscompliance_read, oscompliance_write, oscompliance_exec and oscompliance_attr. The read rule only records sessions with a login UID (auid!=-1). Each access carries its kind. The agent loads a missing watch with auditctl and unloads, listed in `unloaded`, the watches no longer asked for, the read watches loaded with -w before the auid filter, and the read watches suspended for their volume. Binaries in exec_watches (op.acc.3 P-03) get one execution watch each, key oscompliance_exec.

| Field | Type | Meaning |
|---|---|---|
| `auditd` | `running`, `stopped`, `absent`, `error` | running; stopped (the daemon is not running or the kernel audit is off); absent (auditctl not installed); error. |
| `error` | string |  |
| `wanted` | array | Paths of audit_watches and read_watches. |
| `loaded` | array | Wanted paths whose watches are all loaded. |
| `failed` | array | Wanted paths whose watch could not be loaded, with the reason. A read watch on a file every process reads (/etc/passwd, /etc/group, the CA store, /usr…) is refused here, because it would fill the disk. |
| `read_wanted` | array | Wanted paths whose reads are audited (read_watches). |
| `exec_wanted` | array | Binaries whose executions the manager asked to audit (exec_watches). |
| `exec_loaded` | array | exec_wanted binaries whose execution watch is loaded. |
| `perm_rules` | integer | Rules loaded with the key oscompliance_perm: changes of mode, owner and attributes by people (auid 1000 and above) and writes to /etc/group, /etc/gshadow, /etc/sudoers and /etc/sudoers.d. The agent loads them when none is. |

### auth_log_probe

The agent wrote the line "auth log probe <run_id>" to syslog with facility authpriv and tag oscompliance-agent, where the authentication log is written. When the same line comes back as a Wazuh alert (rule 119002), the authentication log of the machine reaches Wazuh, whether or not anybody logged in.

| Field | Type | Meaning |
|---|---|---|
| `status` | `written`, `error` | written; error (syslog could not be reached). |
| `error` | string |  |

### backup_snapshot

The copies each source of the group configuration holds (backup_sources): a git directory, a directory or a file pattern, with the dates of its newest and oldest copy, who can read them and their filesystem; and the mode of the keys that encrypt them (backup_keys).

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `absent`, `unreadable` |  |
| `error` | string |  |
| `sources` | array |  |
| `key_files` | array |  |

### certificate_record

An X.509 certificate found on disk, the system public CAs left out: subject, expiry, public key and signature algorithms.

| Field | Type | Meaning |
|---|---|---|
| `path` | string |  |
| `subject` | string |  |
| `not_after` | string |  |
| `key_algorithm` | string |  |
| `key_bits` | integer |  |
| `signature_algorithm` | string |  |

### config_file

One configuration source read as key/value entries, in source order: a file (login.defs, faillock.conf, pwquality.conf...) or the effective configuration a program prints (sshd -T). Only the keys the controls judge are sent (agent/internal/collect/config Keys): configuration files can hold secrets. Emitted before the config_snapshot of the same run_id.

| Field | Type | Meaning |
|---|---|---|
| `source` | string | Path, or the command for kind command. |
| `kind` | `file`, `command` |  |
| `status` | `read`, `absent`, `unreadable`, `error` | read; absent (file missing or program not installed: nothing configured); unreadable; error (the command failed). |
| `error` | string |  |
| `entries` | array | Every setting, in order; a key may repeat (later wins where the program says so). |

### config_snapshot

Summary of one read of the configuration sources, emitted after their config_file records.

| Field | Type | Meaning |
|---|---|---|
| `records_emitted` | integer |  |

### device_security

How the machine protects an unattended session and its disk: chassis, screen lock of the graphical session (system dconf), idle timeouts of shells (TMOUT) and logind (StopIdleSessionSec), encryption of the root filesystem, and the DNS servers the machine asks (resolv.conf, the upstream ones of systemd-resolved), and its load: the 15-minute load average against its CPUs and the memory in use, in steps of ten per cent, and whether SYN cookies are on.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `error` |  |
| `error` | string |  |
| `chassis_type` | integer |  |
| `portable` | boolean |  |
| `graphical` | boolean |  |
| `lock_idle_delay_seconds` | integer |  |
| `lock_enabled` | boolean |  |
| `lock_delay_seconds` | integer |  |
| `shell_timeout_seconds` | integer |  |
| `shell_timeout_readonly` | boolean |  |
| `logind_idle_seconds` | integer |  |
| `root_device` | string |  |
| `root_encrypted` | boolean |  |
| `dns_resolvers` | array |  |
| `cpu_count` | integer |  |
| `load_percent` | integer |  |
| `memory_used_percent` | integer |  |
| `syn_cookies` | boolean |  |

### file_sweep_snapshot

Summary of one filesystem sweep, emitted after its special_file records. The sweep walks every local filesystem (one device per root, never crossing into another), pruning pseudo and container filesystems. It is complete only with status complete and no unreadable directories.

| Field | Type | Meaning |
|---|---|---|
| `roots` | array | Mount points swept. |
| `pruned` | array |  |
| `status` | `complete`, `timeout`, `truncated`, `error` | complete; timeout: the time limit stopped it; truncated: more special files than the agent emits; error: the sweep could not start (sweep_error says why). |
| `sweep_error` | string |  |
| `unreadable` | integer | Directories the sweep could not read: what is inside them was not seen. |
| `records_emitted` | integer |  |

### file_access

One audited access to a watched path on Windows, read by `-guard-audit` from event 4663 of the Security log. The engine reads it as an auditd access of the same watch.

| Field | Type | Meaning |
|---|---|---|
| `time` | string | When Windows logged the access. |
| `watch` | string | The watched path the object falls under. |
| `path` | string | The object accessed. |
| `access` | `read`, `write` |  |
| `account` | string | The subject account; SYSTEM, LOCAL SERVICE or NETWORK SERVICE for the services of the operating system. |
| `domain` | string |  |
| `process_name` | string | The executable that made the access. |

### firewall_snapshot

The packet filter of the machine: its base chains on the input and forward hooks and their default policy. A machine with no base input chain accepts everything.

| Field | Type | Meaning |
|---|---|---|
| `tool` | `nft`, `iptables`, `none` | nft, iptables, or none (no packet filter tool installed). |
| `status` | `read`, `error` |  |
| `error` | string |  |
| `chains` | array |  |

### group_record

One group of the group file with its explicit members. Emitted once per group, before the group_snapshot of the same run_id. Which groups grant privilege is decided by the engine (P-11), not here.

| Field | Type | Meaning |
|---|---|---|
| `group_name` | string |  |
| `gid` | integer |  |
| `members` | array | Member list of the group line (field 4), in file order. Accounts whose primary group this is are not listed, as in the file. |

### group_snapshot

Summary of one read of the group file. Emitted once per pass, after every group_record of the same run_id. Emitted even when the file could not be read; then no group_record is emitted.

| Field | Type | Meaning |
|---|---|---|
| `group_path` | string |  |
| `group_status` | `read`, `unreadable`, `implausible` | read, unreadable, or implausible (no GID 0 entry). |
| `group_error` | string | Only when group_status is not read. |
| `records_emitted` | integer | group_record facts emitted in this run_id. Only when read. |

### identity_record

One entry of the identity files (passwd joined with shadow), at any UID. Emitted once per entry, before the identity_snapshot of the same run_id. The engine compares the records of two passes to find created, modified and deleted accounts. Never carries a password hash: only its state. Never the keys either: only how many sshd would accept.

| Field | Type | Meaning |
|---|---|---|
| `account_name` | string |  |
| `uid` | integer |  |
| `gid` | integer |  |
| `shell` | string | Login shell as written in passwd. Empty string when the field is empty. |
| `password_state` | `set`, `locked`, `empty`, `missing`, `other` | From the shadow password field. set: a hash. locked: starts with ! or *. empty: no password. missing: no shadow entry for the account. other: anything else. |
| `account_expires` | string | Account expiration date (shadow field 8), UTC. Absent when the field is empty. |
| `authorized_keys` | integer | Public keys sshd would accept for the account: non-empty, non-comment lines of the AuthorizedKeysFile paths of the identity_snapshot. 0 when sshd is not installed. Absent when it cannot be known: sshd -T failed, an AuthorizedKeysCommand is in use, or a key file exists but cannot be read. |
| `password_changed` | string | Date of the last password change (shadow field 3), UTC. Absent when the field is empty or 0. |
| `password_change_forced` | boolean | Shadow field 3 is 0: the password must be changed at the next login. |
| `password_max_days` | integer | Maximum password age in days (shadow field 5). Absent when the field is empty: the password never expires. 99999 is written as is. |
| `password_inactive_days` | integer | Days after expiry before the account is disabled (shadow field 7). Absent when empty. |
| `authorized_keys_changed` | string | Newest modification time of the account's authorized keys files: the last time a key was added or removed, so some key is at least this old. Absent when no key file exists or it cannot be known. |
| `last_login` | string | Newest interactive login of the account recorded in the login records of the identity_snapshot (wtmp, lastlog). Absent when none records one. |

### identity_snapshot

Summary of one read of the identity files. Emitted once per pass, after every identity_record of the same run_id, so it also marks the pass as complete. Emitted even when a file could not be read; then no identity_record is emitted.

| Field | Type | Meaning |
|---|---|---|
| `passwd_path` | string |  |
| `passwd_status` | `read`, `unreadable`, `implausible` | read, unreadable, or implausible (no UID 0 entry). |
| `passwd_error` | string | Only when passwd_status is not read. |
| `shadow_path` | string |  |
| `shadow_status` | `read`, `unreadable` | read or unreadable. Not attempted (unreadable, with an error saying so) when passwd was not read. |
| `shadow_error` | string | Only when shadow_status is not read. |
| `records_emitted` | integer | identity_record facts emitted in this run_id. Only when both files were read. |
| `sshd_status` | `read`, `absent`, `command`, `error` | How the agent learned where sshd looks for keys. read: from sshd -T. absent: no sshd binary, so no key logins. command: an AuthorizedKeysCommand decides, keys cannot be counted. error: sshd -T failed. |
| `sshd_error` | string | Only when sshd_status is error. |
| `authorized_keys_files` | array | AuthorizedKeysFile patterns from sshd -T, as written (%h, %u, %U, %% not expanded). Only when sshd_status is read. |
| `login_records` | array | Login record files read for last_login, in order. A missing file records nothing; last_login is only as complete as the files read. |

### key_record

A private key found on disk by its PEM header: path, kind, fingerprint of its public part (SHA256, as OpenSSH writes it), mode and owner.

| Field | Type | Meaning |
|---|---|---|
| `path` | string |  |
| `key_kind` | `openssh`, `rsa`, `ec`, `encrypted`, `pkcs8` |  |
| `fingerprint` | string |  |
| `mode` | string |  |
| `owner` | string |  |

### key_snapshot

The sweep for keys and certificates behind the key_record and certificate_record records of a pass.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `error` |  |
| `error` | string |  |
| `roots` | array |  |
| `truncated` | boolean |  |
| `keys_emitted` | integer |  |
| `certificates_emitted` | integer |  |

### listening_snapshot

Summary of one read of the listening sockets, emitted after their listening_socket records.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `unreadable` | read; unreadable (/proc/net could not be read). |
| `error` | string |  |
| `addresses` | array | Addresses of the machine's interfaces, loopback left out: what 0.0.0.0 and :: expose. |
| `processes_matched` | boolean | false when sockets could not be matched to processes (the agent is not root). |
| `systemd` | `read`, `absent`, `error` | read: unit states were asked; absent: no systemctl (containers, non-systemd systems); error. |
| `records_emitted` | integer |  |

### listening_socket

One socket accepting connections from outside the machine (loopback is left out): TCP in LISTEN, or UDP bound without a peer. What service it is, and whether it encrypts, is the engine's decision. Emitted before the listening_snapshot of the same run_id. Field names avoid the objects of the Wazuh alerts template (data.port, data.process).

| Field | Type | Meaning |
|---|---|---|
| `protocol` | `tcp`, `udp` |  |
| `local_address` | string | Local address as bound: 0.0.0.0 or :: is every address of the machine (listening_snapshot.addresses). |
| `local_port` | integer |  |
| `process_id` | integer | Process holding the socket; absent when no process could be matched (not root). |
| `process_name` | string | Process name (/proc/<pid>/comm). |
| `process_exe` | string | Executable path, when readable. |
| `unit` | string | systemd unit of the process (from its cgroup), or the service a listening socket unit activates. |
| `unit_enabled` | string | systemctl is-enabled of unit, as printed (enabled, disabled, static, masked...). |
| `socket_unit` | string | systemd socket unit listening on this address (socket activation), when there is one. |
| `socket_enabled` | string | systemctl is-enabled of socket_unit. |

### malware_protection

The machine's defences against malicious code: antimalware products and whether they run, ClamAV's signatures, settings and last full scan, fapolicyd, and the active response scripts and YARA installed.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `unreadable` |  |
| `error` | string |  |
| `products` | array |  |
| `signatures` | string |  |
| `enabled_settings` | array | ClamAV settings switched on: proteccion_tiempo_real, actualizacion_automatica_firmas, analisis_comprimidos, registro_syslog. |
| `last_scan` | string |  |
| `allowlist` | `enforcing`, `permissive`, `stopped`, `absent` |  |
| `responses` | array |  |
| `yara` | boolean |  |

### neighbour_snapshot

The machine's IPv4 neighbour table (/proc/net/arp, or Get-NetNeighbor on Windows): the hosts it has talked to on its links. Entries still being resolved are left out.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `unreadable` |  |
| `error` | string |  |
| `neighbours` | array |  |

### package_selection

The packages installed on request (apt-mark showmanual, dnf repoquery --userinstalled), not the dependencies they pulled in.

| Field | Type | Meaning |
|---|---|---|
| `manager` | `apt`, `dnf`, `none` |  |
| `status` | `read`, `error` |  |
| `error` | string |  |
| `packages` | array |  |

### package_transaction

One apt transaction of /var/log/apt/history.log: when it ran, who asked for it and the packages it changed (name version).

| Field | Type | Meaning |
|---|---|---|
| `start` | string |  |
| `end` | string |  |
| `actor` | string |  |
| `command` | string |  |
| `installed` | array |  |
| `upgraded` | array |  |
| `removed` | array |  |

### pam_rule

One rule of a PAM service stack, in evaluation order, with include, substack and @include already resolved: the engine sees the stack PAM runs. Emitted before the pam_snapshot of the same run_id.

| Field | Type | Meaning |
|---|---|---|
| `service` | string | PAM service: the file name under /etc/pam.d (sshd, login, su, common-password...). |
| `position` | integer | 0-based order inside the resolved stack of the service. |
| `type` | `auth`, `account`, `password`, `session` |  |
| `control` | string | required, requisite, sufficient, optional, or a [value=action ...] block as written. |
| `module` | string | Module name without path (pam_unix.so). |
| `args` | array | The arguments the controls judge (deny, unlock_time, minlen, minclass, the credits, dictcheck, remember, obscure, trust); others never leave the machine. |
| `file` | string | File the rule is written in (an included one, possibly). |
| `line` | integer |  |
| `via` | array | Include chain from the service file, outermost first. |
| `module_missing` | boolean | The module file is not installed: PAM skips a "-" rule and fails a plain one, so the rule enforces nothing. |

### pam_snapshot

Summary of one read of /etc/pam.d, emitted after its pam_rule records.

| Field | Type | Meaning |
|---|---|---|
| `services` | array |  |
| `status` | `read`, `absent`, `unreadable` | read; absent (no /etc/pam.d); unreadable. |
| `error` | string |  |
| `problems` | array | Rules or includes that could not be followed (missing include, loop, unreadable file), up to 20. |
| `records_emitted` | integer |  |

### service_log

The authentication log of one external-user service, as the Wazuh agent reads it: a <localfile> of the agent's shared configuration whose label oscompliance_service names the service. Reports the file and its rotated copies, so the engine can tell retention and continuity (a log deleted, truncated or rotated without a trace). Emitted before the service_log_snapshot of the same run_id.

| Field | Type | Meaning |
|---|---|---|
| `service` | string |  |
| `path` | string | The <location> of the localfile. |
| `status` | `read`, `absent`, `unreadable` | read; absent (the file does not exist); unreadable. |
| `error` | string |  |
| `inode` | integer |  |
| `size` | integer |  |
| `modified` | string |  |
| `rotated` | array | Rotated copies next to it (path.N, path-DATE, path.N.gz...), oldest first. |
| `earliest_event` | string | ts of the first contract line of the oldest copy: how far back the service's log reaches on disk. Absent when no line could be read. |

### service_log_snapshot

Summary of one read of the external-user service logs declared to the Wazuh agent, emitted after their service_log records. No service declared is a valid read with no record.

| Field | Type | Meaning |
|---|---|---|
| `config` | string | The Wazuh agent shared configuration read. |
| `status` | `read`, `absent`, `unreadable` | read; absent (no shared configuration: the agent is not enrolled in a group); unreadable. |
| `error` | string |  |
| `agent_name` | string | Wazuh agent name the agent_config blocks are matched against. |
| `records_emitted` | integer |  |

### snapshot_list

The LVM, ZFS and Btrfs snapshots of the machine and when each was taken.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `error` |  |
| `error` | string |  |
| `snapshots` | array |  |

### special_file

One file or directory the filesystem sweep found with at least one property access control cares about: SUID, SGID, world-writable, or no owner or group in the local account database. Emitted before the file_sweep_snapshot of the same run_id. Which ones are allowed (P-10 SUID baseline, P-11 world-writable exceptions, P-02 scope) is decided by the engine.

| Field | Type | Meaning |
|---|---|---|
| `path` | string |  |
| `kind` | `file`, `directory` |  |
| `mode` | string | Permission bits in octal, 4 digits, as a string (keeps the leading zero). |
| `uid` | integer |  |
| `gid` | integer |  |
| `suid` | boolean |  |
| `sgid` | boolean |  |
| `sticky` | boolean |  |
| `world_writable` | boolean |  |
| `no_owner` | boolean | uid has no passwd entry. |
| `no_group` | boolean | gid has no group entry. |

### sudo_grant

One subject of a sudoers user specification, with aliases expanded but groups not resolved: the engine resolves groups and UIDs against the identity and group facts. Emitted before the sudoers_snapshot of the same run_id. Negated subjects grant nothing and are not emitted.

| Field | Type | Meaning |
|---|---|---|
| `subject_kind` | `user`, `group`, `uid`, `gid` | user: a login name; group: %group; uid: #uid; gid: %#gid. |
| `subject` | string | The name or number, without % or #. |
| `file` | string |  |
| `line` | integer |  |
| `nopasswd` | boolean | The specification carries a NOPASSWD tag. |
| `nopasswd_commands` | array | Commands this subject runs without a password (NOPASSWD tag, which carries over to the next commands of the list until PASSWD), in order, Cmnd_Alias expanded. ALL is every command. A name left in capitals is a Cmnd_Alias that is not defined. Negated commands are left out. |
| `spec` | string | What the specification grants, as written after the user list with blanks squeezed: host list, =, runas and commands (ALL=(ALL:ALL) ALL). |

### sudoers_snapshot

Summary of one read of the sudoers policy (/etc/sudoers and the files sudo includes), emitted after its sudo_grant records. blind_spots counts what was read but cannot be attributed to named subjects; while it is not zero, 'nobody else has sudo' cannot be asserted.

| Field | Type | Meaning |
|---|---|---|
| `files` | array |  |
| `status` | `read`, `absent`, `unreadable` | read: /etc/sudoers was read; absent: no sudo policy on this host (sudo not installed); unreadable. |
| `blind_spots` | integer |  |
| `blind_spot_reasons` | array | Up to 20 short reasons, for the verdict. |
| `defaults` | array | Every Defaults setting, in file order: binding is what follows Defaults ("" global, @host, :user, !command, >runas), setting is one entry as written (!authenticate, timestamp_timeout=-1). |
| `records_emitted` | integer |  |

### time_sync

How the machine keeps its clock: chrony or systemd-timesyncd, whether it is synchronised, its offset, the sources in use and whether they are authenticated.

| Field | Type | Meaning |
|---|---|---|
| `tool` | `chrony`, `timesyncd`, `none` |  |
| `status` | `read`, `error` |  |
| `error` | string |  |
| `synchronised` | boolean |  |
| `offset_seconds` | number |  |
| `sources` | array |  |
| `authenticated` | boolean |  |

### transaction_snapshot

The read of apt history behind the package_transaction records of a pass.

| Field | Type | Meaning |
|---|---|---|
| `manager` | `apt`, `none` |  |
| `status` | `read`, `absent`, `unreadable` |  |
| `error` | string |  |
| `records_emitted` | integer |  |

### umask_snapshot

The umask declared by every system-wide shell and login source, read in one pass. The engine takes the least restrictive declaration and compares it bit by bit with P-07. A source read without any declaration is left out.

| Field | Type | Meaning |
|---|---|---|
| `sources` | array |  |

### unit_snapshot

The systemd services running on the machine, and those failed. absent: the machine does not run systemd.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `absent`, `error` |  |
| `error` | string |  |
| `units` | array |  |
| `failed` | array | Services systemd lists as failed. |

### update_status

What apt would upgrade now (a simulation, nothing downloaded) and the time of its newest package list.

| Field | Type | Meaning |
|---|---|---|
| `manager` | `apt`, `none` |  |
| `status` | `read`, `error` |  |
| `error` | string |  |
| `lists_updated` | string |  |
| `pending` | integer |  |
| `security` | integer |  |

### virtualization

Whether the machine is a virtual machine, from systemd-detect-virt, the firmware (DMI) or the CPU hypervisor flag. Containers are not virtual machines.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `unreadable` |  |
| `error` | string |  |
| `virtual` | boolean |  |
| `platform` | string | As systemd-detect-virt --vm names it (kvm, vmware, microsoft...), or unknown. |
| `vendor` | string |  |
| `product` | string |  |
| `source` | `systemd-detect-virt`, `dmi`, `cpuinfo` |  |

### wazuh_agent_config

What the Wazuh agent of the machine is configured to watch, from its ossec.conf and the shared agent.conf blocks that apply to it: the FIM directories and the log files it reads. The engine checks with it that a silence of Wazuh is a real silence.

| Field | Type | Meaning |
|---|---|---|
| `status` | `read`, `absent`, `unreadable` | read; absent (no Wazuh agent installed); unreadable. |
| `error` | string |  |
| `syscheck_disabled` | boolean | FIM is switched off (<disabled>yes</disabled>). |
| `syscheck_frequency` | integer | Seconds between scheduled FIM scans. |
| `directories` | array | FIM <directories>, one entry per path. |
| `ignored` | array | FIM <ignore> entries. |
| `localfiles` | array |  |
| `syscollector_disabled` | boolean | No syscollector wodle, or <disabled>yes</disabled>. |
| `syscollector_interval` | integer | Seconds between syscollector scans. |
| `syscollector_scans` | array | Syscollector scans switched on. |
| `sca_disabled` | boolean | No <sca> block, or <enabled>no</enabled>. |
| `sca_interval` | integer | Seconds between SCA assessments. |
| `syscheck_scan_on_start` | boolean | FIM scans when the agent starts (Wazuh's default). |
| `rootcheck_disabled` | boolean |  |
| `integrations` | array | <integration> names of this ossec.conf (on the manager: virustotal, slack...). |
| `active_responses` | array | Active response scripts the manager sends to this machine (shared/ar.conf), restarts left out. |
| `sealed_days` | array | Days (YYYY-MM-DD) of the last 400 whose alert log is signed (.log.sum). Empty off the manager. |
| `lists` | array | CDB lists of etc/lists. Empty off the manager. |
| `ruleset_files` | integer | Rule files of ruleset/rules. 0 off the manager. |
| `custom_rules` | array | Files of etc/rules. Empty off the manager. |
