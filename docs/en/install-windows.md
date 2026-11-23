# Windows agent

The OSCompliance agent for Windows collects the same kind of facts as the Linux agent and writes them to `C:\ProgramData\oscompliance\facts.ndjson`. The Wazuh agent ships the file to the manager and the engine judges the facts with the same controls. The plugin shows Windows machines like any other machine.

The Windows agent has been tested in the lab only, not yet on a physical machine. Try it on a test machine before rolling it out.

## Requirements

- Windows Server 2016, 2019, 2022 or 2025, or Windows 10 or 11, 64-bit.
- Windows PowerShell 5.1, which every supported version includes.
- The Wazuh agent 4.x installed in `C:\Program Files (x86)\ossec-agent` and registered with the manager.
- An elevated PowerShell for the installation. The agent runs as SYSTEM.

## Install

Run one command from an elevated PowerShell, the same as `install.sh agent --group ens` on Linux:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((irm https://github.com/arseniteio/oscompliance-ens-wazuh/releases/latest/download/install.ps1))) -Group ens
```

The script downloads the Windows package of the release and checks it against `SHA256SUMS`. To check the files before running anything, download `oscompliance-ens-wazuh-<version>-windows-amd64.zip` and `SHA256SUMS`, verify the zip with `Get-FileHash`, extract it and run `.\install.ps1 -Group ens` from the extracted folder: the script uses the binary next to it. `-Release 1.3.0` installs another release. Run the same command again to upgrade.

The script:

- copies `oscompliance-agent.exe` to `C:\Program Files\OSCompliance`;
- creates `C:\ProgramData\oscompliance` and its `state` folder with access for SYSTEM and Administrators only;
- writes the requested group to `C:\ProgramData\oscompliance\agent.json`, which the engine reads to add the machine to that group;
- adds the facts file to the local `ossec.conf` of the Wazuh agent and restarts it, so the first facts reach the manager before the group configuration does;
- registers the `oscompliance-agent` source in the Application log;
- schedules `\OSCompliance\agent-pass` every hour and `\OSCompliance\audit-guard` every 2 minutes, both as SYSTEM, and starts the first pass.

The engine adds the machine to the group within 15 minutes and writes an `<agent_config os="Windows">` block to the group configuration with the facts file, the Microsoft Defender channel, the managed paths and the file integrity paths. A group with Linux and Windows machines gets one block per operating system, so no machine reads the paths of the other one. For a manual setup, `wazuh/agent.conf.windows.fragment.xml` holds the two `localfile` entries.

The manager needs the rules of this release: rule 119007 decodes the Windows facts file and rule 119008 alerts on suspended read watches.

## Check

```powershell
Get-ScheduledTask -TaskPath \OSCompliance\
Get-Content C:\ProgramData\oscompliance\facts.ndjson -Tail 5
& 'C:\Program Files\OSCompliance\oscompliance-agent.exe' -collect device -full
```

The last command runs one collector and writes its fact at once.

## What the agent reads

| Collector | Facts | Reads |
|---|---|---|
| `identity` | identity_record, identity_snapshot | local accounts (`Get-LocalUser`), or Active Directory accounts on a domain controller (`Get-ADUser`, at most 20,000) |
| `groups` | group_record, group_snapshot | local groups and members through ADSI, or Active Directory groups on a domain controller |
| `config` | config_file, config_snapshot | `secedit /export` (account policy, audit policy, user rights, security options), `auditpol /backup`, security registry values (UAC, RDP, LSA, SMB signing, WinRM, event log sizes, SCHANNEL) |
| `device` | device_security | chassis type, inactivity lock policy, BitLocker protection of the system drive, DNS servers, load, memory |
| `firewall` | firewall_snapshot | Windows Firewall profiles and their default actions |
| `malware` | malware_protection | Microsoft Defender status and settings, AppLocker enforcement, Wazuh active response scripts |
| `timesync` | time_sync | W32Time type, sources and synchronisation |
| `updates` | update_status | Windows Update offline search of pending and security updates, last successful search |
| `transactions` | package_transaction, transaction_snapshot | Windows Update history |
| `packages` | package_selection | installed programs from the Uninstall registry keys and installed server features |
| `units` | unit_snapshot | running services and automatic services that stopped with an error |
| `listening` | listening_socket, listening_snapshot | listening TCP endpoints and UDP endpoints outside the dynamic port range, their process and service |
| `neighbours` | neighbour_snapshot | IPv4 neighbour table (`Get-NetNeighbor`), without unresolved, broadcast, multicast and QEMU placeholder entries |
| `wazuh` | wazuh_agent_config | ossec.conf and the shared agent.conf |
| `acl` | acl_record, acl_snapshot | owner and access rules of the `acl_paths` |
| `audit` | audit_watch_snapshot | adds and removes the SACL entries of the read and change watches |
| `-guard-audit` | file_access | event 4663 of the Security log on the watched paths |

Windows translates the output of some tools. The agent reads `auditpol` by subcategory GUID, `secedit` by key and `w32tm` by line position, so a Spanish Windows gives the same facts as an English one. Group names are translated too: the `windows` profile lists both names of each built-in group.

## Audited reads and volume

Windows has no rate limit on event 4663. The agent keeps the volume bounded the same way as on Linux:

- The `audit` collector adds a SACL entry for Everyone, success only, on each read watch (`ReadData`) and change watch (write, append, delete, permission and owner changes). It records the entries it added in `state\sacl-managed.json` and removes only those when the group configuration stops asking for them. It enables success auditing of the File System subcategory.
- `-guard-audit` reads the 4663 events after its bookmark, oldest first and at most 2,000 per run, and writes one `file_access` fact per access under a watch. Services that run as SYSTEM, LOCAL SERVICE or NETWORK SERVICE are named that way instead of the computer account.
- When a read watch records more than `audit_read_limit` reads per minute (60 by default) since the last run, the guard removes its read entry for one hour and writes event 1006 to the Application log. Rule 119008 alerts on it at level 10.

The Wazuh agent does not forward event 4663: its default query excludes it, and the agent forwards the accesses as facts instead.

## Uninstall

```powershell
& ([scriptblock]::Create((irm https://github.com/arseniteio/oscompliance-ens-wazuh/releases/latest/download/install.ps1))) -Uninstall
```

The script also removes the facts entry it added to `ossec.conf`. Add `-Purge` to delete `C:\ProgramData\oscompliance`. The SACL entries the agent added stay on the watched paths; remove them with `Get-Acl -Audit` and `Set-Acl`.

## Limits

- `op.exp.10` reads the accesses to the key stores, but the agent does not inventory certificates or keys on Windows yet.
- `op.exp.6` counts Microsoft Defender detections only through the event channel; the evidence that counts ClamAV detections by rule does not count them yet.
- Logins come from events 4624 of logon types 2, 10 and 11. Network logons (type 3), such as WinRM and SMB, and service logons (type 5) are not logins of a person and are left out.
