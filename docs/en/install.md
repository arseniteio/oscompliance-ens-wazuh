# Installation with packages

This guide installs OSCompliance ENS and Power ENS on a Wazuh deployment installed from packages. It covers an all-in-one server, with the manager, indexer and dashboard on one host, and a distributed deployment, with a manager cluster and separate indexer and dashboard nodes. For Wazuh on Docker, see [Installation with Docker](install-docker.md).

Plan for about one hour on the servers and a few minutes per audited machine. All commands run as root.

`install.sh server` runs the steps of this guide that belong to the node it runs on, and `install.sh agent --group ens` runs section 7 on each audited machine, as in [Get started](../../README.md#get-started). This guide is the manual procedure, and the reference for what the script does.

## Nodes

A deployment has exactly one engine, on the master manager. The engine reaches the indexers over the network and the Wazuh API on its own host.

| Node | Steps | What `install.sh server` installs |
|---|---|---|
| All-in-one server | 2, 3, 4, 6 and 8 | rules, `ens` group, engine users, engine, plugin and manager audit |
| Master manager | 2, 3, 6 and 8 | rules, `ens` group, engine users, engine and manager audit |
| Worker manager | worker part of 2 | nothing: it waits for the rules of its release from the master and restarts `wazuh-manager` |
| Dashboard node | 4 | Power ENS plugin |
| Indexer node | none | nothing |
| Audited machine | 7 | agent, with `install.sh agent` |

A manager is the master when its cluster is disabled in `ossec.conf` or its `node_type` is `master`. A single manager is a master. Section 5 runs in the dashboard and is optional.

Install the master first. The workers take the rules from it through the Wazuh cluster, and Power ENS needs its engine to show results. Then install the worker and dashboard nodes in any order, and the audited machines last. The same `install.sh server` command runs on every server node.

`install.sh server --only <components>` replaces the detection with a comma-separated list of `rules`, `audit`, `engine`, `plugin` and `worker`.

## Requirements

- Wazuh 4.14.7, 4.14.8 or 4.14.9, installed from packages.
- Audited machines on Linux, amd64 or arm64, with a Wazuh agent enrolled in the manager.
- `curl` and `jq` on the master manager, `unzip` on the dashboard nodes, `cron` and `auditd` on the audited machines.
- `curl` and `python3` on the host that holds the indexer admin certificate, to grant access to Power ENS.
- On a distributed deployment, Filebeat on the master manager sending alerts to the indexers, and the master reaching them on port 9200.
- The authentication log of each audited machine reaching Wazuh: `/var/log/auth.log`, `/var/log/secure` or journald, as a localfile of the Wazuh agent.

auditd feeds op.acc.2 EV-06, op.acc.3 and op.acc.4 EV-04 and EV-07. Without it those evidences are not evaluable. Without the authentication log, the login evidences are not evaluable.

### Hardware

The figures below were measured in the lab on arm64 with the 34 controls of the catalog. They come on top of what Wazuh itself needs.

| Component | Where | CPU | Memory | Disk |
|---|---|---|---|---|
| Agent | each audited machine | under 1 second per hourly pass | 15 MB during a pass, nothing between passes | 10 MB for the binary, plus `facts.ndjson`, about 200 KB per day |
| Engine | master manager | 1 core during the pass | 50 MB plus 250 MB per 1,000 audited machines | none on the manager |
| Verdicts | indexer cluster | | | about 2.5 MB per audited machine and day in `oscompliance-verdicts`, before replicas |

A pass over 5,000 machines took 270 seconds and peaked at 1.2 GB of memory. The pass must end within `-interval`, 15 minutes by default, which puts the limit of one engine at about 15,000 machines. The daily file sweep of the agent stops after `sweep_timeout`, 15 minutes by default.

## Before you start

Decide with the organisation which machines to audit, its ENS category (BAJO, MEDIO or ALTO) and who changes the configuration besides the users with `all_access`. A wrong category gives wrong verdicts without any error. The control parameters can be declared later.

On the master manager, check the version and where Filebeat sends the alerts. The engine uses the same indexers and the same CA certificate.

```bash
/var/ossec/bin/wazuh-control info | grep WAZUH_VERSION
grep -A4 'hosts' /etc/filebeat/filebeat.yml
ls /etc/filebeat/certs/root-ca.pem
```

On each dashboard node, check the dashboard version. It must be 2.19.5 on Wazuh 4.14.7 and 2.19.6 on 4.14.8 and 4.14.9.

```bash
grep -m1 '"version"' /usr/share/wazuh-dashboard/package.json
```

On each machine to audit, the services must be `active` and the last command must print at least one line, which means the authentication log reaches Wazuh. On RHEL and Rocky the cron service is `crond`. `uname -m` tells the package: `x86_64` is amd64 and `aarch64` is arm64.

```bash
systemctl is-active wazuh-agent auditd cron
uname -m
grep -E 'auth.log|/var/log/secure|journald' /var/ossec/etc/ossec.conf /var/ossec/etc/shared/agent.conf
```

The script of section 3 asks for passwords. To run it without questions, for example from an automation or an AI agent, export them in that shell first and unset them at the end.

| Variable | Value |
|---|---|
| `API_ADMIN_PASSWORD` | password of `wazuh-wui`, in `wazuh-passwords.txt` inside `wazuh-install-files.tar` |
| `INDEXER_ADMIN_PASSWORD` | password of the indexer `admin` user, in the same file; asked only when the master has no indexer admin certificate |
| `OSC_INDEXER_PASSWORD` | new password of the engine user in the indexer |
| `OSC_WAZUH_API_PASSWORD` | new password of the engine user in the Wazuh API |

`install.sh` also reads these variables.

| Variable | Default | Purpose |
|---|---|---|
| `OSC_INDEXER_URLS` | `output.elasticsearch.hosts` in `/etc/filebeat/filebeat.yml` | indexer URLs of the engine, comma-separated; a host without a scheme gets `https://` |
| `OSC_INDEXER_CA` | `/etc/filebeat/certs/root-ca.pem`, else `/etc/wazuh-indexer/certs/root-ca.pem` | CA certificate of the indexers |
| `OSC_WAIT_SECONDS` | `900` | how long a worker waits for the rules, and an agent without `--group` for the group configuration |

On a rerun without `OSC_INDEXER_URLS`, the script keeps the values of `/etc/oscompliance/engine.conf`.

## 1. Get the packages

Download the package of your architecture and its checksums on each server node where you install something and on every audited machine. `uname -m` tells the architecture: `x86_64` is amd64 and `aarch64` is arm64. The line of your package must end in `OK`. The commands below run from the package folder.

```bash
v=2.1.0
url=https://github.com/arseniteio/oscompliance-ens-wazuh/releases/download/v$v
curl -fLO "$url/oscompliance-ens-$v-linux-amd64.tar.gz" -O "$url/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar xzf "oscompliance-ens-wazuh-$v-linux-amd64.tar.gz" && cd "oscompliance-ens-wazuh-$v-linux-amd64"
```

Each package holds the binaries in `bin/`, the Wazuh files in `wazuh/`, the agent's cron file and example configuration in `agent/`, `install.sh` and the licenses.

On each dashboard node, download the plugin for your dashboard into the same folder: `osd-2.19.5` for Wazuh 4.14.7, `osd-2.19.6` for 4.14.8 and 4.14.9. `create-admin-role.sh` runs on the host that holds the indexer admin certificate.

```bash
url=https://github.com/arseniteio/power-ens-wazuh/releases/download/v$v
curl -fL -o plugin.sha256 "$url/SHA256SUMS"
curl -fLO "$url/power-ens-$v-osd-2.19.6.zip" -O "$url/deploy-plugin.sh" -O "$url/create-admin-role.sh"
sha256sum -c --ignore-missing plugin.sha256
```

To build the packages and the plugin instead, see [Build from source](#build-from-source).

## 2. Install the rules and create the group

Run this on the master manager or the all-in-one server.

The rules use IDs 119000 to 119006. They index facts, the authentication probe, service events and audited accesses, and raise nothing above level 3. No other rule may use those IDs: the first command must print nothing, or only `oscompliance_facts_rules.xml` on a reinstallation. `wazuh-analysisd -t` must print no errors.

```bash
grep -rlE 'id="11900[0-6]"' /var/ossec/etc/rules/
install -o wazuh -g wazuh -m 660 wazuh/oscompliance_facts_rules.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

Wait one minute for the manager to start. Then create the `ens` group.

```bash
/var/ossec/bin/agent_groups -a -g ens -q
```

The engine also creates every group of the ENS scope that does not exist, and adds the machines that ask for the group, as in section 7. To add a machine by hand instead, replace `<id>` with the agent ID from the list. A machine keeps its other groups.

```bash
/var/ossec/bin/agent_control -l
/var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

On each worker manager, do not install the rules by hand. The master syncs them through the Wazuh cluster. Wait until the file on the worker matches the one in the package, which `cmp` confirms by printing nothing, then restart the manager so that it loads the rules.

```bash
cmp /var/ossec/etc/rules/oscompliance_facts_rules.xml wazuh/oscompliance_facts_rules.xml
systemctl restart wazuh-manager
```

## 3. Create the engine users

Run this on the master manager or the all-in-one server.

The engine has its own user in the indexer and in the Wazuh API, with the permissions listed in [Security](security.md#engine). This script creates them and writes the credentials to `/etc/oscompliance/engine.env`.

It asks for the password of `wazuh-wui`, found in `wazuh-passwords.txt` inside `wazuh-install-files.tar`, and for two new passwords. Each new password needs 8 to 64 characters with upper and lower case, a digit and a symbol, and cannot hold `$`, `&`, quotes, backslashes or spaces. To run it without questions, export the variables of [Before you start](#before-you-start).

The script authenticates to the indexer with the admin certificate when `/etc/wazuh-indexer/certs/admin.pem` and `admin-key.pem` exist, as on an all-in-one server. Otherwise it asks for the password of the indexer `admin` user, so no certificate is copied between hosts. `INDEXER_ADMIN` sets another user.

It reaches the indexer at `INDEXER_URL`, `https://127.0.0.1:9200` by default, and checks it against `INDEXER_CA`, `/etc/wazuh-indexer/certs/root-ca.pem` by default. On a distributed deployment, set them to one of the Filebeat hosts and the Filebeat CA.

```bash
export INDEXER_URL=https://10.0.0.1:9200 INDEXER_CA=/etc/filebeat/certs/root-ca.pem
bash wazuh/engine-users.sh create
```

Each run sets the passwords again. To keep the passwords in `engine.env` and only update the roles and permissions, as `install.sh server` does on a rerun, set `KEEP_PASSWORDS=1`. The script still asks for the password of `wazuh-wui`.

```bash
KEEP_PASSWORDS=1 bash wazuh/engine-users.sh create
```

## 4. Install the plugin

Run this on each dashboard node or the all-in-one server.

The script validates the zip, keeps a copy of any previous version in `/var/backups/power-ens`, installs the plugin and restarts the dashboard. It must end with the dashboard active.

```bash
bash deploy-plugin.sh "power-ens-wazuh-$v-osd-2.19.6.zip"
```

Log in to the dashboard and open Power ENS. If it says `No se puede leer el inventario de agentes`, the dashboard has not yet written its agent inventory, which it does every 15 minutes: wait and press Reintentar.

A user with `all_access` can change the configuration. To allow another user, give it the `power_ens_admin` role. The script adds the user and keeps the ones that already have the role. Run it on the host that holds the indexer admin certificate: the all-in-one server or the indexer node where the certificate was generated. When the indexer does not listen on `127.0.0.1:9200` of that host, set `OS_URL`.

```bash
bash create-admin-role.sh --map <user>
```

## 5. Set the ENS configuration

This step is optional for the first verdicts. Until a configuration is saved in Power ENS, the engine and the plugin use the catalog default, `catalog/default-configuration.json`: level MEDIO and the `ens` group in scope. Save a configuration to change the level or the scope, and to declare the parameters of the controls.

The screens are in Spanish. In Power ENS, open Configuración.

1. In General, fill in Cliente, change Nivel ENS if your system has another level, and press Guardar configuración global. This creates the configuration.
2. In Organización, open each control, press Completar configuración, fill in what is missing and save.
3. In Grupos y máquinas, give each group the values of its machines, and open a machine to set the parameters that belong to it alone.

Each page in [Controls](controls/README.md) lists the parameters of its control. A control can be filled in later: until then it shows as not evaluable by configuration.

The first save is only done from the dashboard, because it writes the full catalog of controls. After it, the parameters can also be set from a JSON file: see [Configuration](configuration.md#parameters-from-a-file).

## 6. Start the engine

Run this on the master manager or the all-in-one server. Never start a second engine on a worker.

The systemd unit reads the indexer URLs and the CA certificate from `/etc/oscompliance/engine.conf`. Without that file it uses `https://127.0.0.1:9200` and `/etc/wazuh-indexer/certs/root-ca.pem`, which fit an all-in-one server. On a distributed deployment, write the file with the hosts of `output.elasticsearch.hosts` in `/etc/filebeat/filebeat.yml`, each with its scheme, and the Filebeat CA. When an indexer does not answer, the engine tries the next URL.

```bash
install -d -m 755 /etc/oscompliance
cat > /etc/oscompliance/engine.conf <<'EOF'
OSC_INDEXER_URLS=https://10.0.0.1:9200,https://10.0.0.2:9200
OSC_INDEXER_CA=/etc/filebeat/certs/root-ca.pem
EOF
```

Install and start the engine.

```bash
install -m 755 bin/oscompliance-engine bin/oscompliance-policy /usr/local/bin/
install -m 644 wazuh/oscompliance-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now oscompliance-engine
```

Wait 20 seconds. Until a configuration is saved, the log shows a `parameters` line with `catalog default`. It must also show a `group configuration` line with `applied` true and a `pass` line with no `error`.

```bash
journalctl -u oscompliance-engine -n 10 --no-pager
```

The group configuration must now hold a block between `oscompliance begin` and `oscompliance end`, with the `facts.ndjson` localfile. In a cluster, the master syncs it to the workers.

```bash
cat /var/ossec/etc/shared/ens/agent.conf
```

The engine writes only that block. It leaves the rest of the file untouched.

## 7. Install the agent on the audited machines

On each machine to audit, install the agent and its cron file. It reads `/etc/shadow`, `sshd -T` and the sudoers files, so it runs as root. It needs no other configuration on a standard system.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
touch /var/log/oscompliance/facts.ndjson
```

The machine then joins the `ens` group in one of two ways.

### Ask the engine to add the machine

This is what `install.sh agent --group ens` does. No command per machine is needed on the manager.

Write the group to the agent configuration. If `/etc/oscompliance/agent.json` already exists, add the `wazuh_group` key to it instead.

```bash
install -d -m 755 /etc/oscompliance
echo '{"wazuh_group": "ens"}' > /etc/oscompliance/agent.json
```

Add this block at the end of `/var/ossec/etc/ossec.conf`, so that the Wazuh agent reads the facts file before the group configuration arrives. Keep the markers: the uninstall finds the block by them.

```xml
<!-- oscompliance begin -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/oscompliance/facts.ndjson</location>
  </localfile>
</ossec_config>
<!-- oscompliance end -->
```

Restart the Wazuh agent before the first pass. Otherwise Wazuh opens the file later and skips what is already in it.

```bash
systemctl restart wazuh-agent
sleep 30
oscompliance-agent -full
```

Every `agent_pass` fact carries the group as `requested_group`. On its next group sync, within 15 minutes, the engine adds the agent to the group, and the group configuration follows. The engine adds an agent only to a group of the ENS scope, never to any other group, and only from `agent_pass` facts inside its window.

When the group configuration arrives, the facts file is declared twice. Wazuh logs warning 1958, which says the log file is duplicated, and reads the file once. The warning needs no action.

### Add the machine by hand

Add the machine to the group on the master manager, as in section 2. Then wait until it has received the group configuration: this command must print a number above 0.

```bash
grep -c facts.ndjson /var/ossec/etc/shared/agent.conf
```

Restart the Wazuh agent before the first pass. Otherwise Wazuh opens the file later and skips what is already in it.

```bash
systemctl restart wazuh-agent
sleep 30
oscompliance-agent -full
```

### Check the agent

The last line of the facts file must be JSON with `"oscompliance":"1"`.

```bash
tail -n 1 /var/log/oscompliance/facts.ndjson
```

The agent adds its audit watches at runtime with `auditctl`, tagged `oscompliance_*`. It unloads the `oscompliance_*` watches the group configuration no longer asks for and never writes to `/etc/audit`. With SELinux enforcing, also run `restorecon -R /usr/local/bin/oscompliance-agent /etc/cron.d/oscompliance /var/log/oscompliance`.

On RHEL and Rocky, `cron` is the `cronie` package.

```bash
dnf install -y cronie && systemctl enable --now crond
```

## 8. Audit the manager

Run this on the master manager or the all-in-one server. The worker managers are not audited.

The manager is judged like any other machine. Until the agent runs on it, its row shows as not compliant. It belongs to no group, so it needs two settings of its own.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
install -d -m 755 /etc/oscompliance
echo '{"paths": {"wazuh_shared_conf": "/var/ossec/etc/shared/ens/agent.conf", "wazuh_client_keys": ""}}' > /etc/oscompliance/agent.json
touch /var/log/oscompliance/facts.ndjson
```

Add the facts file and the audit log to `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`.

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/oscompliance/facts.ndjson</location>
</localfile>
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Restart the manager and run the first pass.

```bash
systemctl restart wazuh-manager
sleep 60
oscompliance-agent -full
```

## 9. Verify

Log in to an audited machine over SSH, so that a real login reaches Wazuh, and wait one minute. Then run an engine pass on the master manager. The last `pass` line must show `verdicts` above 0 and no `error`.

```bash
systemctl restart oscompliance-engine
sleep 20
journalctl -u oscompliance-engine -n 5 --no-pager
```

The machines that asked for the group must be in it after the next group sync. List them on the master manager.

```bash
/var/ossec/bin/agent_groups -l -g ens
```

In the dashboard, open Discover on `wazuh-alerts-*`. `rule.id:119001` must show the facts of each machine, and `rule.id:119002` one authentication probe per machine and pass.

In Power ENS, open Detalle del control and choose a machine. Each evidence shows its status and the reason. The usual result on a new machine is partial: an evidence stays not evaluable until its parameters are declared, and a requirement that depends on a document stays open until its attestation is declared in P-ATT.

The first complete picture needs one agent pass and one engine pass after it. Without `-full` that takes up to 75 minutes.

If a step gives another result, see [Operations](operations.md#troubleshooting).

## Upgrade

Upgrade the master first: its engine reads facts from older agents. Then upgrade the workers, the dashboard nodes and the audited machines.

With the install script, run `install.sh server` of the new release on the master, then on each worker and dashboard node, and `install.sh agent` with the same arguments as before on each audited machine. On the master, the script keeps the passwords of the engine users and updates their permissions. It still asks for the password of `wazuh-wui`, and for the indexer `admin` password when there is no admin certificate. A worker waits up to `OSC_WAIT_SECONDS` until its rules file matches the one of the new release, then restarts its manager. If the rules do not arrive in time, the script stops with an error: upgrade the master, then run it again.

By hand, on the master, save the current binary, so you can return to it by putting it back and restarting the service.

```bash
cp /usr/local/bin/oscompliance-engine /usr/local/bin/oscompliance-engine.prev
install -m 755 bin/oscompliance-engine bin/oscompliance-policy /usr/local/bin/
systemctl restart oscompliance-engine
```

If the role changed, run `KEEP_PASSWORDS=1 bash wazuh/engine-users.sh create` as in section 3. Version 1.2.0 adds two Wazuh API actions, so an upgrade from 1.1.0 needs it. If the rules changed, install them on the master as in section 2 and restart each worker once they arrive, as in the worker part of section 2. On each audited machine, install the new agent binary: the next cron run uses it. On each dashboard node, install the plugin zip of the same release as in section 4.

From 1.2.0 to 2.0.0, the first pass of the new agent unloads the read watches of 1.2.0 on each Linux machine of a group with the engine's block. On a machine outside such a group, run `auditctl -D -k oscompliance_read` and `auditctl -D -k oscompliance_exec` once. The releases are now published in `arseniteio/oscompliance-ens-wazuh` and `arseniteio/power-ens-wazuh`: download `install.sh` and the packages from there.

## Uninstall

With the install script, run `install.sh uninstall` on each node and audited machine. On each one it removes what it finds there: the engine and its users, the plugin, the manager parts on a manager, and the agent with its block in `ossec.conf`. The rules and the block in the group configuration are removed only on the master, and the workers follow it through the cluster. The manual steps follow.

On each audited machine, remove the agent.

```bash
rm -f /etc/cron.d/oscompliance /usr/local/bin/oscompliance-agent
rm -rf /etc/oscompliance /var/log/oscompliance /var/lib/oscompliance
augenrules --load
```

If the machine asked for the group, also remove the block from `ossec.conf` and restart the Wazuh agent.

```bash
sed -i '/<!-- oscompliance begin -->/,/<!-- oscompliance end -->/d' /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
```

On each dashboard node, remove the plugin.

```bash
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove powerEns
systemctl restart wazuh-dashboard
```

On the master manager, remove the engine, the rules and the block in the group configuration, and restart the manager.

```bash
systemctl disable --now oscompliance-engine
rm -f /etc/systemd/system/oscompliance-engine.service /usr/local/bin/oscompliance-engine /usr/local/bin/oscompliance-policy
systemctl daemon-reload
rm -f /var/ossec/etc/rules/oscompliance_facts_rules.xml
sed -i '/<!-- oscompliance begin/,/<!-- oscompliance end -->/d' /var/ossec/etc/shared/ens/agent.conf
systemctl restart wazuh-manager
```

Remove the engine users. The script asks for the password of `wazuh-wui`, and for the indexer `admin` password when there is no admin certificate. On a distributed deployment, set `INDEXER_URL` and `INDEXER_CA` as in section 3.

```bash
bash wazuh/engine-users.sh remove
```

On each worker manager, restart the manager once the rules file is gone.

The indices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history`, `oscompliance-host-profile` and `wazuh-ens-configuration` stay in the indexer, so the history is not lost. Delete them from Dev Tools when you no longer need them. If you audited the manager, also remove the agent from the master as from an audited machine, and remove its two localfile blocks from `ossec.conf`.

## Build from source

Build the packages in this repository with Go 1.27.2 or later. The result is in `dist/`, with `install.sh` and `SHA256SUMS`.

```bash
make dist VERSION=2.1.0
```

Build the plugin in the power-ens-wazuh repository with Docker, for the OpenSearch Dashboards version of your dashboard. The first build takes about 20 minutes. The result is `dist/powerEns-2.19.6.zip`.

```bash
ci/build-zip.sh 2.19.6
```
