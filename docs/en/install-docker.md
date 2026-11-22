# Installation with Docker

This guide installs OSCompliance ENS and Power ENS on a Wazuh deployment based on the official wazuh-docker single-node compose file. For Wazuh installed from packages, see [Installation with packages](install.md).

Plan for about one hour on the Docker host and a few minutes per audited machine. All commands run as root on the Docker host, except in section 7.

## Requirements

- Wazuh 4.14.7, 4.14.8 or 4.14.9, with ports 9200 and 55000 published on the host.
- The service names, volumes and certificate folder of the official compose file: `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`, the `wazuh_api_configuration` volume and `config/wazuh_indexer_ssl_certs`. If yours differ, adapt `wazuh/docker-compose.override.yml` and the variables of section 1.
- Audited machines on Linux, amd64 or arm64, with a Wazuh agent enrolled in the manager.
- `curl`, `jq` and `python3` on the host, `cron` and `auditd` on the audited machines.
- The authentication log of each audited machine reaching Wazuh: `/var/log/auth.log`, `/var/log/secure` or journald, as a localfile of the Wazuh agent.

auditd feeds op.acc.2 EV-06, op.acc.3 and op.acc.4 EV-04 and EV-07. Without it those evidences are not evaluable. Without the authentication log, the login evidences are not evaluable.

Before you start, decide with the organisation, check the machines to audit and prepare the passwords as in [Before you start](install.md#before-you-start) of the package guide. On Docker, `API_ADMIN_PASSWORD` is `API_PASSWORD` in your compose file.

## 1. Set the variables

Set these in a shell and keep it open until section 6. `WAZUH_DIR` is the folder of your `docker-compose.yml`. `PROJECT` is the compose project name, shown by `docker compose ls`.

```bash
export WAZUH_DIR=/srv/wazuh-docker/single-node
export PROJECT=single-node
export WAZUH_VERSION=4.14.8
export MGR=$PROJECT-wazuh.manager-1
export CERTS=$WAZUH_DIR/config/wazuh_indexer_ssl_certs
```

Your compose file is not changed. The installation adds `docker-compose.override.yml` next to it, which compose reads on its own. If that file already exists, this command prints it: add the content of section 5 to it by hand instead of copying it.

```bash
cat "$WAZUH_DIR/docker-compose.override.yml" 2>/dev/null
```

Check the dashboard version. It must be 2.19.5 on Wazuh 4.14.7 and 2.19.6 on 4.14.8 and 4.14.9. Download the plugin for that version in section 2.

```bash
docker exec "$PROJECT-wazuh.dashboard-1" grep -m1 '"version"' /usr/share/wazuh-dashboard/package.json
```

## 2. Get the packages

Download the package of your architecture and its checksums on the host and on every audited machine, and the plugin files on the host, as in [section 1 of the package guide](install.md#1-get-the-packages). On Docker the plugin needs `dashboard.Dockerfile` instead of `deploy-plugin.sh`.

```bash
v=2.1.0
url=https://github.com/arseniteio/power-ens-wazuh/releases/download/v$v
curl -fLO "$url/dashboard.Dockerfile"
```

To build the packages and the plugin instead, see [Build from source](install.md#build-from-source).

## 3. Install the rules and create the group

The rules use IDs 119000 to 119006. No other rule may use them: the first command must print nothing, or only `oscompliance_facts_rules.xml` on a reinstallation. `wazuh-analysisd -t` must print no errors.

```bash
docker exec "$MGR" grep -rlE 'id="11900[0-6]"' /var/ossec/etc/rules/
docker cp wazuh/oscompliance_facts_rules.xml "$MGR:/var/ossec/etc/rules/"
docker exec "$MGR" chown wazuh:wazuh /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" chmod 660 /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" /var/ossec/bin/wazuh-analysisd -t
docker exec "$MGR" /var/ossec/bin/wazuh-control restart
```

Wait one minute for the manager to start. Then create the `ens` group and add each machine to audit, replacing `<id>` with the agent ID from the list. A machine keeps its other groups.

```bash
docker exec "$MGR" /var/ossec/bin/agent_groups -a -g ens -q
docker exec "$MGR" /var/ossec/bin/agent_control -l
docker exec "$MGR" /var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

## 4. Create the engine users

The engine has its own user in the indexer and in the Wazuh API, with the permissions listed in [Security](security.md#engine). This script creates them and writes the credentials to `/etc/oscompliance/engine.env` on the host. The two variables make it reach the indexer under the name in its certificate.

It asks for the password of `wazuh-wui`, which is `API_PASSWORD` in your compose file, and for two new passwords. Each new password needs 8 to 64 characters with upper and lower case, a digit and a symbol, and cannot hold `$`, `&`, quotes, backslashes or spaces. To run it without questions, export the variables of [Before you start](install.md#before-you-start).

```bash
export INDEXER_URL=https://wazuh.indexer:9200
export INDEXER_RESOLVE=wazuh.indexer:9200:127.0.0.1
bash wazuh/engine-users.sh create
```

## 5. Install the plugin

The plugin goes into its own image, because anything installed in a running container is lost when the container is recreated. From the folder holding the zip and the Dockerfile:

```bash
docker build -f dashboard.Dockerfile --build-arg WAZUH_VERSION="$WAZUH_VERSION" \
  --build-arg PLUGIN_ZIP="power-ens-wazuh-$v-osd-2.19.6.zip" -t power-ens/wazuh-dashboard:local .
```

From the package folder, install the engine binary and the override file, and recreate the dashboard. The override file sets the dashboard image and defines the engine service, which starts in section 6.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
cp wazuh/docker-compose.override.yml "$WAZUH_DIR/"
(cd "$WAZUH_DIR" && docker compose -p "$PROJECT" up -d wazuh.dashboard)
```

Log in to the dashboard and open Power ENS. If it says `No se puede leer el inventario de agentes`, the dashboard has not yet written its agent inventory, which it does every 15 minutes: wait and press Reintentar.

A user with `all_access` can change the configuration. To allow another user, give it the `power_ens_admin` role. The script adds the user and keeps the ones that already have the role.

```bash
export OS_CERT=$CERTS/admin.pem OS_KEY=$CERTS/admin-key.pem OS_CA=$CERTS/root-ca.pem
export OS_URL=$INDEXER_URL OS_RESOLVE=$INDEXER_RESOLVE
bash create-admin-role.sh --map <user>
```

Until a configuration is saved, the engine uses the catalog default: level MEDIO and the `ens` group in scope. To change it, set the ENS configuration as in [section 5 of the package guide](install.md#5-set-the-ens-configuration).

## 6. Start the engine

```bash
(cd "$WAZUH_DIR" && docker compose -p "$PROJECT" up -d oscompliance.engine)
```

Wait 20 seconds. The log must show a `group configuration` line with `applied` true and a `pass` line with no `error`.

```bash
docker logs --tail 10 "$PROJECT-oscompliance.engine-1"
```

The group configuration must now hold a block between `oscompliance begin` and `oscompliance end`, with the `facts.ndjson` localfile.

```bash
docker exec "$MGR" cat /var/ossec/etc/shared/ens/agent.conf
```

## 7. Install the agent on the audited machines

On each machine to audit, run `install.sh agent --group ens` from the package, or follow [section 7 of the package guide](install.md#7-install-the-agent-on-the-audited-machines).

This guide does not audit the manager container, so its row shows as not compliant. To see each result, choose the machine in the Máquina selector.

## 8. Verify

Log in to an audited machine over SSH, so that a real login reaches Wazuh, and wait one minute. Then run an engine pass. The last `pass` line must show `verdicts` above 0 and no `error`.

```bash
docker restart "$PROJECT-oscompliance.engine-1"
sleep 20
docker logs --tail 5 "$PROJECT-oscompliance.engine-1"
```

Then check the dashboard as in [section 9 of the package guide](install.md#9-verify).

## Upgrade

Upgrade the engine first: it reads facts from older agents. Install the new binary and restart the service. If the rules changed, install them as in section 3. If the role changed, run `KEEP_PASSWORDS=1 bash wazuh/engine-users.sh create` with the variables of sections 1 and 4; an upgrade from 1.1.0 needs it. On each audited machine, install the new agent binary.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
docker restart "$PROJECT-oscompliance.engine-1"
```

To upgrade the plugin, keep the current image under another tag, build the new one with the same tag and recreate the dashboard. To go back, tag `previous` as `local` again and recreate it.

```bash
docker tag power-ens/wazuh-dashboard:local power-ens/wazuh-dashboard:previous
docker build -f dashboard.Dockerfile --build-arg WAZUH_VERSION="$WAZUH_VERSION" \
  --build-arg PLUGIN_ZIP="power-ens-wazuh-$v-osd-2.19.6.zip" -t power-ens/wazuh-dashboard:local .
(cd "$WAZUH_DIR" && docker compose -p "$PROJECT" up -d wazuh.dashboard)
```

The dashboard image is built on one Wazuh version, so it does not follow a Wazuh upgrade. Follow the official Wazuh procedure, and before you recreate the services build the plugin and the image for the new version as above. The plugin must match the dashboard: 2.19.5 for Wazuh 4.14.7, 2.19.6 for 4.14.8 and 4.14.9.

## Uninstall

On each audited machine, follow the first step of [the package guide](install.md#uninstall).

On the host, stop the engine, remove the override file and recreate the dashboard with the official image. Then remove the rules and the block in the group configuration, and restart the manager.

```bash
cd "$WAZUH_DIR"
docker compose -p "$PROJECT" rm -sf oscompliance.engine
rm -f docker-compose.override.yml /usr/local/bin/oscompliance-engine
docker compose -p "$PROJECT" up -d wazuh.dashboard
docker image rm power-ens/wazuh-dashboard:local
docker exec "$MGR" rm -f /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" sed -i '/<!-- oscompliance begin/,/<!-- oscompliance end -->/d' /var/ossec/etc/shared/ens/agent.conf
docker exec "$MGR" /var/ossec/bin/wazuh-control restart
```

Remove the engine users, with the same variables as in section 4. The script asks for the password of `wazuh-wui`.

```bash
bash wazuh/engine-users.sh remove
```

The indices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history`, `oscompliance-host-profile` and `wazuh-ens-configuration` stay in the indexer, so the history is not lost. Delete them from Dev Tools when you no longer need them.
