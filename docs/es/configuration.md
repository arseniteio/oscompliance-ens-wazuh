# Configuración

Se configuran tres cosas, en tres lugares. El operador define la conexión y los tiempos del motor una vez, con flags, `/etc/oscompliance/engine.conf` y `/etc/oscompliance/engine.env` en el manager maestro. El operador define las rutas del agente en `/etc/oscompliance/agent.json`, solo en máquinas no estándar. El responsable de seguridad define la política ENS (nivel, alcance y cada parámetro de control) en Power ENS en cualquier momento. Se guarda en `wazuh-ens-configuration`.

La política nunca reside en las máquinas. Los agentes solo guardan rutas; cada valor que decide el cumplimiento es un parámetro de Power ENS, y el motor lo recarga en cada pasada.

## Motor

`oscompliance-engine` no lee ningún fichero de configuración, solo flags y dos variables de entorno. Sin `-interval` ejecuta una pasada y termina.

| Flag | Por defecto | Función |
|---|---|---|
| `-indexer` | `https://wazuh.indexer:9200` | URL de los indexers, separadas por comas; cuando una no responde, el motor prueba la siguiente |
| `-user` | `admin` | usuario del indexer; contraseña en `OSC_INDEXER_PASSWORD` |
| `-ca` | raíces del sistema | certificado de CA del indexer (PEM) |
| `-wazuh-api` | vacío | URL de la API de Wazuh; vacío desactiva todo lo que se lee o se escribe en la API |
| `-wazuh-api-user` | `oscompliance` | usuario de la API; contraseña en `OSC_WAZUH_API_PASSWORD` |
| `-wazuh-api-ca` | raíces del sistema | certificado con el que se confía en la API (PEM) |
| `-wazuh-api-server-name` | host de la URL | nombre comprobado en el certificado de la API |
| `-interval` | `0` | tiempo entre pasadas; `0` ejecuta una vez |
| `-window` | `26h` | cuentan los eventos más recientes que esto |
| `-lookback` | `168h` | se juzgan los agentes con hechos así de recientes |
| `-sync-interval` | `15m` | tiempo mínimo entre dos sincronizaciones de la configuración de grupo |
| `-sync-apply` | desactivado | escribe la configuración de grupo; sin él los cambios solo se registran |
| `-controls` | vacío | controles que juzgar, separados por comas; vacío los juzga todos |
| `-alerts-index` | `wazuh-alerts-*` | patrón del índice de alertas |
| `-monitoring-index` | `wazuh-monitoring-*` | patrón del índice de keepalive de los agentes |
| `-states-prefix` | `wazuh-states-` | prefijo de los índices de inventario y vulnerabilidades de Wazuh |
| `-config-index` | `wazuh-ens-configuration` | índice de configuración de Power ENS |
| `-verdicts-index` | `oscompliance-verdicts` | veredictos |
| `-history-index` | `oscompliance-identity-history` | historial por cuenta |
| `-config-history-index` | `oscompliance-config-history` | cambios en la configuración de grupo |
| `-host-profile-index` | `oscompliance-host-profile` | lo que el motor deduce de cada máquina |
| `-profile-groups` | desactivado | mete cada máquina en el grupo de Wazuh `ens-perfil-<id>` de cada perfil que recibe; necesita `-wazuh-api` y solo escribe con `-sync-apply` |

| Variable de entorno | Función |
|---|---|
| `OSC_INDEXER_PASSWORD` | contraseña del indexer |
| `OSC_WAZUH_API_PASSWORD` | contraseña de la API de Wazuh |

La ventana es de 26 horas para que un agente horario y un barrido diario siempre tengan una pasada dentro, con margen para una ejecución tardía de cron.

La unidad de systemd `oscompliance-engine.service` lee `/etc/oscompliance/engine.conf` y pasa `OSC_INDEXER_URLS` a `-indexer` y `OSC_INDEXER_CA` a `-ca`. Sin el fichero usa `https://127.0.0.1:9200` y `/etc/wazuh-indexer/certs/root-ca.pem`. `install.sh server` escribe el fichero a partir de la salida de Filebeat del manager: los hosts de `output.elasticsearch.hosts` de `/etc/filebeat/filebeat.yml` y `/etc/filebeat/certs/root-ca.pem` o, si no, `/etc/wazuh-indexer/certs/root-ca.pem`.

```ini
OSC_INDEXER_URLS=https://10.0.0.1:9200,https://10.0.0.2:9200
OSC_INDEXER_CA=/etc/filebeat/certs/root-ca.pem
```

## Perfil de máquina

En cada pasada, el motor deduce qué es cada máquina a partir del inventario de Wazuh y lo escribe en `oscompliance-host-profile`, un documento por agente. Ningún agente envía nada nuevo y no se configura nada en las máquinas.

| Campo | Procede de |
|---|---|
| `distro`, `family` | `host.os.platform` o, si no, `host.os.name` de `wazuh-states-inventory-system`, con la versión recortada a `major` o `major.minor` |
| `role` | `manager` para el agente 000 o una máquina con `wazuh-manager`; `workstation` para una máquina con un gestor de pantalla o un paquete de escritorio; `server` en el resto |
| `services` | paquetes instalados de `wazuh-states-inventory-packages`, como `zimbra-core` o `slapd` |
| `groups` | los grupos de Wazuh del agente |
| `signals` | cada deducción con el campo o el paquete del que sale |

Las reglas están en [`catalog/host-signals.json`](../../catalog/host-signals.json). Un nombre de paquete que termina en `*` compara por prefijo. Un servicio con `unless` se omite cuando está presente alguno de esos servicios, para que el LDAP que trae Zimbra no aparezca como OpenLDAP.

El perfil de máquina decide qué [perfiles](#perfiles) recibe cada máquina.

## Perfiles

Un perfil da valores de parámetros a todas las máquinas cuyo perfil de máquina cumple sus condiciones, de modo que un valor se define una vez por tipo de máquina y no una vez por máquina. Cada perfil es un documento de `wazuh-ens-configuration` con `documentType` `PROFILE`. Power ENS muestra los perfiles como grupos y los gestiona en Configuración > Grupos y máquinas, que muestra las máquinas a las que llega cada grupo mientras se edita, importa y exporta YAML, y muestra en cada máquina sus grupos y el origen de cada valor. `oscompliance-policy`, más abajo, es la opción para automatizar. El catálogo trae `ubuntu`, `manager-wazuh` y `windows` en [`catalog/profiles/`](../../catalog/profiles/), con los mismos valores que las plantillas integradas; un perfil guardado con el mismo `id` sustituye al integrado.

```yaml
id: web
name: Servidores web
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

| Clave | Significado |
|---|---|
| `id` | minúsculas, dígitos y guiones |
| `layer` | `distro`, `role`, `service` o `site`, de menos a más específica |
| `match` | condiciones que deben cumplirse todas: `distro`, `family`, `role` y `hostname` admiten `is`, `is_not`, `matches` (patrón de shell como `web-*`) o `in` (lista separada por comas, para un grupo de máquinas elegidas a mano); `service` y `group` admiten `has` o `has_not` |
| `values` | parámetros por control, con los tipos de la [política ENS](#política-ens); no se aceptan parámetros `organisation` |
| `match_modes` | `regex` para un parámetro dado como expresión regular |
| `replace` | parámetros, por control, para los que este perfil descarta los valores de las capas menos específicas |

Cuando varios perfiles encajan con una máquina, las listas y las tablas se suman desde todas las capas y el resto de valores sale de la más específica. Un valor definido para la propia máquina, o una plantilla asignada a ella, va primero; una máquina con la plantilla `none` no toma ningún perfil. Sin perfil de máquina, que el motor escribe en su siguiente pasada, la máquina sigue con la plantilla integrada de su tipo de sistema.

Con `-profile-groups`, el motor mantiene además un grupo de Wazuh por perfil, `ens-perfil-<id>`, con las máquinas que lo reciben, y da al grupo la etiqueta `ens.perfil.<id>`. Así las alertas llevan `agent.labels.ens.perfil.<id>`, y las reglas, los dashboards o el `agent.conf` de un grupo pueden distinguir las máquinas por perfil. Una máquina que deja de encajar sale del grupo; el manager nunca se añade. Una condición de perfil no puede usar estos grupos.

Para automatizar, `oscompliance-policy`, que se instala con el motor, lee perfiles de ficheros YAML y los escribe. Sus ficheros tienen el mismo formato que Exportar e Importar en Power ENS. Usa el usuario y la contraseña del indexer, como el motor: ejecútalo en el manager con un usuario administrador.

```bash
export OSC_INDEXER_PASSWORD='...'
oscompliance-policy check perfiles/*.yaml
oscompliance-policy plan -ca /etc/wazuh-indexer/certs/root-ca.pem perfiles/*.yaml
oscompliance-policy apply -ca /etc/wazuh-indexer/certs/root-ca.pem perfiles/*.yaml
```

`check` valida los ficheros sin conectarse. `plan` muestra cada perfil como nuevo, cambiado (con los parámetros que cambian) o igual, y los perfiles guardados que no están en los ficheros. `apply` escribe los nuevos y los cambiados; el motor los usa desde su siguiente pasada. `export` imprime en YAML los perfiles guardados, todos o los indicados, y con `-builtin` también los integrados, para partir de lo que está en uso. `delete` borra perfiles guardados. `explain -agent 001` muestra lo que el motor ha deducido de una máquina, los perfiles que recibe y de dónde sale cada uno de sus parámetros. `-indexer` indica la URL del indexer, `https://localhost:9200` por defecto.

## Configuración de grupo

Con `-wazuh-api` y `-sync-apply`, el motor mantiene una región marcada en el `agent.conf` de cada grupo de Wazuh nombrado en el alcance ENS:

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

| Contenido | Procede de |
|---|---|
| `acl_paths` | P-08 de op.acc.2, P-08 de op.exp.2 |
| `audit_watches` | P-04 de op.exp.3: solo escrituras y cambios de atributos |
| `read_watches` | P-06 de op.acc.2, rutas de P-03 de op.acc.3 y las rutas de seguridad, P-07 de op.acc.4, P-02 de op.exp.10: lecturas de sesiones con UID de inicio de sesión, y además escrituras, ejecuciones y cambios de atributos |
| `exec_watches` | binarios de P-03 de op.acc.3 |
| `backup_sources`, `backup_keys` | P-07 de op.exp.3, P-04 y P-08 de mp.info.6 |
| `key_stores` | P-02 de op.exp.10 |
| `<directories>` de FIM | rutas de P-02 de op.acc.2 fuera de los valores por defecto de Wazuh |
| localfiles de servicio | P-02 de op.acc.5 |

Lo que comparten la mayoría de las máquinas del grupo va a todos los agentes; una máquina que necesita otras rutas o tiene servicios propios recibe un bloque con su nombre. Todo lo que queda fuera de las marcas no se toca. Cada cambio se registra en `oscompliance-config-history` con la región anterior y posterior; sin `-sync-apply` el cambio se registra pero no se escribe.

En cada sincronización de grupos, el motor también crea los grupos del alcance ENS que no existen y les añade los agentes que los piden. Un agente pide un grupo con `wazuh_group` en su `agent.json`, que envía como `requested_group` en cada hecho `agent_pass`. El motor lee las peticiones de los hechos `agent_pass` dentro de su ventana, y solo añade un agente a un grupo del alcance ENS. Una petición de cualquier otro grupo se ignora. Cada asignación se registra en `oscompliance-config-history`.

## Grupos por control

Con la opción activada en Power ENS (`scope.controlGroups`), el motor crea un grupo de Wazuh por control, `ens-excluir-<control>`, en su siguiente sincronización de grupos. Necesita `-wazuh-api`, `-sync-apply` y `group:create` en su rol de API. Para sacar una máquina de un control, añádela a ese grupo. Al desactivar la opción, los grupos se ignoran y no se borra ninguno. Consulta [Veredictos](verdicts.md).

## Agente

`/etc/oscompliance/agent.json` es opcional. Sin él, el agente usa los valores por defecto; con él, solo cambian las claves presentes. Una clave desconocida detiene el agente con un error. El fichero se lee en cada ejecución.

| Clave | Por defecto | Función |
|---|---|---|
| `output` | `/var/log/oscompliance/facts.ndjson` | fichero al que se añaden los hechos |
| `host` | nombre de host del sistema | nombre de host escrito en cada hecho |
| `state` | `/var/lib/oscompliance/state.json` | lo último que envió cada colector, para enviar solo los cambios |
| `collectors` | todos menos `sweep` | colectores de la pasada horaria |
| `sweep_timeout` | `15m` | límite de tiempo del barrido diario del sistema de ficheros |
| `audit_read_limit` | `60` | lecturas por minuto que puede registrar una vigilancia de lectura antes de que `-guard-audit` la retire una hora |
| `paths.passwd` | `/etc/passwd` | base de datos de cuentas |
| `paths.shadow` | `/etc/shadow` | caducidad y bloqueo de contraseñas |
| `paths.group` | `/etc/group` | base de datos de grupos |
| `paths.sshd` | `/usr/sbin/sshd` | binario de sshd, al que se pide su configuración efectiva |
| `paths.sudoers` | `/etc/sudoers` | fichero sudoers principal; se siguen los includes |
| `paths.pam_dir` | `/etc/pam.d` | configuración de PAM |
| `paths.wazuh_shared_conf` | `/var/ossec/etc/shared/agent.conf` | configuración de grupo que escribe el motor |
| `paths.wazuh_client_keys` | `/var/ossec/etc/client.keys` | la clave del agente, que da nombre a la máquina en esa configuración; vacío en el manager |
| `wazuh_group` | vacío | grupo de Wazuh al que la máquina pide que el motor la añada; lo escribe `install.sh agent --group` |

`agent/agent.example.json` contiene cada clave con su valor por defecto.

| Flag | Función |
|---|---|
| `-config ruta` | lee otro fichero; debe existir |
| `-collect a,b` | ejecuta estos colectores en lugar de los configurados |
| `-full` | envía todo, incluso lo que no ha cambiado |

Colectores: `identity`, `groups`, `umask`, `sudoers`, `config`, `pam`, `authprobe`, `listening`, `services`, `wazuh`, `acl`, `audit`, `firewall`, `neighbours`, `virtualization`, `packages`, `units`, `backups`, `updates`, `transactions`, `snapshots`, `malware`, `timesync`, `keys`, `device` y `sweep`. Lo que lee cada uno está en [Hechos](facts.md).

Quitar un colector de la lista deja las evidencias que lo necesitan en NOT_EVALUABLE por COLLECTION. Nunca hace que pasen.

## Política ENS

Se define en Power ENS, en Configuración, y se guarda en el documento `active` de `wazuh-ens-configuration`.

Hasta que se guarda una configuración, el motor y el plugin usan la configuración por defecto del catálogo, [`catalog/default-configuration.json`](../../catalog/default-configuration.json): categoría MEDIO y alcance por grupo, con el grupo `ens`. Ningún parámetro de control está definido, así que las evidencias que necesitan uno son NOT_EVALUABLE por CONFIGURATION. El motor registra una línea `parameters` con `catalog default` en cada pasada que la usa.

| Ajuste | Efecto |
|---|---|
| Categoría del sistema | BÁSICO, MEDIO o ALTO (se guarda como `BAJO`, `MEDIO` o `ALTO`; el motor también lee `BÁSICO`); los requisitos fuera de ella son NOT_APPLICABLE |
| Alcance | los grupos de Wazuh auditados |
| Tipo de sistema de cada máquina | elige su plantilla de parámetros integrada |
| Control activado | un control desactivado es NOT_APPLICABLE en todas partes |
| Parámetros del control | listados en cada [página de control](controls/README.md) |
| Niveles por dimensión | C, I, T, A y D, BAJO, MEDIO o ALTO; un control se aplica al nivel más alto de sus dimensiones, y una dimensión sin nivel toma la categoría |
| Ajustes de nivel | juzgan un control, o un control en una máquina, a un nivel inferior a la categoría |

`levelAdjustments` baja el nivel al que se juzga un control:

```json
{ "controlId": "op.acc.1", "agentId": "001", "level": "BAJO", "reason": "entorno de pruebas, análisis de riesgos de 2026-11" }
```

`agentId` es opcional; un ajuste de máquina prevalece sobre el del control. `reason` es obligatorio. Se ignora un ajuste por encima de la categoría, sin motivo o con un nivel desconocido. Los requisitos y evidencias fuera del nivel ajustado son NOT_APPLICABLE y su motivo cita el ajuste.

Cada parámetro tiene una clase que decide de dónde sale su valor:

| Clase | Valor |
|---|---|
| `organisation` | el valor común del control; se ignoran los valores por máquina |
| `system` | el valor propio de la máquina o, si no, la plantilla asignada o, si no, sus perfiles o, si no, la plantilla de su tipo de sistema (ninguna si su tipo es `none`, «Sin plantilla») o, si no, el valor común |
| `platform` | como `system`; las plantillas integradas por tipo de sistema traen valores para él |

Plantillas: la asignada a la máquina, integrada (`catalog/templates/`) o propia; `none` la desactiva; sin ninguna asignada, la plantilla integrada del tipo de sistema de la máquina. El tipo de sistema es el definido a mano o, si no, el que implica la plataforma del inventario de Wazuh (`catalog/system-types.json`).

Las listas comparan sin distinguir mayúsculas. Un parámetro marcado como expresión regular usa RE2, compara el valor completo, distingue mayúsculas y tiene 512 caracteres como máximo. Las tablas son filas de celdas separadas por `|`.

Un parámetro sin definir da NOT_EVALUABLE por CONFIGURATION en las evidencias que lo necesitan. El motor nunca aplica un valor que nadie haya elegido, salvo los dos valores por defecto del producto que documenta op.acc.1 (el UID más bajo de una persona y los grupos privilegiados), y el veredicto indica cuándo lo hace.

## Parámetros desde un fichero

Los valores por tipo de máquina van en [perfiles](#perfiles). Después del primer guardado desde Power ENS, que crea la configuración con el catálogo completo, los parámetros también se pueden definir desde un fichero JSON con `config/set-parameters.py` del repositorio power-ens-wazuh. Comprueba cada valor con el catálogo, muestra el plan y solo escribe con `--apply`. Cada ejecución guarda la versión anterior en el historial, igual que un guardado desde el dashboard.

Ejecútalo desde la carpeta `config/` de un clon completo de power-ens-wazuh, en una máquina que llegue al indexer con su certificado de administrador. Necesita `python3`. En Docker, añade `ENS_OS_URL=https://127.0.0.1:9200` y los certificados de `config/wazuh_indexer_ssl_certs`.

```bash
export OS_CERT=/etc/wazuh-indexer/certs/admin.pem OS_KEY=/etc/wazuh-indexer/certs/admin-key.pem
python3 set-parameters.py /root/parameters.json
python3 set-parameters.py /root/parameters.json --apply
```

El fichero tiene una clave por control con sus valores de organización, `agents` con los valores por máquina según el identificador de agente de Wazuh, y `organization` con los elementos de Datos de la organización. Los valores siguen los tipos de arriba; un parámetro que admite una expresión regular recibe `{"value": "...", "matchMode": "regex"}`.

```json
{
  "op.acc.1": {"P-04": ["guest", "test"], "P-05": 2},
  "agents": {"001": {"op.acc.1": {"P-07": ["alice | web-01 | admin"]}}}
}
```

La primera ejecución debe mostrar el plan y ningún `ERROR`; cada error indica el control, el parámetro y el motivo. Escribe solo los parámetros que decidió la organización: un valor vacío o `null` borra el valor actual. El fichero contiene la política de la organización, así que mantenlo fuera de cualquier repositorio y bórralo al terminar.
