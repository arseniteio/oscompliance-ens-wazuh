# Instalación por paquetes

Esta guía instala OSCompliance ENS y Power ENS en un despliegue de Wazuh instalado por paquetes. Cubre un servidor todo en uno, con el manager, el indexer y el dashboard en un mismo host, y un despliegue distribuido, con un clúster de managers y nodos de indexer y de dashboard separados. Para Wazuh en Docker, consulta [Instalación con Docker](install-docker.md).

Calcula alrededor de una hora en los servidores y unos minutos por activo auditado. Todos los comandos se ejecutan como root.

`install.sh server` hace los pasos de esta guía que corresponden al nodo en el que se ejecuta, e `install.sh agent --group ens` hace el apartado 7 en cada activo auditado, como en los [primeros pasos](../../README.es.md#primeros-pasos). Esta guía es el procedimiento manual y la referencia de lo que hace el script.

## Nodos

Un despliegue tiene exactamente un motor, en el manager maestro. El motor llega a los indexers por la red y a la API de Wazuh en su propio host.

| Nodo | Pasos | Lo que instala `install.sh server` |
|---|---|---|
| Servidor todo en uno | 2, 3, 4, 6 y 8 | reglas, grupo `ens`, usuarios del motor, motor, plugin y auditoría del manager |
| Manager maestro | 2, 3, 6 y 8 | reglas, grupo `ens`, usuarios del motor, motor y auditoría del manager |
| Manager worker | parte de worker del 2 | nada: espera del maestro las reglas de su versión y reinicia `wazuh-manager` |
| Nodo de dashboard | 4 | plugin Power ENS |
| Nodo de indexer | ninguno | nada |
| Activo auditado | 7 | agente, con `install.sh agent` |

Un manager es el maestro cuando su clúster está desactivado en `ossec.conf` o su `node_type` es `master`. Un manager único es maestro. El apartado 5 se hace en el dashboard y es opcional.

Instala primero el maestro. Los workers toman de él las reglas a través del clúster de Wazuh, y Power ENS necesita su motor para mostrar resultados. Después instala los workers y los nodos de dashboard en cualquier orden, y los activos auditados al final. El mismo comando `install.sh server` se ejecuta en cada nodo servidor.

`install.sh server --only <componentes>` sustituye la detección por una lista separada por comas de `rules`, `audit`, `engine`, `plugin` y `worker`.

## Requisitos

- Wazuh 4.14.7, 4.14.8 o 4.14.9, instalado por paquetes.
- Activos auditados en Linux, amd64 o arm64, con un agente de Wazuh registrado en el manager.
- `curl` y `jq` en el manager maestro, `unzip` en los nodos de dashboard, `cron` y `auditd` en los activos auditados.
- `curl` y `python3` en el host que tiene el certificado de administración del indexer, para dar acceso a Power ENS.
- En un despliegue distribuido, Filebeat en el manager maestro enviando las alertas a los indexers, y el maestro llegando a ellos por el puerto 9200.
- Que el registro de autenticación de cada activo auditado llegue a Wazuh: `/var/log/auth.log`, `/var/log/secure` o journald, como localfile del agente de Wazuh.

auditd alimenta EV-06 de op.acc.2, op.acc.3 y EV-04 y EV-07 de op.acc.4. Sin él, esas evidencias no son evaluables. Sin el registro de autenticación, las evidencias de inicio de sesión no son evaluables.

### Hardware

Las cifras se midieron en el laboratorio sobre arm64 con los 34 controles del catálogo. Se suman a lo que necesita Wazuh.

| Componente | Dónde | CPU | Memoria | Disco |
|---|---|---|---|---|
| Agente | cada activo auditado | menos de 1 segundo por pasada horaria | 15 MB durante la pasada, nada entre pasadas | 10 MB del binario, más `facts.ndjson`, unos 200 KB al día |
| Motor | manager master | 1 núcleo durante la pasada | 50 MB más 250 MB por cada 1.000 activos auditados | nada en el manager |
| Veredictos | clúster de indexers | | | unos 2,5 MB por activo auditado y día en `oscompliance-verdicts`, sin réplicas |

Una pasada sobre 5.000 activos tardó 270 segundos con un pico de 1,2 GB de memoria. La pasada debe acabar dentro de `-interval`, 15 minutos por defecto, lo que sitúa el límite de un motor en unas 15.000 activos. El barrido diario de ficheros del agente se detiene tras `sweep_timeout`, 15 minutos por defecto.

## Antes de empezar

Decide con la organización qué activos se auditan, su categoría ENS (BAJO, MEDIO o ALTO) y quién cambia la configuración además de los usuarios con `all_access`. Una categoría equivocada da veredictos equivocados sin ningún error. Los parámetros de los controles se pueden declarar más tarde.

En el manager maestro, comprueba la versión y adónde envía Filebeat las alertas. El motor usa los mismos indexers y el mismo certificado de CA.

```bash
/var/ossec/bin/wazuh-control info | grep WAZUH_VERSION
grep -A4 'hosts' /etc/filebeat/filebeat.yml
ls /etc/filebeat/certs/root-ca.pem
```

En cada nodo de dashboard, comprueba la versión del dashboard. Debe ser 2.19.5 en Wazuh 4.14.7 y 2.19.6 en 4.14.8 y 4.14.9.

```bash
grep -m1 '"version"' /usr/share/wazuh-dashboard/package.json
```

En cada activo que se va a auditar, los servicios deben estar `active` y el último comando debe mostrar al menos una línea, lo que significa que el registro de autenticación llega a Wazuh. En RHEL y Rocky el servicio de cron es `crond`. `uname -m` indica el paquete: `x86_64` es amd64 y `aarch64` es arm64.

```bash
systemctl is-active wazuh-agent auditd cron
uname -m
grep -E 'auth.log|/var/log/secure|journald' /var/ossec/etc/ossec.conf /var/ossec/etc/shared/agent.conf
```

El script del apartado 3 pide contraseñas. Para ejecutarlo sin preguntas, por ejemplo desde una automatización o un agente de IA, expórtalas antes en ese shell y bórralas al terminar.

| Variable | Valor |
|---|---|
| `API_ADMIN_PASSWORD` | contraseña de `wazuh-wui`, en `wazuh-passwords.txt` dentro de `wazuh-install-files.tar` |
| `INDEXER_ADMIN_PASSWORD` | contraseña del usuario `admin` del indexer, en el mismo fichero; solo se pide cuando el maestro no tiene el certificado de administración del indexer |
| `OSC_INDEXER_PASSWORD` | contraseña nueva del usuario del motor en el indexer |
| `OSC_WAZUH_API_PASSWORD` | contraseña nueva del usuario del motor en la API de Wazuh |

`install.sh` también lee estas variables.

| Variable | Por defecto | Función |
|---|---|---|
| `OSC_INDEXER_URLS` | `output.elasticsearch.hosts` en `/etc/filebeat/filebeat.yml` | URL de los indexers para el motor, separadas por comas; un host sin esquema recibe `https://` |
| `OSC_INDEXER_CA` | `/etc/filebeat/certs/root-ca.pem` o, si no, `/etc/wazuh-indexer/certs/root-ca.pem` | certificado de CA de los indexers |
| `OSC_WAIT_SECONDS` | `900` | cuánto espera un worker las reglas, y un agente sin `--group` la configuración de grupo |

En una nueva ejecución sin `OSC_INDEXER_URLS`, el script mantiene los valores de `/etc/oscompliance/engine.conf`.

## 1. Obtener los paquetes

Descarga el paquete de tu arquitectura y sus sumas de comprobación en cada nodo servidor donde instales algo y en cada activo auditado. `uname -m` indica la arquitectura: `x86_64` es amd64 y `aarch64` es arm64. La línea de tu paquete debe terminar en `OK`. Los comandos siguientes se ejecutan desde la carpeta del paquete.

```bash
v=2.1.0
url=https://github.com/arseniteio/oscompliance-ens-wazuh/releases/download/v$v
curl -fLO "$url/oscompliance-ens-$v-linux-amd64.tar.gz" -O "$url/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar xzf "oscompliance-ens-wazuh-$v-linux-amd64.tar.gz" && cd "oscompliance-ens-wazuh-$v-linux-amd64"
```

Cada paquete contiene los binarios en `bin/`, los ficheros de Wazuh en `wazuh/`, el fichero de cron y la configuración de ejemplo del agente en `agent/`, `install.sh` y las licencias.

En cada nodo de dashboard, descarga en la misma carpeta el plugin para tu dashboard: `osd-2.19.5` para Wazuh 4.14.7, `osd-2.19.6` para 4.14.8 y 4.14.9. `create-admin-role.sh` se ejecuta en el host que tiene el certificado de administración del indexer.

```bash
url=https://github.com/arseniteio/power-ens-wazuh/releases/download/v$v
curl -fL -o plugin.sha256 "$url/SHA256SUMS"
curl -fLO "$url/power-ens-$v-osd-2.19.6.zip" -O "$url/deploy-plugin.sh" -O "$url/create-admin-role.sh"
sha256sum -c --ignore-missing plugin.sha256
```

Para compilar los paquetes y el plugin, consulta [Compilar desde el código](#compilar-desde-el-código).

## 2. Instalar las reglas y crear el grupo

Ejecuta esto en el manager maestro o en el servidor todo en uno.

Las reglas usan los identificadores 119000 a 119006. Indexan hechos, la sonda de autenticación, eventos de servicio y accesos auditados, y no generan nada por encima del nivel 3. Ninguna otra regla puede usar esos identificadores: el primer comando no debe mostrar nada, o solo `oscompliance_facts_rules.xml` en una reinstalación. `wazuh-analysisd -t` no debe mostrar errores.

```bash
grep -rlE 'id="11900[0-6]"' /var/ossec/etc/rules/
install -o wazuh -g wazuh -m 660 wazuh/oscompliance_facts_rules.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

Espera un minuto a que arranque el manager. Después crea el grupo `ens`.

```bash
/var/ossec/bin/agent_groups -a -g ens -q
```

El motor también crea cada grupo del alcance ENS que no existe, y añade los activos que piden el grupo, como en el apartado 7. Para añadir un activo a mano, sustituye `<id>` por el identificador del agente que aparece en la lista. Cada activo conserva sus otros grupos.

```bash
/var/ossec/bin/agent_control -l
/var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

En cada manager worker, no instales las reglas a mano. El maestro las sincroniza a través del clúster de Wazuh. Espera a que el fichero del worker coincida con el del paquete, lo que `cmp` confirma sin mostrar nada, y reinicia el manager para que cargue las reglas.

```bash
cmp /var/ossec/etc/rules/oscompliance_facts_rules.xml wazuh/oscompliance_facts_rules.xml
systemctl restart wazuh-manager
```

## 3. Crear los usuarios del motor

Ejecuta esto en el manager maestro o en el servidor todo en uno.

El motor tiene su propio usuario en el indexer y en la API de Wazuh, con los permisos que indica [Seguridad](security.md#motor). Este script los crea y escribe las credenciales en `/etc/oscompliance/engine.env`.

Pide la contraseña de `wazuh-wui`, que está en `wazuh-passwords.txt` dentro de `wazuh-install-files.tar`, y dos contraseñas nuevas. Cada contraseña nueva necesita entre 8 y 64 caracteres con mayúscula, minúscula, número y símbolo, y no puede contener `$`, `&`, comillas, barras invertidas ni espacios. Para ejecutarlo sin preguntas, exporta las variables de [Antes de empezar](#antes-de-empezar).

El script se autentica en el indexer con el certificado de administración cuando existen `/etc/wazuh-indexer/certs/admin.pem` y `admin-key.pem`, como en un servidor todo en uno. Si no, pide la contraseña del usuario `admin` del indexer, así que no se copia ningún certificado entre hosts. `INDEXER_ADMIN` indica otro usuario.

Llega al indexer en `INDEXER_URL`, `https://127.0.0.1:9200` por defecto, y lo comprueba con `INDEXER_CA`, `/etc/wazuh-indexer/certs/root-ca.pem` por defecto. En un despliegue distribuido, indica uno de los hosts de Filebeat y la CA de Filebeat.

```bash
export INDEXER_URL=https://10.0.0.1:9200 INDEXER_CA=/etc/filebeat/certs/root-ca.pem
bash wazuh/engine-users.sh create
```

Cada ejecución vuelve a definir las contraseñas. Para mantener las contraseñas de `engine.env` y actualizar solo los roles y los permisos, como hace `install.sh server` en una nueva ejecución, indica `KEEP_PASSWORDS=1`. El script sigue pidiendo la contraseña de `wazuh-wui`.

```bash
KEEP_PASSWORDS=1 bash wazuh/engine-users.sh create
```

## 4. Instalar el plugin

Ejecuta esto en cada nodo de dashboard o en el servidor todo en uno.

El script valida el zip, guarda una copia de la versión anterior en `/var/backups/power-ens`, instala el plugin y reinicia el dashboard. Debe terminar con el dashboard activo.

```bash
bash deploy-plugin.sh "power-ens-wazuh-$v-osd-2.19.6.zip"
```

Entra en el dashboard y abre Power ENS. Si indica `No se puede leer el inventario de agentes`, el dashboard aún no ha escrito su inventario de agentes, lo que hace cada 15 minutos: espera y pulsa Reintentar.

Un usuario con `all_access` puede cambiar la configuración. Para dar permiso a otro usuario, asígnale el rol `power_ens_admin`. El script añade el usuario y mantiene a los que ya tienen el rol. Ejecútalo en el host que tiene el certificado de administración del indexer: el servidor todo en uno o el nodo de indexer donde se generó el certificado. Cuando el indexer no escucha en `127.0.0.1:9200` de ese host, indica `OS_URL`.

```bash
bash create-admin-role.sh --map <usuario>
```

## 5. Definir la configuración ENS

Este paso es opcional para obtener los primeros veredictos. Hasta que se guarda una configuración en Power ENS, el motor y el plugin usan la configuración por defecto del catálogo, `catalog/default-configuration.json`: nivel MEDIO y el grupo `ens` en alcance. Guarda una configuración para cambiar el nivel o el alcance, y para declarar los parámetros de los controles.

En Power ENS, abre Configuración.

1. En General, rellena Cliente, cambia Nivel ENS si tu sistema tiene otro nivel y pulsa Guardar configuración global. Esto crea la configuración.
2. En Organización, abre cada control, pulsa Completar configuración, rellena lo que falta y guarda.
3. En Grupos y activos, da a cada grupo los valores de sus activos y abre un activo para fijar los parámetros que solo le corresponden a él.

Cada página de [Controles](controls/README.md) lista los parámetros de su control. Un control se puede rellenar más tarde: hasta entonces aparece como no evaluable por configuración.

El primer guardado solo se hace desde el dashboard, porque escribe el catálogo completo de controles. Después, los parámetros también se pueden definir desde un fichero JSON: consulta [Configuración](configuration.md#parámetros-desde-un-fichero).

## 6. Arrancar el motor

Ejecuta esto en el manager maestro o en el servidor todo en uno. No arranques nunca un segundo motor en un worker.

La unidad de systemd lee las URL de los indexers y el certificado de CA de `/etc/oscompliance/engine.conf`. Sin ese fichero usa `https://127.0.0.1:9200` y `/etc/wazuh-indexer/certs/root-ca.pem`, que sirven para un servidor todo en uno. En un despliegue distribuido, escribe el fichero con los hosts de `output.elasticsearch.hosts` de `/etc/filebeat/filebeat.yml`, cada uno con su esquema, y la CA de Filebeat. Cuando un indexer no responde, el motor prueba la siguiente URL.

```bash
install -d -m 755 /etc/oscompliance
cat > /etc/oscompliance/engine.conf <<'EOF'
OSC_INDEXER_URLS=https://10.0.0.1:9200,https://10.0.0.2:9200
OSC_INDEXER_CA=/etc/filebeat/certs/root-ca.pem
EOF
```

Instala y arranca el motor.

```bash
install -m 755 bin/oscompliance-engine bin/oscompliance-policy /usr/local/bin/
install -m 644 wazuh/oscompliance-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now oscompliance-engine
```

Espera 20 segundos. Hasta que se guarda una configuración, el registro muestra una línea `parameters` con `catalog default`. También debe mostrar una línea `group configuration` con `applied` true y una línea `pass` sin `error`.

```bash
journalctl -u oscompliance-engine -n 10 --no-pager
```

La configuración de grupo debe contener ahora un bloque entre `oscompliance begin` y `oscompliance end`, con el localfile de `facts.ndjson`. En un clúster, el maestro la sincroniza con los workers.

```bash
cat /var/ossec/etc/shared/ens/agent.conf
```

El motor solo escribe ese bloque. Deja intacto el resto del fichero.

## 7. Instalar el agente en los activos auditados

En cada activo que se va a auditar, instala el agente y su fichero de cron. Lee `/etc/shadow`, `sshd -T` y los ficheros sudoers, así que se ejecuta como root. No necesita más configuración en un sistema estándar.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
touch /var/log/oscompliance/facts.ndjson
```

Después el activo entra en el grupo `ens` de una de estas dos formas.

### Pedir al motor que añada el activo

Es lo que hace `install.sh agent --group ens`. No hace falta ningún comando por activo en el manager.

Escribe el grupo en la configuración del agente. Si `/etc/oscompliance/agent.json` ya existe, añádele la clave `wazuh_group`.

```bash
install -d -m 755 /etc/oscompliance
echo '{"wazuh_group": "ens"}' > /etc/oscompliance/agent.json
```

Añade este bloque al final de `/var/ossec/etc/ossec.conf`, para que el agente de Wazuh lea el fichero de hechos antes de que llegue la configuración de grupo. Mantén las marcas: la desinstalación encuentra el bloque por ellas.

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

Reinicia el agente de Wazuh antes de la primera pasada. Si no, Wazuh abre el fichero más tarde y omite lo que ya contiene.

```bash
systemctl restart wazuh-agent
sleep 30
oscompliance-agent -full
```

Cada hecho `agent_pass` lleva el grupo en `requested_group`. En su siguiente sincronización de grupos, en menos de 15 minutos, el motor añade el agente al grupo, y la configuración de grupo llega después. El motor solo añade un agente a un grupo del alcance ENS, nunca a otro grupo, y solo a partir de hechos `agent_pass` dentro de su ventana.

Cuando llega la configuración de grupo, el fichero de hechos queda declarado dos veces. Wazuh registra el aviso 1958, que indica que el fichero de registro está duplicado, y lee el fichero una sola vez. El aviso no requiere ninguna acción.

### Añadir el activo a mano

Añade el activo al grupo en el manager maestro, como en el apartado 2. Después espera a que reciba la configuración de grupo: este comando debe devolver un número mayor que 0.

```bash
grep -c facts.ndjson /var/ossec/etc/shared/agent.conf
```

Reinicia el agente de Wazuh antes de la primera pasada. Si no, Wazuh abre el fichero más tarde y omite lo que ya contiene.

```bash
systemctl restart wazuh-agent
sleep 30
oscompliance-agent -full
```

### Comprobar el agente

La última línea del fichero de hechos debe ser JSON con `"oscompliance":"1"`.

```bash
tail -n 1 /var/log/oscompliance/facts.ndjson
```

El agente añade sus vigilancias de auditoría en tiempo de ejecución con `auditctl`, etiquetadas `oscompliance_*`. Retira las vigilancias `oscompliance_*` que la configuración de grupo ya no pide y nunca escribe en `/etc/audit`. Con SELinux en enforcing, ejecuta también `restorecon -R /usr/local/bin/oscompliance-agent /etc/cron.d/oscompliance /var/log/oscompliance`.

En RHEL y Rocky, `cron` es el paquete `cronie`.

```bash
dnf install -y cronie && systemctl enable --now crond
```

## 8. Auditar el manager

Ejecuta esto en el manager maestro o en el servidor todo en uno. Los managers worker no se auditan.

El manager se juzga como cualquier otro activo. Hasta que el agente se ejecute en él, su fila aparece como no conforme. No pertenece a ningún grupo, así que necesita dos ajustes propios.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
install -d -m 755 /etc/oscompliance
echo '{"paths": {"wazuh_shared_conf": "/var/ossec/etc/shared/ens/agent.conf", "wazuh_client_keys": ""}}' > /etc/oscompliance/agent.json
touch /var/log/oscompliance/facts.ndjson
```

Añade el fichero de hechos y el registro de auditoría a `/var/ossec/etc/ossec.conf`, dentro de `<ossec_config>`.

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

Reinicia el manager y ejecuta la primera pasada.

```bash
systemctl restart wazuh-manager
sleep 60
oscompliance-agent -full
```

## 9. Comprobar el resultado

Inicia sesión por SSH en un activo auditado, para que un inicio de sesión real llegue a Wazuh, y espera un minuto. Después ejecuta una pasada del motor en el manager maestro. La última línea `pass` debe mostrar `verdicts` mayor que 0 y ningún `error`.

```bash
systemctl restart oscompliance-engine
sleep 20
journalctl -u oscompliance-engine -n 5 --no-pager
```

Los activos que pidieron el grupo deben estar en él tras la siguiente sincronización de grupos. Lístalos en el manager maestro.

```bash
/var/ossec/bin/agent_groups -l -g ens
```

En el dashboard, abre Discover sobre `wazuh-alerts-*`. `rule.id:119001` debe mostrar los hechos de cada activo, y `rule.id:119002` una sonda de autenticación por activo y pasada.

En Power ENS, abre Detalle del control y elige un activo. Cada evidencia muestra su estado y el motivo. El resultado habitual en un activo nuevo es parcial: una evidencia queda no evaluable hasta que se declaran sus parámetros, y un requisito que depende de un documento queda abierto hasta que se declara su atestación en P-ATT.

El primer resultado completo necesita una pasada del agente y una pasada del motor después. Sin `-full` tarda hasta 75 minutos.

Si un paso da otro resultado, consulta [Operación](operations.md#resolución-de-problemas).

## Actualizar

Actualiza primero el maestro: su motor lee hechos de agentes más antiguos. Después actualiza los workers, los nodos de dashboard y los activos auditados.

Con el script de instalación, ejecuta `install.sh server` de la versión nueva en el maestro, después en cada worker y nodo de dashboard, e `install.sh agent` con los mismos argumentos que antes en cada activo auditado. En el maestro, el script mantiene las contraseñas de los usuarios del motor y actualiza sus permisos. Sigue pidiendo la contraseña de `wazuh-wui`, y la contraseña de `admin` del indexer cuando no hay certificado de administración. Un worker espera hasta `OSC_WAIT_SECONDS` a que su fichero de reglas coincida con el de la versión nueva y después reinicia su manager. Si las reglas no llegan a tiempo, el script se detiene con un error: actualiza el maestro y ejecútalo de nuevo.

A mano, en el maestro, guarda el binario actual, para poder volver a él poniéndolo de nuevo y reiniciando el servicio.

```bash
cp /usr/local/bin/oscompliance-engine /usr/local/bin/oscompliance-engine.prev
install -m 755 bin/oscompliance-engine bin/oscompliance-policy /usr/local/bin/
systemctl restart oscompliance-engine
```

Si ha cambiado el rol, ejecuta `KEEP_PASSWORDS=1 bash wazuh/engine-users.sh create` como en el apartado 3. La versión 1.2.0 añade dos acciones de la API de Wazuh, así que una actualización desde 1.1.0 lo necesita. Si han cambiado las reglas, instálalas en el maestro como en el apartado 2 y reinicia cada worker cuando lleguen, como en la parte de worker del apartado 2. En cada activo auditado, instala el nuevo binario del agente: lo usa la siguiente ejecución de cron. En cada nodo de dashboard, instala el zip del plugin de la misma versión como en el apartado 4.

De la 1.2.0 a la 2.0.0, la primera pasada del nuevo agente descarga las vigilancias de lectura de la 1.2.0 en cada activo Linux de un grupo con el bloque del motor. En un activo fuera de esos grupos, ejecuta una vez `auditctl -D -k oscompliance_read` y `auditctl -D -k oscompliance_exec`. Las versiones se publican ahora en `arseniteio/oscompliance-ens-wazuh` y `arseniteio/power-ens-wazuh`: descarga `install.sh` y los paquetes de ahí.

## Desinstalar

Con el script de instalación, ejecuta `install.sh uninstall` en cada nodo y en cada activo auditado. En cada uno retira lo que encuentra: el motor y sus usuarios, el plugin, las partes del manager en un manager, y el agente con su bloque en `ossec.conf`. Las reglas y el bloque de la configuración de grupo solo se retiran en el maestro, y los workers lo siguen a través del clúster. Los pasos manuales son estos.

En cada activo auditado, retira el agente.

```bash
rm -f /etc/cron.d/oscompliance /usr/local/bin/oscompliance-agent
rm -rf /etc/oscompliance /var/log/oscompliance /var/lib/oscompliance
augenrules --load
```

Si el activo pidió el grupo, retira también el bloque de `ossec.conf` y reinicia el agente de Wazuh.

```bash
sed -i '/<!-- oscompliance begin -->/,/<!-- oscompliance end -->/d' /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
```

En cada nodo de dashboard, retira el plugin.

```bash
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove powerEns
systemctl restart wazuh-dashboard
```

En el manager maestro, retira el motor, las reglas y el bloque de la configuración de grupo, y reinicia el manager.

```bash
systemctl disable --now oscompliance-engine
rm -f /etc/systemd/system/oscompliance-engine.service /usr/local/bin/oscompliance-engine /usr/local/bin/oscompliance-policy
systemctl daemon-reload
rm -f /var/ossec/etc/rules/oscompliance_facts_rules.xml
sed -i '/<!-- oscompliance begin/,/<!-- oscompliance end -->/d' /var/ossec/etc/shared/ens/agent.conf
systemctl restart wazuh-manager
```

Retira los usuarios del motor. El script pide la contraseña de `wazuh-wui`, y la contraseña de `admin` del indexer cuando no hay certificado de administración. En un despliegue distribuido, indica `INDEXER_URL` e `INDEXER_CA` como en el apartado 3.

```bash
bash wazuh/engine-users.sh remove
```

En cada manager worker, reinicia el manager cuando haya desaparecido el fichero de reglas.

Los índices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history`, `oscompliance-host-profile` y `wazuh-ens-configuration` se quedan en el indexer, así que no se pierde el historial. Bórralos desde Dev Tools cuando ya no los necesites. Si auditaste el manager, retira también el agente del maestro como en un activo auditado, y retira sus dos bloques localfile de `ossec.conf`.

## Compilar desde el código

Compila los paquetes en este repositorio con Go 1.27.2 o posterior. El resultado está en `dist/`, con `install.sh` y `SHA256SUMS`.

```bash
make dist VERSION=2.1.0
```

Compila el plugin en el repositorio power-ens-wazuh con Docker, para la versión de OpenSearch Dashboards de tu dashboard. La primera compilación tarda unos 20 minutos. El resultado es `dist/powerEns-2.19.6.zip`.

```bash
ci/build-zip.sh 2.19.6
```
