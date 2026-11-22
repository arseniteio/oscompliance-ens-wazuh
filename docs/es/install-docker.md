# Instalación con Docker

Esta guía instala OSCompliance ENS y Power ENS en un despliegue de Wazuh basado en el fichero de compose single-node oficial de wazuh-docker. Para Wazuh instalado por paquetes, consulta [Instalación por paquetes](install.md).

Calcula alrededor de una hora en el host de Docker y unos minutos por máquina auditada. Todos los comandos se ejecutan como root en el host de Docker, salvo en el apartado 7.

## Requisitos

- Wazuh 4.14.7, 4.14.8 o 4.14.9, con los puertos 9200 y 55000 publicados en el host.
- Los nombres de servicio, volúmenes y carpeta de certificados del fichero de compose oficial: `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`, el volumen `wazuh_api_configuration` y `config/wazuh_indexer_ssl_certs`. Si los tuyos son otros, adapta `wazuh/docker-compose.override.yml` y las variables del apartado 1.
- Máquinas auditadas en Linux, amd64 o arm64, con un agente de Wazuh registrado en el manager.
- `curl`, `jq` y `python3` en el host, `cron` y `auditd` en las máquinas auditadas.
- Que el registro de autenticación de cada máquina auditada llegue a Wazuh: `/var/log/auth.log`, `/var/log/secure` o journald, como localfile del agente de Wazuh.

auditd alimenta EV-06 de op.acc.2, op.acc.3 y EV-04 y EV-07 de op.acc.4. Sin él, esas evidencias no son evaluables. Sin el registro de autenticación, las evidencias de inicio de sesión no son evaluables.

Antes de empezar, decide con la organización, comprueba las máquinas que se van a auditar y prepara las contraseñas como en [Antes de empezar](install.md#antes-de-empezar) de la guía por paquetes. En Docker, `API_ADMIN_PASSWORD` es `API_PASSWORD` en tu fichero de compose.

## 1. Definir las variables

Defínelas en un shell y mantenlo abierto hasta el apartado 6. `WAZUH_DIR` es la carpeta de tu `docker-compose.yml`. `PROJECT` es el nombre del proyecto de compose, que muestra `docker compose ls`.

```bash
export WAZUH_DIR=/srv/wazuh-docker/single-node
export PROJECT=single-node
export WAZUH_VERSION=4.14.8
export MGR=$PROJECT-wazuh.manager-1
export CERTS=$WAZUH_DIR/config/wazuh_indexer_ssl_certs
```

Tu fichero de compose no se modifica. La instalación añade `docker-compose.override.yml` a su lado, que compose lee por sí solo. Si ese fichero ya existe, este comando lo muestra: añade a mano el contenido del apartado 5 en lugar de copiarlo.

```bash
cat "$WAZUH_DIR/docker-compose.override.yml" 2>/dev/null
```

Comprueba la versión del dashboard. Debe ser 2.19.5 en Wazuh 4.14.7 y 2.19.6 en 4.14.8 y 4.14.9. Descarga el plugin para esa versión en el apartado 2.

```bash
docker exec "$PROJECT-wazuh.dashboard-1" grep -m1 '"version"' /usr/share/wazuh-dashboard/package.json
```

## 2. Obtener los paquetes

Descarga el paquete de tu arquitectura y sus sumas de comprobación en el host y en cada máquina auditada, y los ficheros del plugin en el host, como en el [apartado 1 de la guía por paquetes](install.md#1-obtener-los-paquetes). En Docker el plugin necesita `dashboard.Dockerfile` en lugar de `deploy-plugin.sh`.

```bash
v=2.1.0
url=https://github.com/arseniteio/power-ens-wazuh/releases/download/v$v
curl -fLO "$url/dashboard.Dockerfile"
```

Para compilar los paquetes y el plugin, consulta [Compilar desde el código](install.md#compilar-desde-el-código).

## 3. Instalar las reglas y crear el grupo

Las reglas usan los identificadores 119000 a 119006. Ninguna otra regla puede usarlos: el primer comando no debe mostrar nada, o solo `oscompliance_facts_rules.xml` en una reinstalación. `wazuh-analysisd -t` no debe mostrar errores.

```bash
docker exec "$MGR" grep -rlE 'id="11900[0-6]"' /var/ossec/etc/rules/
docker cp wazuh/oscompliance_facts_rules.xml "$MGR:/var/ossec/etc/rules/"
docker exec "$MGR" chown wazuh:wazuh /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" chmod 660 /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" /var/ossec/bin/wazuh-analysisd -t
docker exec "$MGR" /var/ossec/bin/wazuh-control restart
```

Espera un minuto a que arranque el manager. Después crea el grupo `ens` y añade cada máquina que quieras auditar, sustituyendo `<id>` por el identificador del agente que aparece en la lista. Cada máquina conserva sus otros grupos.

```bash
docker exec "$MGR" /var/ossec/bin/agent_groups -a -g ens -q
docker exec "$MGR" /var/ossec/bin/agent_control -l
docker exec "$MGR" /var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

## 4. Crear los usuarios del motor

El motor tiene su propio usuario en el indexer y en la API de Wazuh, con los permisos que indica [Seguridad](security.md#motor). Este script los crea y escribe las credenciales en `/etc/oscompliance/engine.env` en el host. Las dos variables hacen que llegue al indexer con el nombre de su certificado.

Pide la contraseña de `wazuh-wui`, que es `API_PASSWORD` en tu fichero de compose, y dos contraseñas nuevas. Cada contraseña nueva necesita entre 8 y 64 caracteres con mayúscula, minúscula, número y símbolo, y no puede contener `$`, `&`, comillas, barras invertidas ni espacios. Para ejecutarlo sin preguntas, exporta las variables de [Antes de empezar](install.md#antes-de-empezar).

```bash
export INDEXER_URL=https://wazuh.indexer:9200
export INDEXER_RESOLVE=wazuh.indexer:9200:127.0.0.1
bash wazuh/engine-users.sh create
```

## 5. Instalar el plugin

El plugin va en una imagen propia, porque lo que se instala en un contenedor en marcha se pierde al recrearlo. Desde la carpeta que contiene el zip y el Dockerfile:

```bash
docker build -f dashboard.Dockerfile --build-arg WAZUH_VERSION="$WAZUH_VERSION" \
  --build-arg PLUGIN_ZIP="power-ens-wazuh-$v-osd-2.19.6.zip" -t power-ens/wazuh-dashboard:local .
```

Desde la carpeta del paquete, instala el binario del motor y el fichero override, y recrea el dashboard. El fichero override indica la imagen del dashboard y define el servicio del motor, que arranca en el apartado 6.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
cp wazuh/docker-compose.override.yml "$WAZUH_DIR/"
(cd "$WAZUH_DIR" && docker compose -p "$PROJECT" up -d wazuh.dashboard)
```

Entra en el dashboard y abre Power ENS. Si indica `No se puede leer el inventario de agentes`, el dashboard aún no ha escrito su inventario de agentes, lo que hace cada 15 minutos: espera y pulsa Reintentar.

Un usuario con `all_access` puede cambiar la configuración. Para dar permiso a otro usuario, asígnale el rol `power_ens_admin`. El script añade el usuario y mantiene a los que ya tienen el rol.

```bash
export OS_CERT=$CERTS/admin.pem OS_KEY=$CERTS/admin-key.pem OS_CA=$CERTS/root-ca.pem
export OS_URL=$INDEXER_URL OS_RESOLVE=$INDEXER_RESOLVE
bash create-admin-role.sh --map <usuario>
```

Hasta que se guarda una configuración, el motor usa la configuración por defecto del catálogo: nivel MEDIO y el grupo `ens` en alcance. Para cambiarla, define la configuración ENS como en el [apartado 5 de la guía por paquetes](install.md#5-definir-la-configuración-ens).

## 6. Arrancar el motor

```bash
(cd "$WAZUH_DIR" && docker compose -p "$PROJECT" up -d oscompliance.engine)
```

Espera 20 segundos. El registro debe mostrar una línea `group configuration` con `applied` true y una línea `pass` sin `error`.

```bash
docker logs --tail 10 "$PROJECT-oscompliance.engine-1"
```

La configuración de grupo debe contener ahora un bloque entre `oscompliance begin` y `oscompliance end`, con el localfile de `facts.ndjson`.

```bash
docker exec "$MGR" cat /var/ossec/etc/shared/ens/agent.conf
```

## 7. Instalar el agente en las máquinas auditadas

En cada máquina que se audita, ejecuta `install.sh agent --group ens` desde el paquete, o sigue el [apartado 7 de la guía por paquetes](install.md#7-instalar-el-agente-en-las-máquinas-auditadas).

Esta guía no audita el contenedor del manager, así que su fila aparece como no conforme. Para ver cada resultado, elige la máquina en el selector Máquina.

## 8. Comprobar el resultado

Inicia sesión por SSH en una máquina auditada, para que un inicio de sesión real llegue a Wazuh, y espera un minuto. Después ejecuta una pasada del motor. La última línea `pass` debe mostrar `verdicts` mayor que 0 y ningún `error`.

```bash
docker restart "$PROJECT-oscompliance.engine-1"
sleep 20
docker logs --tail 5 "$PROJECT-oscompliance.engine-1"
```

Después comprueba el dashboard como en el [apartado 9 de la guía por paquetes](install.md#9-comprobar-el-resultado).

## Actualizar

Actualiza primero el motor: lee hechos de agentes anteriores. Instala el binario nuevo y reinicia el servicio. Si cambiaron las reglas, instálalas como en el apartado 3. Si cambió el rol, ejecuta `KEEP_PASSWORDS=1 bash wazuh/engine-users.sh create` con las variables de los apartados 1 y 4; una actualización desde 1.1.0 lo necesita. En cada máquina auditada, instala el binario nuevo del agente.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
docker restart "$PROJECT-oscompliance.engine-1"
```

Para actualizar el plugin, guarda la imagen actual con otra etiqueta, construye la nueva con la misma etiqueta y recrea el dashboard. Para volver atrás, etiqueta `previous` de nuevo como `local` y recréalo.

```bash
docker tag power-ens/wazuh-dashboard:local power-ens/wazuh-dashboard:previous
docker build -f dashboard.Dockerfile --build-arg WAZUH_VERSION="$WAZUH_VERSION" \
  --build-arg PLUGIN_ZIP="power-ens-wazuh-$v-osd-2.19.6.zip" -t power-ens/wazuh-dashboard:local .
(cd "$WAZUH_DIR" && docker compose -p "$PROJECT" up -d wazuh.dashboard)
```

La imagen del dashboard se construye sobre una versión de Wazuh, así que no sigue una actualización de Wazuh. Sigue el procedimiento oficial de Wazuh y, antes de recrear los servicios, compila el plugin y la imagen para la nueva versión como arriba. El plugin debe coincidir con el dashboard: 2.19.5 para Wazuh 4.14.7, 2.19.6 para 4.14.8 y 4.14.9.

## Desinstalar

En cada máquina auditada, sigue el primer paso de [la guía por paquetes](install.md#desinstalar).

En el host, para el motor, borra el fichero override y recrea el dashboard con la imagen oficial. Después retira las reglas y el bloque de la configuración de grupo, y reinicia el manager.

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

Retira los usuarios del motor, con las mismas variables del apartado 4. El script pide la contraseña de `wazuh-wui`.

```bash
bash wazuh/engine-users.sh remove
```

Los índices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history`, `oscompliance-host-profile` y `wazuh-ens-configuration` se quedan en el indexer, así que no se pierde el historial. Bórralos desde Dev Tools cuando ya no los necesites.
