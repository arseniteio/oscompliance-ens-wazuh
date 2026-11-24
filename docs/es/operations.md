# Operación

## Qué se ejecuta y cuándo

Cada activo auditado ejecuta una pasada del agente cada hora en el minuto 17, el barrido del sistema de ficheros cada día a las 03:23, limitado por `sweep_timeout` (15 minutos), y el control de volumen de lecturas cada 2 minutos. El motor ejecuta una pasada cada 15 minutos. Sincroniza la configuración de grupo como máximo cada 15 minutos, y solo cuando algo ha cambiado.

## Registros del motor

El motor registra en JSON en el journal:

```bash
journalctl -u oscompliance-engine -f
```

| Mensaje | Campos | Significado |
|---|---|---|
| `pass` | `verdicts`, `seconds`, `requests` | una pasada terminada |
| `pass` con `error` | los mismos, más `error` | la pasada ha fallado; los veredictos ya escritos se quedan |
| `parameters` | `error` | no se ha podido leer la configuración ENS; la pasada sigue con lo leído |
| `inventory platforms` | `error` | no se han podido derivar los tipos de sistema del inventario |
| `group configuration` | `group`, `agents`, `applied` | se ha sincronizado la región de un grupo (`applied: false` sin `-sync-apply`) |
| `group configuration` | `error` | la sincronización ha fallado; la siguiente pasada lo intenta de nuevo |

`requests` debería crecer linealmente con la flota, unas 0,7 por agente. Una pasada que tarda varias veces lo habitual apunta al indexer: memoria, disco o una recolección de basura larga.

## Comprobar un activo

En el activo:

```bash
tail -n 5 /var/log/oscompliance/facts.ndjson | jq -c '{fact, ts, status}'
grep -c oscompliance /var/ossec/etc/shared/agent.conf
auditctl -l | grep -c oscompliance_
```

En Discover, sobre `wazuh-alerts-*`, para ese agente:

| Consulta | Muestra |
|---|---|
| `rule.id:119001` | sus hechos |
| `rule.id:119002` | sus sondas de autenticación: el registro de autenticación llega a Wazuh |
| `rule.id:119004` | sus accesos auditados |

Sus veredictos, en `oscompliance-verdicts`:

```
agent.name:"web-01" and scope:evidence and status:NOT_EVALUABLE
```

## Resolución de problemas

No hay alertas 119001 de un activo. El agente de Wazuh no ha recibido el localfile de hechos o las reglas no están cargadas. Comprueba que `/var/ossec/etc/shared/agent.conf` del activo menciona `facts.ndjson` y ejecuta `wazuh-analysisd -t` en el manager. Si el fichero llegó después de la primera pasada, ejecuta `touch /var/log/oscompliance/facts.ndjson`, reinicia `wazuh-agent` y ejecuta `oscompliance-agent -full`.

Todo sale NOT_EVALUABLE por COLLECTION en un activo. No ha habido ninguna pasada del agente en la ventana. Revisa `/etc/cron.d/oscompliance` y ejecuta el agente a mano para leer su error. Con SELinux en enforcing, ejecuta `restorecon` como en la guía de instalación.

Las evidencias de inicio de sesión salen NOT_EVALUABLE por COLLECTION. El registro de autenticación no llega a Wazuh, así que no hay alerta 119002. Añade `/var/log/auth.log`, `/var/log/secure` o journald a los localfiles del agente, y después inicia sesión por SSH.

EV-06 de op.acc.2, op.acc.3 o EV-07 de op.acc.4 salen NOT_EVALUABLE por COLLECTION. auditd está parado, sus vigilancias no están cargadas o no se lee el registro de auditoría. Instala auditd y comprueba `auditctl -l`. El bloque del motor en la configuración de grupo añade el localfile de auditoría.

Las alertas 119004 con clave `oscompliance_read` inundan el indexador desde un activo actualizado desde la 1.2.0 o anterior. Esas versiones cargaban vigilancias de lectura en todas las rutas auditadas, incluidos ficheros legibles por todos como /etc/group, Actualiza el agente: su siguiente pasada retira las vigilancias de lectura cargadas con -w, que no tienen filtro de auid, y toda vigilancia que la configuración de grupo ya no pide. La regla 119005 ya descarta en el manager las lecturas de los ficheros que lee todo proceso.

`failed` de `audit_watch_snapshot` dice "a read watch would fill the disk". Una ruta de P-06 de op.acc.2, P-07 de op.acc.4 o P-02 de op.exp.10 es un fichero que lee todo proceso, o un directorio que contiene uno. Declara en su lugar el fichero o directorio concreto con los datos protegidos.

`failed` de `audit_watch_snapshot` dice "suspended until". El control contó más de `audit_read_limit` lecturas con éxito por minuto en esa vigilancia de lectura durante los últimos 5 minutos y la retiró una hora para proteger el disco. Cada suspensión escribe una línea en el registro de autenticación, y la regla 119006 levanta una alerta de nivel 10 con la ruta. Las lecturas fallidas no cuentan, y una avalancha en una ruta nunca suspende otra. Mientras dura la suspensión, los controles que juzgan lecturas en esa ruta salen NOT_EVALUABLE por COLLECTION. Las suspensiones están en `/var/lib/oscompliance/audit-throttle.json`. Acota la ruta de P-06 de op.acc.2, P-07 de op.acc.4 o P-02 de op.exp.10 a los ficheros que leen las personas, o sube `audit_read_limit` si el volumen es el esperado. Borrar el fichero termina las suspensiones en la siguiente pasada.

Un control sale NOT_EVALUABLE por CONFIGURATION. Falta un parámetro. El veredicto lo nombra: defínelo en Power ENS.

El motor registra `the ENS scope has never been read`. El motor no ha podido leer el índice de configuración desde que arrancó. La línea `parameters` anterior nombra el error, normalmente la conexión con el indexer. Sin una configuración guardada, el motor usa la configuración por defecto del catálogo y no registra esto.

El motor recibe 401 o 403 del indexer. La contraseña es incorrecta o al rol le falta un permiso. Revisa `engine.env` y compara el rol con `engine-role.json`. El error nombra la acción.

El motor recibe 401 o 403 de la API de Wazuh. La contraseña es incorrecta o a la política le falta una acción. Compara la política con `engine-api-role.json`.

El motor registra un error de certificado. La CA es incorrecta o el certificado de la API nombra otro host. Revisa `-ca`, `-wazuh-api-ca` y `-wazuh-api-server-name`.

El motor registra HTTP 429. El indexer está bajo presión. El motor reintenta. Si ocurre a menudo, aumenta la memoria del indexer o `-interval`.

No se aplica la configuración de grupo. Falta `-sync-apply` o el alcance no nombra ningún grupo de Wazuh. La línea `group configuration` del registro indica cuál.

`agent_groups` devuelve el error 1017. El manager está arrancando. Espera un minuto y repite. El error 1751 significa que el agente ya está en el grupo, y no hay que hacer nada.

El manager no tiene veredictos. El agente no está instalado en él o su `ossec.conf` no tiene el localfile de hechos. Consulta la [instalación, apartado 8](install.md#8-auditar-el-manager).

Un activo nuevo no muestra nada. No está en el grupo ENS, o su primera pasada se ejecutó antes de recibir la configuración de grupo. Añádelo al grupo y repite el [apartado 7 de la instalación](install.md#7-instalar-el-agente-en-los-activos-auditados).

Un activo instalado con `--group` no entra en el grupo. El grupo no está en el alcance ENS, al motor le falta `group:modify_assignments` o `agent:modify_group`, o no hay ningún `agent_pass` con `requested_group` en la ventana. Las líneas `group configuration` y `group requests` del registro indican cuál. Tras actualizar desde 1.1.0, ejecuta de nuevo `engine-users.sh create` para añadir las dos acciones.

El agente de Wazuh registra el aviso 1958 para `facts.ndjson`. El fichero está declarado en `ossec.conf` y en la configuración de grupo. Wazuh lo lee una sola vez, y no hay que hacer nada.

Power ENS no aparece en el dashboard. En paquetes, lee la salida de `deploy-plugin.sh` y `journalctl -u wazuh-dashboard`. En Docker, revisa la imagen del servicio `wazuh.dashboard`. Si el zip se compiló para otra versión, el dashboard lo rechaza: compílalo de nuevo para tu versión. Una página en blanco tras una actualización desaparece al cerrar la pestaña y volver a entrar.

Docker no puede descargar imágenes. El host necesita acceso a Docker Hub. Si no lo tiene, descarga `wazuh/wazuh-dashboard` de tu versión y `alpine:3.20` desde una red con acceso, y pásalas con `docker save` y `docker load`.

## Antes de instalar en un activo

`oscompliance-doctor` ([arseniteio/oscompliance-agent-doctor-ens](https://github.com/arseniteio/oscompliance-agent-doctor-ens)) comprueba un activo antes y después de la instalación: que el agente de Wazuh está instalado, registrado, conectado y en el grupo ENS; que auditd, auditctl, cron, el socket de syslog y el log de autenticación están disponibles; y, con el agente instalado, su fichero de cron, sus directorios, su configuración y su última pasada. En el manager comprueba el localfile de hechos en `ossec.conf` en lugar del grupo. Termina con código 0 cuando el activo está lista y con 1 y cada problema en caso contrario.

## Capacidad

Una pasada hace unas 0,7 peticiones por agente. Tarda de 6 a 8 segundos con 1.000 agentes y de 100 a 130 segundos con 10.000, medido en un indexer de laboratorio de un solo nodo con 1 GB de memoria.

Cada agente envía unos 115 hechos al día en régimen estable, una pequeña parte de lo que envían los módulos de Wazuh. Los veredictos se escriben por pasada, así que define una política ISM en `oscompliance-verdicts` con la retención que exija la auditoría.

`oscompliance-fleetsim` carga una flota sintética, copiada de un agente real, en índices separados, para medir el motor en el indexer de destino antes del despliegue:

```bash
oscompliance-fleetsim -indexer https://127.0.0.1:9200 -user admin -ca root-ca.pem \
  -agent 001 -agents 10000 -quiet
oscompliance-engine -indexer https://127.0.0.1:9200 -user admin -ca root-ca.pem \
  -alerts-index wazuh-alerts-4.x-fleetsim -monitoring-index wazuh-monitoring-fleetsim \
  -verdicts-index oscompliance-verdicts-fleetsim
```

## Copias de seguridad

Todo lo que OSCompliance necesita para recuperarse está en el indexer: la configuración ENS (`wazuh-ens-configuration`) y los índices de historial. Inclúyelos en la política de snapshots del indexer. Los agentes no guardan ningún estado que no se pueda reconstruir: perder `/var/lib/oscompliance` solo hace que la siguiente pasada sea completa.
