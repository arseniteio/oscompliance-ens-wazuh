# Seguridad

Una herramienta de cumplimiento se ejecuta como root en cada activo y guarda credenciales junto al SIEM. Esta página indica qué puede hacer cada parte, qué no puede hacer y qué gana un atacante si la compromete.

## Agente

El agente se ejecuta como root desde cron, con una sola pasada a la vez y un fichero de bloqueo que evita solapamientos. Lee ficheros locales del sistema y la salida de comandos locales, listados por colector en [Hechos](facts.md).

Escribe `/var/log/oscompliance/facts.ndjson` (0640), `/var/lib/oscompliance/` (0700) y una línea de syslog por pasada. Su único cambio en el sistema es añadir vigilancias de auditd en tiempo de ejecución, etiquetadas `oscompliance_*`, para las rutas de la configuración de grupo. Retira las vigilancias `oscompliance_*` que la configuración de grupo ya no pide y nunca escribe en `/etc/audit`. Cada 2 minutos, `-guard-audit` retira una vigilancia de lectura cuyas lecturas superan `audit_read_limit`.

No abre ningún socket ni escucha en ningún puerto. Los hechos viajan por el canal existente del agente de Wazuh. Nunca envía hashes de contraseñas, claves privadas, contenido de ficheros ni valores de configuración que los controles no juzgan.

Se ejecuta como root porque los hechos importantes solo están al alcance de root: `/etc/shadow`, `sshd -T`, sudoers, auditd. Los lee; no los cambia.

Los ficheros de configuración pueden contener secretos, así que el colector `config` solo envía las claves que juzgan los controles (por ejemplo `PasswordAuthentication` de sshd, nunca un fichero entero). El colector `keys` encuentra las claves privadas por su cabecera PEM y envía la ruta, el tipo, la huella pública, el modo y el propietario, nunca la clave. El colector `backups` envía fechas, tamaños y permisos de las copias, nunca su contenido.

## Reglas

Las reglas aceptan un hecho solo desde `/var/log/oscompliance/facts.ndjson`, que solo root puede escribir. Un usuario local que escribe una línea con forma de hecho en syslog o en el journal no produce un hecho. Los eventos de servicio (op.acc.5) se rechazan desde syslog, el journal y los registros de autenticación del sistema por la misma razón. Ninguna regla genera una alerta por encima del nivel 3: OSCompliance no añade ruido al SOC.

## Motor

El motor se ejecuta como servicio de systemd en el host del manager, con `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` y `PrivateTmp`. No escribe nada en local.

En el indexer tiene su propio usuario y rol. Lee los índices de alertas, monitorización, inventario y vulnerabilidades de Wazuh y la configuración de Power ENS, y solo escribe en `oscompliance-*`.

En la API de Wazuh tiene su propio usuario y política. Lee agentes, grupos, inventario, configuración del manager y reglas. Solo escribe la configuración de grupo, crea los grupos del alcance ENS y les añade agentes. La política concede `group:read`, `group:create`, `group:update_config`, `group:modify_assignments`, `agent:modify_group`, `agent:read`, `syscollector:read`, `manager:read` y `rules:read`.

`engine-users.sh` crea los dos usuarios. Se autentica en el indexer con el certificado de administración cuando existe `/etc/wazuh-indexer/certs/admin.pem` en el host y, si no, con la contraseña del usuario `admin` del indexer, escrita en la pregunta o leída de `INDEXER_ADMIN_PASSWORD`. La contraseña llega a curl en un fichero de cabeceras temporal, nunca en la línea de comandos, y no se copia ningún certificado entre hosts.

Sus credenciales están en `/etc/oscompliance/engine.env`, modo 0600, y se leen por el entorno. Nunca aparecen en la línea de comandos ni en los registros. Los certificados se verifican contra la CA indicada con `-ca` y `-wazuh-api-ca`, y no hay opción para omitir la verificación.

El motor cambia tres cosas en el despliegue de Wazuh: la región marcada del `agent.conf` de cada grupo ENS, los grupos del alcance ENS que no existen, que crea, y los miembros de esos grupos, a los que añade los agentes que los piden. Las tres son opcionales (`-sync-apply`), se limitan a los grupos del alcance ENS y quedan registradas en `oscompliance-config-history`. El motor nunca saca un agente de un grupo. No puede ejecutar comandos en los agentes, cambiar reglas o decodificadores ni tocar ningún otro grupo.

Roles: [`catalog/wazuh/engine-role.json`](../../catalog/wazuh/engine-role.json), [`catalog/wazuh/engine-api-role.json`](../../catalog/wazuh/engine-api-role.json).

## Plugin

El plugin Power ENS se ejecuta dentro del dashboard de Wazuh con la autenticación del dashboard y el control de acceso del indexer. Escribe la configuración ENS y lee veredictos. No juzga nada, así que un plugin modificado puede mostrar mal los veredictos, pero no cambiar los guardados.

## Modelo de amenazas

Una cuenta sin privilegios en un activo auditado no gana nada específico de OSCompliance. No puede escribir hechos, falsificar eventos de servicio ni leer el fichero de hechos.

Root en un activo auditado puede parar el agente. Las evidencias del activo pasan a NOT_EVALUABLE por COLLECTION y aparece como no conforme, así que la parada no se puede ocultar. También puede escribir hechos falsos sobre ese activo, pero no sobre otra. No puede falsificar lo que recoge el propio Wazuh (inicios de sesión, sudo, FIM, SCA, inventario, vulnerabilidades), que muchas evidencias leen en lugar del agente.

El host del motor es el host del manager de Wazuh. Quien lo controla puede cambiar veredictos, pero en ese punto Wazuh ya está comprometido.

Las credenciales del motor en el indexer permiten escribir veredictos falsos. No permiten leer más allá de los índices de Wazuh ni cambiar los datos de Wazuh.

Las credenciales del motor en la API permiten cambiar la configuración de cualquier grupo y los grupos de cualquier agente. No permiten ejecutar comandos, reiniciar agentes ni cambiar reglas.

Root en un activo auditado puede pedir un grupo con `wazuh_group`. El motor solo añade el agente a un grupo del alcance ENS, así que la petición no puede meter el activo en ningún otro grupo ni sacarlo de uno.

Con `install.sh agent --group`, el activo auditado lee el fichero de hechos mediante un localfile en su propio `ossec.conf`, entre marcas `<!-- oscompliance begin -->`. Lee el mismo fichero que la configuración de grupo, así que no añade ninguna fuente nueva a lo que aceptan las reglas.

Por eso el activo auditado informa de hechos, nunca de veredictos, y por eso el silencio nunca es cumplimiento. Donde Wazuh ya observa algo, el motor lee Wazuh, no el agente.

## Cadena de suministro

- El agente y el motor solo usan la biblioteca estándar de Go y el catálogo propio de este repositorio. No hay código de terceros en ningún binario.
- `make dist` compila con `CGO_ENABLED=0` y `-trimpath` y escribe `SHA256SUMS`. `make check` ejecuta gofmt, `go vet` y todas las pruebas.
- Los binarios son estáticos: no se carga ninguna biblioteca compartida del host.

## Notificar una vulnerabilidad

Notifícala en privado mediante un aviso de seguridad de GitHub en este repositorio. No abras una incidencia pública.
