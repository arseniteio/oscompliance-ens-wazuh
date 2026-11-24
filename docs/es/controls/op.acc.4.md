# op.acc.4 Proceso de gestión de derechos de acceso

op.acc.4 juzga qué está abierto a cualquiera, quién tiene qué privilegios frente a la matriz de accesos de P-01, quién cambia los derechos, quién llega a los recursos de necesidad de conocer, quién inicia sesión en remoto y si los derechos se revisan.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.2.4. Definición: [`catalog/controls/ens/op.acc.4.json`](../../../catalog/controls/ens/op.acc.4.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 4.1 acceso denegado salvo autorización | B/M/A | EV-01, EV-02 |
| 4.2 mínimo privilegio | B/M/A | EV-02, EV-03, EV-08 |
| 4.3 necesidad de conocer | B/M/A | EV-07 |
| 4.4 solo el personal competente concede derechos | B/M/A | EV-03, EV-04, EV-05 |
| 4.5 política de acceso remoto | B/M/A | EV-06 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `firewall_snapshot` (`firewall`) | cadenas del filtro de paquetes y su política por defecto | EV-01 |
| `config_snapshot`, `config_file` | smb.conf, vsftpd.conf, login.defs | EV-01, EV-08 |
| `sudoers_snapshot`, `sudo_grant` ([op.acc.2](op.acc.2.md)) | concesiones de sudo | EV-02, EV-08 |
| `identity_*`, `group_*` ([op.acc.1](op.acc.1.md)) | cuentas y grupos | EV-03, EV-04, EV-07, EV-08 |
| `audit_watch_snapshot`, `wazuh_agent_config` ([op.acc.2](op.acc.2.md)) | estado de auditd, vigilancias, registro de auditoría leído por Wazuh | EV-04, EV-07 |
| regla 119004, accesos auditados | cambios de derechos (`oscompliance_perm`) y accesos | EV-04, EV-07 |
| inicios de sesión por sshd, regla 5715 y derivadas | inicios de sesión remotos | EV-06 |
| `auth_log_probe` y regla 119002 | el registro de autenticación llega a Wazuh | EV-06 |

Las rutas de P-07 llegan a auditd por la configuración de grupo que escribe el motor (`read_watches`). Los cambios de modo, propietario y atributos, y las escrituras en los ficheros de cuentas y de sudo, se auditan con la clave `oscompliance_perm`.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 matriz de accesos `rol \| recurso \| acceso,acceso` | sistema; los roles son cuentas o sujetos de sudoers (`%grupo`, `#uid`, `%#gid`) | EV-01, EV-02, EV-03, EV-08 |
| P-02 cuentas competentes para cambiar derechos | primera columna | EV-04 |
| P-03 días entre revisiones | | EV-05 |
| P-04 canales de acceso remoto permitidos | plataforma; ver [op.acc.6](op.acc.6.md) | |
| P-05 cuentas con acceso remoto permitido | sistema; hasta el primer `\|` | EV-06 |
| P-06 grupos privilegiados | plataforma | EV-03 |
| P-07 recursos de necesidad de conocer `recurso \| perfiles` | sistema; los perfiles son grupos | EV-07 |
| P-08 registro de revisiones `fecha \| alcance \| responsable` | | EV-05 |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opacc4`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION. El silencio en un activo con la cadena de auditoría incompleta (auditd parado, reglas sin cargar, registro de auditoría sin leer) es NOT_EVALUABLE por COLLECTION; un incumplimiento encontrado se mantiene.

- EV-01 denegar por defecto. Son aperturas una cadena del filtro de paquetes que acepta por defecto, la falta de cadena de entrada, la falta total de filtro de paquetes, un recurso de Samba con `guest ok` o `public` y vsftpd con `anonymous_enable`. Una apertura cuyo recurso no está en la columna `recurso` de P-01: NON_COMPLIANT. Un filtro de paquetes sin reglas es una apertura.
- EV-02 sudo frente a la matriz. Cada concesión se busca como `sujeto | sudo` en P-01, y cada parte de lo que concede debe estar entre los accesos de la fila. Una concesión sin fila o por encima de sus accesos: NON_COMPLIANT. Una fila sin accesos: NOT_EVALUABLE por CONFIGURATION. sudo sin instalar: COMPLIANT. Las concesiones a sujetos que el agente no puede nombrar dejan el silencio en NOT_EVALUABLE por COLLECTION.
- EV-03 grupos privilegiados. Cada miembro de un grupo de P-06, grupo primario incluido, debe ser un rol de P-01; si no, NON_COMPLIANT.
- EV-04 quién cambia los derechos. Cada cambio `oscompliance_perm` con éxito en la ventana debe ser de una cuenta de P-02; si no, NON_COMPLIANT. Cambios cuya cuenta no se puede nombrar: NOT_EVALUABLE por EVIDENCE.
- EV-05 revisión periódica. La fecha más reciente de P-08 que no esté en el futuro debe quedar dentro de P-03 días; si no, NON_COMPLIANT. Sin fecha utilizable: NOT_EVALUABLE por CONFIGURATION.
- EV-06 acceso remoto. Cada inicio de sesión por sshd en la ventana debe ser de una cuenta de P-05; si no, NON_COMPLIANT. Ningún inicio de sesión es COMPLIANT solo si la sonda demuestra que el registro llega a Wazuh.
- EV-07 necesidad de conocer. Cada acceso auditado bajo un recurso de P-07 (el más largo que lo contiene) debe ser de una cuenta con uno de sus perfiles entre sus grupos; si no, NON_COMPLIANT. El silencio exige que auditd vigile todos los recursos de P-07.
- EV-08 privilegios por encima del mínimo. Las concesiones de sudo de cualquier comando y las cuentas de sistema (UID por debajo de `UID_MIN` de login.defs, salvo root) con shell de inicio de sesión deben ser roles de P-01; si no, NON_COMPLIANT.

## No se mide

- Los derechos dentro de aplicaciones y directorios. El control lee el sistema operativo: filtro de paquetes, compartición de ficheros, sudo, grupos y accesos a ficheros auditados.
- El acceso remoto por canales distintos de sshd para EV-06; los propios canales los juzgan EV-07 y EV-08 de [op.acc.6](op.acc.6.md).
