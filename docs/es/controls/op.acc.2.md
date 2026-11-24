# op.acc.2 Requisitos de acceso

op.acc.2 juzga que los recursos están protegidos por control de acceso: nada crítico es escribible por todos, los ficheros del sistema operativo no cambian sin que se note, nadie escala sin autorización, los derechos declarados son los aplicados y, en ALTO, cada privilegio es individual y cada acceso es de un tipo permitido.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.2.2. Definición: [`catalog/controls/ens/op.acc.2.json`](../../../catalog/controls/ens/op.acc.2.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 2.1 recursos protegidos por control de acceso | B/M/A | EV-01, EV-03, EV-07 |
| 2.2 derechos según decide el propietario del recurso | B/M/A | EV-03, EV-04 |
| 2.3 ficheros del sistema operativo protegidos | B/M/A | EV-02, EV-03, EV-07 |
| r1.1 privilegios mantenidos individualmente | A | EV-05 |
| r1.2 los privilegios restringen el tipo de acceso | A | EV-05, EV-06 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `file_sweep_snapshot`, `special_file` (`sweep`, diario) | entradas escribibles por todos, ficheros SUID y SGID, entradas sin propietario o grupo | EV-01, EV-07 |
| `umask_snapshot` (`umask`) | cada declaración de umask de login.defs, /etc/profile, /etc/bash.bashrc y /etc/profile.d | EV-01 |
| `identity_*`, `group_*` ([op.acc.1](op.acc.1.md)) | cuentas y grupos | EV-03, EV-05, EV-06 |
| `sudoers_snapshot`, `sudo_grant` (`sudoers`) | especificaciones de usuario con los alias expandidos, comandos NOPASSWD, Defaults; se siguen los includes | EV-03, EV-05 |
| `wazuh_agent_config` (`wazuh`) | directorios, exclusiones y frecuencia de FIM; localfiles | EV-02, EV-06 |
| `acl_snapshot`, `acl_record` (`acl`) | modo, propietario y ACL POSIX de cada ruta de P-08 | EV-04 |
| `audit_watch_snapshot` (`audit`) | estado de auditd y vigilancias cargadas | EV-06 |
| `auth_log_probe` y regla 119002 | el registro de autenticación llega a Wazuh | EV-03 |
| alertas de FIM, grupo `syscheck` | cambios en ficheros | EV-02 |
| alertas de sudo 5401 a 5407, sesiones de su (5501) | elevaciones y rechazos | EV-03 |
| regla 119004, registros de auditd con una clave `oscompliance_*` | accesos auditados y su tipo | EV-06 |

El barrido recorre `/` y los demás sistemas de ficheros locales, nunca los de red ni los pseudo sistemas de ficheros, y no sigue enlaces simbólicos. Tiene un límite de tiempo y otro de registros; al alcanzar cualquiera, marca el barrido como parcial en lugar de ocultar lo que falta.

Las rutas de P-08 y P-06 llegan a los agentes por la configuración de grupo que escribe el motor (`acl_paths`, `read_watches`). Para cada ruta auditada, el agente carga cuatro vigilancias de auditd, una por permiso (`oscompliance_read`, `_write`, `_exec`, `_attr`), de modo que cada acceso auditado lleva su tipo. Las lecturas solo se registran para sesiones con UID de inicio de sesión. Nunca retira una regla.

FIM es el de Wazuh. Por defecto vigila /etc, /usr/bin, /usr/sbin, /bin, /sbin y /boot; una ruta de P-02 en otro lugar necesita una entrada `<directories>` en la configuración de grupo.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 sistemas en alcance | sistema | |
| P-02 rutas críticas | plataforma | EV-01 (alcance), EV-02 |
| P-03 escribible por todos permitido si tiene sticky | | EV-01 |
| P-04 referencia de la política de acceso | documental | |
| P-05 modelo de privilegios | presencia | EV-05 |
| P-06 `perfil \| recurso \| tipos_permitidos` | sistema | EV-06 |
| P-07 umask mínima | | EV-01 |
| P-08 `recurso \| modo \| propietario_grupo \| acl_esperada` | sistema | EV-04 |
| P-09 `usuario \| perfil \| privilegios` | sistema | EV-05, EV-06 |
| P-10 binarios SUID y SGID autorizados | plataforma | EV-07 |
| P-11 excepciones de escritura para todos | plataforma | EV-01 |
| P-12 grupos privilegiados | plataforma | EV-03, EV-05 |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opacc2`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION.

- EV-01 escritura para todos y umask. Una entrada escribible por todos bajo una ruta de P-02 que no es una excepción de P-11 (ni, con P-03, un directorio con sticky), o una umask declarada que no cubre todos los bits de P-07: NON_COMPLIANT. Un barrido parcial, una fuente de umask ilegible o ninguna umask declarada: NOT_EVALUABLE por COLLECTION. La umask nunca se supone.
- EV-02 ficheros críticos. Una alerta de FIM de la ventana en una ruta de P-02 o debajo de ella: NON_COMPLIANT; se informa de cada cambio. Una ruta de P-02 que FIM no vigila a tiempo (sin cubrir, excluida, FIM apagado o análisis más espaciados que la ventana sin tiempo real): NOT_EVALUABLE por COLLECTION.
- EV-03 escaladas. Son cuentas privilegiadas el UID 0, los miembros de un grupo de P-12 y las cuentas que nombra una concesión de sudo. Una ejecución de sudo o sesión de su que convierte una cuenta sin privilegios en una privilegiada: NON_COMPLIANT. Pasar a una cuenta ordinaria es lateral y se acepta; los rechazos son el control funcionando y solo se informa de ellos. Una elevación de una cuenta no local o con puntos ciegos en sudoers, o ninguna elevación mientras la sonda no vuelve: NOT_EVALUABLE por COLLECTION.
- EV-04 derechos declarados. Para cada fila de P-08: el modo se compara en octal, el propietario si está declarado, cada entrada de ACL declarada debe estar presente y cada entrada con nombre aplicada debe estar declarada. Una diferencia: NON_COMPLIANT. Una ruta que falta o no se puede leer: NOT_EVALUABLE por COLLECTION.
- EV-05 privilegios individuales (ALTO). Una cuenta privilegiada (como en EV-03, sin el UID 0) que no está en P-09: NON_COMPLIANT. Puntos ciegos en sudoers o concesiones a grupos o UID que no existen: NOT_EVALUABLE por COLLECTION.
- EV-06 tipo de acceso (ALTO). Para cada acceso auditado con éxito, la persona (UID de auditoría o, si no, UID) da un perfil mediante P-09; el perfil y la ruta más larga de P-06 que contiene el recurso dan los tipos permitidos. Un tipo no permitido: NON_COMPLIANT. Una cuenta sin perfil se cuenta, no se juzga. Un acceso sin persona o sin fila: NOT_EVALUABLE por EVIDENCE. El silencio exige auditd en marcha, todas las rutas de P-06 vigiladas y el registro de auditoría leído por Wazuh; si no, NOT_EVALUABLE por COLLECTION.
- EV-07 ficheros SUID, SGID y sin propietario. Una entrada sin propietario o grupo, o un fichero SUID o SGID que no está en P-10: NON_COMPLIANT. Un barrido parcial sin hallazgos: NOT_EVALUABLE por COLLECTION.

## No se mide

- Los activos sin auditd, como la mayoría de los contenedores: EV-06 queda ahí NOT_EVALUABLE por COLLECTION.
- No se leen los rechazos de auditd; de las ejecuciones de sudo rechazadas solo se informa.
