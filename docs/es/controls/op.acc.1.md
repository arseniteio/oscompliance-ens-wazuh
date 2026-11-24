# op.acc.1 Identificación

op.acc.1 juzga que cada persona y cada proceso tiene su propio identificador: los UID son únicos, los cambios de identidad quedan registrados, las cuentas genéricas y de servicio no inician sesión, los administradores usan una cuenta separada, las bajas se deshabilitan a tiempo y se conservan antes de borrarse, y toda cuenta activa está autorizada.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.2.1. Definición: [`catalog/controls/ens/op.acc.1.json`](../../../catalog/controls/ens/op.acc.1.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 1.1 identificador único y válido | B/M/A | EV-03 |
| 1.2 identificadores separados por rol | B/M/A | EV-05, EV-06 |
| 1.3 un identificador por entidad | B/M/A | EV-01, EV-02, EV-03, EV-05 |
| 1.4 ciclo de vida de las cuentas | B/M/A | EV-01, EV-02, EV-04, EV-08 |
| 1.5 identificación en comunicaciones electrónicas (eIDAS) | B/M/A | P-ATT |
| r1.1 la persona detrás del identificador | M/A | P-ATT |
| r1.2 la identificación determina los privilegios | M/A | EV-01, EV-06 |
| r1.3 lista actualizada de usuarios autorizados | M/A | EV-01, EV-07 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `identity_snapshot`, `identity_record` (colector `identity`) | cada entrada de passwd unida con shadow: nombre, UID, GID, shell, estado de la contraseña, caducidad, número de claves que acepta sshd | EV-01, EV-02, EV-04, EV-06, EV-07, EV-08 |
| `group_snapshot`, `group_record` (colector `groups`) | cada grupo y sus miembros | EV-06 |
| inicios de sesión por sshd, regla 5715 y derivadas | `data.dstuser`, `data.srcip` | EV-03, EV-05, EV-06 |
| inicios de sesión en consola, su y gráficos, regla 5501 (`login`, `su`, `gdm-password`, `lightdm`, `sddm`) | `data.dstuser` | EV-03, EV-05, EV-06 |
| cualquier alerta `authentication_success`, `authentication_failed` o `sudo` en el periodo de consulta | el registro de autenticación llega a Wazuh | EV-03, EV-05, EV-06 |
| `oscompliance-identity-history` (índice del motor) | por agente y cuenta: primera y última vez vista, deshabilitada desde, borrada el, última caducidad | EV-08, op.acc.6 EV-06 |

El agente envía la tabla de identidades completa en cada pasada y nunca un hash de contraseña ni una clave. No aplica ningún umbral de UID ni calcula cambios: el motor compara pasadas, así que una línea base perdida o manipulada en el activo no puede ocultar ni inventar un cambio.

El número de claves por cuenta sale de `sshd -T -C user=<cuenta>`, así que los bloques `Match User` y `Match Group` se aplican con exactitud. Cuando decide un `AuthorizedKeysCommand`, el número es desconocido.

Una pasada es utilizable cuando se han leído passwd y shadow y han llegado todos los registros de su `run_id`. Si no, las evidencias que la necesitan quedan NOT_EVALUABLE por COLLECTION.

Cuenta deshabilitada: shell sin inicio de sesión, caducada, o sin contraseña utilizable (`locked` o `missing`) y sin clave SSH. Una contraseña bloqueada con claves no está deshabilitada: sshd sigue aceptando la clave. Cuenta activa: UID igual o mayor que P-10 y no deshabilitada.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 origen de las identidades | documental | |
| P-02 sistemas en alcance | sistema | |
| P-03 cuentas de servicio | plataforma; lista o expresión regular | EV-05 |
| P-04 cuentas genéricas prohibidas | lista o expresión regular | EV-03 |
| P-05 días para deshabilitar una baja | | EV-04 |
| P-06 días para conservar una cuenta deshabilitada antes de borrarla | | EV-08 |
| P-07 usuarios autorizados `usuario \| sistema \| rol` | sistema; solo se compara `usuario` | EV-07 |
| P-08 integración con RR. HH. | documental | |
| P-09 bajas declaradas `usuario \| fecha_baja` (AAAA-MM-DD) | | EV-04, EV-08 |
| P-10 UID más bajo de una persona | plataforma; valor por defecto del producto 1000 | EV-01, EV-04, EV-07, EV-08 |
| P-11 grupos privilegiados | plataforma; valor por defecto del producto `sudo, wheel, admin` | EV-06 |
| P-12 prefijo o sufijo de las cuentas administrativas | tabla `texto`, `posicion` (`sufijo` o `prefijo`, vacía equivale a `sufijo`); se aplican todas las filas; si no hay ninguna, no excluye a nadie | EV-06 |
| P-ATT atestaciones documentales | | 1.5, r1.1 |

Las expresiones regulares son RE2, comparan el nombre completo, distinguen mayúsculas y tienen 512 caracteres como máximo. Las listas comparan sin distinguir mayúsculas. P-10 y P-11 son los únicos parámetros con valor por defecto del producto, y el veredicto indica cuándo se usa.

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opacc1`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION.

- EV-01 inventario de cuentas. Un UID en más de una entrada, sea cual sea: NON_COMPLIANT, nombrando cada cuenta. Si no, COMPLIANT.
- EV-02 cambios de identidad registrados. Se compara con la pasada completa anterior más reciente (se prueban hasta diez): el veredicto lista las cuentas creadas, borradas y modificadas en cualquier campo. COMPLIANT siempre que la pasada sea utilizable; la primera pasada es la línea base. Solo falla si falla la recogida.
- EV-03 cuentas genéricas. Un inicio de sesión en la ventana de una cuenta que coincide con P-04: NON_COMPLIANT, con cada cuenta y su recuento. Ningún evento de autenticación en el periodo de consulta: NOT_EVALUABLE por COLLECTION, porque el silencio de un registro que no llega a Wazuh no es cumplimiento.
- EV-04 bajas deshabilitadas a tiempo. Una cuenta con UID igual o mayor que P-10 y una fecha de baja (su fila de P-09 o, si no, su caducidad) sin deshabilitar en los P-05 días siguientes: NON_COMPLIANT. Cuando solo sus claves podrían decidirlo y son desconocidas: NOT_EVALUABLE por EVIDENCE. Sin ninguna fecha y con P-09 vacío: NOT_EVALUABLE por CONFIGURATION. Una cuenta declarada que ya no existe cuenta como tratada.
- EV-05 cuentas de servicio. Como EV-03, frente a P-03.
- EV-06 una identidad por rol. Un miembro de un grupo de P-11 (grupo primario incluido) que no es una cuenta administrativa según una convención de P-12 y no tiene una cuenta que empareje `<miembro>` con una convención de P-12, o un inicio de sesión de ese miembro: NON_COMPLIANT. Sin hallazgos y sin eventos de autenticación en el periodo de consulta: NOT_EVALUABLE por COLLECTION.
- EV-07 cuentas activas autorizadas. Una cuenta activa que no está en la columna `usuario` de P-07: NON_COMPLIANT. No listada y con estado desconocido: NOT_EVALUABLE por EVIDENCE.
- EV-08 conservación antes del borrado. Según el historial de identidades. Una cuenta con UID igual o mayor que P-10 borrada en la ventana menos de P-06 días después de su fecha de inicio (fila de P-09 o, si no, última caducidad o, si no, el día en que se vio deshabilitada), o borrada estando aún habilitada: NON_COMPLIANT. Borrada sin fecha de inicio o con su último estado desconocido: NOT_EVALUABLE por EVIDENCE.

## No se mide

- La identificación eIDAS (1.5) y la persona detrás de cada identificador (r1.1). Ningún activo las registra. Se juzgan por atestación.
- Las cuentas de directorio. No se leen las cuentas que solo existen en LDAP, Active Directory u otro directorio: el control juzga la tabla de identidades local de cada activo.
