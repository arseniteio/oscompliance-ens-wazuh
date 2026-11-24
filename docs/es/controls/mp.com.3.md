# mp.com.3 Protección de la integridad y de la autenticidad

mp.com.3 juzga si los activos autentican al otro extremo antes de intercambiar, usan los algoritmos que autoriza el CCN, detectan ataques activos y abren un incidente cuando ocurren, llevan sus canales fuera del dominio por túneles cifrados, cambian las configuraciones de canal solo bajo control de cambios y usan productos certificados.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.4.3. Definición: [`catalog/controls/ens/mp.com.3.json`](../../../catalog/controls/ens/mp.com.3.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 3.1 primero se autentica al otro extremo | B/M/A | EV-01, EV-02, EV-10 |
| 3.2 ataques activos tratados como incidentes | B/M/A | EV-04 a EV-07 |
| 3.3 mecanismos legales de identificación aceptados | B/M/A | atestación (P-ATT) |
| r1.1 VPN cifrada fuera del dominio | M/A | EV-08 |
| r2.1 algoritmos autorizados por el CCN | M/A | EV-02, EV-03, EV-10 |
| r3.1 dispositivos VPN de hardware | A | atestación (P-ATT) |
| r4.1 productos certificados según op.pl.5 | A | EV-11 |
| r5.1 cifradores CCN-STIC | ninguno | |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `config_file` de `/etc/ssh/ssh_config` y sus drop-ins | `Host`, `StrictHostKeyChecking`, `UserKnownHostsFile` | EV-01 |
| `config_file` para `sshd -T`, inicios de sesión por sshd ([op.exp.10](op.exp.10.md)) | algoritmos aceptados y tipos de clave usados | EV-02, EV-03 |
| reglas de la API de Wazuh ([op.mon.1](op.mon.1.md)) | reglas de los indicadores de P-02 | EV-04 a EV-07 |
| alertas de esas reglas, por activo y hora | | EV-07 |
| P-13 de op.exp.7, registro de incidentes | | EV-07 |
| inventario de red ([mp.com.1](mp.com.1.md)) | interfaces y procesos de túnel | EV-08 |
| alertas de FIM ([op.exp.5](op.exp.5.md)), P-10 de op.exp.5 | cambios bajo P-06 y sus peticiones | EV-10 |

Las rutas de P-06 fuera de los directorios por defecto de FIM de Wazuh llegan al agente en la configuración de grupo como directorios de FIM.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 canales fuera del dominio | documental | |
| P-02 indicadores de ataques activos `ataque \| indicador \| fuente \| reglas` | `ataque` alteración, inyección o secuestro | EV-04 a EV-07 |
| P-03 procedimiento de incidentes, P-04 mecanismos de identificación, P-08 VPN de hardware | documental | |
| P-05 túneles `canal \| sistema \| tunel \| protocolo \| cifrado` | `tunel` una interfaz o un proceso | EV-08 |
| P-06 configuraciones de canal | sistema; integradas por tipo de sistema | EV-10 |
| P-07 productos certificados `producto \| certificacion \| referencia \| vigencia` | | EV-11 |
| P-03 de op.exp.10, algoritmos autorizados | | EV-02, EV-03 |
| P-ATT atestaciones documentales | 3.3, r3.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpcom3`.

- EV-01 el otro extremo. Sin `StrictHostKeyChecking no` (u `off`) ni `UserKnownHostsFile /dev/null` en la configuración del cliente SSH.
- EV-02, EV-03 algoritmos. Como EV-03 y EV-04 de op.exp.10.
- EV-04 a EV-06 ataques activos. La alteración, la inyección y el secuestro tienen cada uno filas en P-02, y cada fila una regla cargada de nivel 1 o superior.
- EV-07 incidentes. Cada hora de la ventana con una alerta de esas reglas en el activo tiene un incidente de op.exp.7 que la afecta, abierto desde una hora antes hasta un día después.
- EV-08 túneles. Cada fila de P-05 para el activo tiene su `tunel` activo como interfaz o en marcha como proceso.
- EV-10 cambios de configuración. Cada cambio de FIM de la ventana bajo P-06 cubierto por una petición de P-10 de op.exp.5.
- EV-11 productos. Cada producto de P-07 con una `referencia` y una `vigencia` no vencida.

## No se mide

- Los mecanismos no rechazados. Ningún registro indica que se haya rechazado un mecanismo legal; 3.3 es una atestación.
