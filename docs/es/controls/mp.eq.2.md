# mp.eq.2 Bloqueo de puesto de trabajo

mp.eq.2 juzga, en cada puesto de trabajo, el bloqueo tras el tiempo de inactividad de P-01, la cancelación de las sesiones inactivas tras el tiempo mayor de P-02 y las herramientas que evitan que la sesión quede inactiva.

Niveles: MEDIO, ALTO. Anexo II, apartado 5.3.2. Definición: [`catalog/controls/ens/mp.eq.2.json`](../../../catalog/controls/ens/mp.eq.2.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 2.1 bloqueo por inactividad con nueva autenticación | M/A | EV-01, EV-05 |
| r1.1 sesiones abiertas canceladas más tarde | A | EV-02 |

Un activo que no es un puesto de trabajo (P-03 o, por defecto, una sin sesión gráfica) o que P-04 exceptúa: todas las evidencias y requisitos NOT_APPLICABLE.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| hecho `device_security` | bloqueo de pantalla, tiempos de inactividad, sesión gráfica | EV-01, EV-02, decisiones |
| `wazuh-states-inventory-processes-*` (el manager mediante la API) | procesos nombrados en P-05 | EV-05 |

### `device_security`

Uno por pasada, solo se emite cuando cambia:

- `chassis_type` (SMBIOS, `/sys/class/dmi/id/chassis_type`) y `portable` (tipos 8 a 11, 14, 30 a 32).
- `graphical`: hay un gestor de pantalla instalado (`display-manager.service`, gdm, lightdm o sddm).
- `lock_idle_delay_seconds`, `lock_enabled`, `lock_delay_seconds`: `org/gnome/desktop/session/idle-delay` y `org/gnome/desktop/screensaver/lock-enabled`, `lock-delay` de GNOME en los ficheros dconf del sistema (`/etc/dconf/db/*.d/*`); prevalece el último fichero.
- `shell_timeout_seconds`, `shell_timeout_readonly`: el `TMOUT` más corto de `/etc/profile`, `/etc/bash.bashrc` y `/etc/profile.d/*.sh`, y si está declarado de solo lectura.
- `logind_idle_seconds`: `StopIdleSessionSec` de logind.conf y sus drop-ins.
- `root_device`, `root_encrypted`: el dispositivo montado en `/` y si él o un dispositivo por debajo es dm-crypt (mp.eq.3).
- `dns_resolvers`: las líneas `nameserver` de `/etc/resolv.conf`; para el stub de systemd-resolved, las de `/run/systemd/resolve/resolv.conf` (mp.s.3).
- `cpu_count`, `load_percent`, `memory_used_percent`, `syn_cookies`: la carga media de 15 minutos frente a las CPU y la memoria en uso, ambas redondeadas a la decena inferior para que el hecho solo cambie al cruzar un tramo, y `net.ipv4.tcp_syncookies` (mp.s.4).

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 minutos de inactividad antes del bloqueo | | EV-01, EV-02 |
| P-02 minutos de inactividad antes de cancelar | | EV-02 |
| P-03 el activo es un puesto de trabajo | sistema; manager: no | decisiones |
| P-04 excepciones `equipo \| justificacion \| medidas \| aprobador` | | decisiones |
| P-05 inhibidores de inactividad | nombres de proceso | EV-05 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpeq2`.

- EV-01 bloqueo. Con sesión gráfica: bloqueo activado, tiempo de inactividad definido y distinto de 0, inactividad más demora de bloqueo dentro de P-01 minutos. Sin ella: un `TMOUT` de solo lectura dentro de P-01 minutos.
- EV-02 cancelación. `StopIdleSessionSec`, o el `TMOUT` sin sesión gráfica, mayor que P-01 y dentro de P-02 minutos.
- EV-05 inhibidores. Ningún proceso nombrado en P-05 (por defecto caffeine, caffeine-ng, caffeinate, jiggler, mousejiggler, keepawake, nosleep, insomnia, stay-awake).

## No se mide

- Los eventos de bloqueo y las sesiones largas sin bloqueo. El bloqueo de una sesión Linux no deja ningún evento que Wazuh decodifique.
