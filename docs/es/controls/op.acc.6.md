# op.acc.6 Mecanismo de autenticación (usuarios de la organización)

op.acc.6 juzga cómo se autentica el personal en cada activo Linux: los factores que exige cada canal por zona, el bloqueo, la antigüedad y la calidad de las credenciales, la inhabilitación tras un aviso, los canales remotos, la reautenticación en puntos críticos, la suspensión por falta de uso y lo que se expone antes de autenticarse.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.2.6. Definición: [`catalog/controls/ens/op.acc.6.json`](../../../catalog/controls/ens/op.acc.6.json).

## Requisitos

| Requisito | Niveles | Evidencias | Se prueba con |
|---|---|---|---|
| 6.1, 6.2, 6.3, 6.9 | B/M/A | | P-ATT |
| 6.4 cambio periódico de credenciales | B/M/A | EV-05 | P-04 |
| 6.5, 6.6 inhabilitación por compromiso o salida | B/M/A | EV-06 | P-06, P-12 |
| 6.7 nada revelado antes de autenticarse | B/M/A | EV-12 | P-11 |
| 6.8 límite de intentos con bloqueo | B/M/A | EV-03, EV-04 | P-05 |
| r1.1 contraseña solo desde zonas controladas (R1) | B/M/A | EV-02 | P-01, P-02 |
| r1.2 calidad de la contraseña (R1, R2) | B/M/A | EV-11 | P-01, P-10 |
| r2.1 segundo factor (R2) | B/M/A | EV-02 | P-01 |
| r3.1, r3.2, r4.1, r4.2 certificados (R3, R4) | B/M/A | | P-01, P-ATT |
| r5.1 registro de accesos | M/A | EV-01 | P-03 |
| r5.2 aviso de último acceso | M/A | | P-ATT |
| r6.1 reautenticación en puntos críticos | A | EV-09 | P-08 |
| r7.1 suspensión por falta de uso | A | EV-10 | P-09 |
| r8.1 dos factores desde zonas no controladas | B/M/A | EV-02 | P-02 |
| r9.1 ITS de interconexión | B/M/A | | P-ATT |
| r9.2 acceso remoto autorizado y cifrado | B/M/A | EV-07, EV-08 | P-07 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `identity_*` (`identity`) | cuentas, último cambio de contraseña, días máximos e inactivos, cambio más reciente de los ficheros de claves, último inicio de sesión de wtmp y lastlog | EV-05, EV-06, EV-10 |
| `config_snapshot`, `config_file` (`config`) | login.defs, faillock.conf, pwquality.conf y sus drop-ins, pwhistory.conf, sshd_config y sus drop-ins, `sshd -T`, `ssh -V` | EV-01, EV-02, EV-03, EV-05, EV-11, EV-12 |
| `pam_snapshot`, `pam_rule` (`pam`) | pilas auth y password de sshd, login, gestores de sesión, su, sudo y passwd, con includes y substacks resueltos | EV-02, EV-03, EV-09, EV-11 |
| `sudoers_snapshot`, `sudo_grant` (`sudoers`) | comandos NOPASSWD y Defaults | EV-09 |
| `listening_snapshot`, `listening_socket` (`listening`) | escuchas fuera de loopback con proceso, unidad systemd, unidad de socket y si arrancan con el sistema | EV-02, EV-08 |
| `auth_log_probe` y regla 119002 | el registro de autenticación llega a Wazuh | EV-01, EV-02, EV-04, EV-07 |
| `authentication_success`: sshd (5715) y sesiones PAM de login y gestores de sesión (5501) | inicios de sesión, con método de sshd y tipo de clave | EV-02, EV-07, EV-10 |
| `authentication_failed` con `data.dstuser`, sin `invalid_login` | fallos contra cuentas existentes | EV-04 |
| líneas de bloqueo de pam_faillock y pam_tally2 | bloqueos | EV-04 |
| `oscompliance-identity-history` ([op.acc.1](op.acc.1.md)) | cuándo se deshabilitó o borró una cuenta | EV-06 |

De los ficheros de configuración, que pueden contener secretos, solo se envían las claves que juzgan los controles. PAM se resuelve igual en Debian (`common-*`) y en RHEL (`system-auth`, `password-auth`); se marca una regla cuyo módulo no está instalado.

El agente escribe `auth log probe <run_id>` en syslog (authpriv, etiqueta `oscompliance-agent`) en cada pasada. La regla 119002 para esa línea demuestra que el registro de autenticación llega a Wazuh aunque nadie haya iniciado sesión. Una sonda escrita hace más de diez minutos que nunca ha vuelto demuestra que no llega.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 mecanismo: R1, R2, R3 o R4 | uno, no acumulativo | decisiones sobre r1.x a r4.x |
| P-02 zonas controladas: CIDR, dirección o `local` | | EV-02 |
| P-03 fuentes cuyos accesos se deben registrar | plataforma | EV-01 |
| P-04 días entre cambios de credencial | | EV-05 |
| P-05 máximo de intentos fallidos | | EV-03, EV-04 |
| P-06 horas para inhabilitar tras un aviso | | EV-06 |
| P-07 `canal \| cifrado \| autoriza \| uso_constante` | plataforma | EV-07, EV-08 |
| P-08 puntos críticos: `sudo`, `su`, `sudo:/ruta` | plataforma | EV-09 |
| P-09 días sin uso antes de la suspensión | | EV-10 |
| P-10 `criterio \| minimo` | | EV-11 |
| P-11 exposiciones permitidas, o `ninguna` | plataforma | EV-12 |
| P-12 registro `usuario \| fecha \| motivo` | fechas RFC 3339 o un día | EV-06 |
| P-ATT atestaciones documentales | | requisitos documentales |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opacc6`. Si falta una fuente o está incompleta, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION, nunca un valor por defecto del producto.

- EV-01 registro. P-03 sin `local`: COMPLIANT, las fuentes de directorio se miden en sus propios servidores. Si no, NON_COMPLIANT cuando las sondas no vuelven o `LogLevel` de sshd es QUIET, FATAL o ERROR.
- EV-02 factores por zona. Factores: publickey 1 (2 para una clave `-SK` con `verify-required`), password 1, keyboard-interactive 2 cuando la pila auth de sshd exige un módulo de segundo factor (google_authenticator, oath, u2f, duo, radius_auth, yubico, totp; no opcional, no suficiente), y la consola igual según la pila de login. `AuthenticationMethods` eleva la cuenta a su lista más débil. Un canal que escucha en una dirección fuera de P-02 está expuesto; una dirección comodín son todas las del activo. Un resultado de un factor bajo un bloque `Match`: NOT_EVALUABLE por EVIDENCE. Se juzga una vez por requisito (ver abajo).
- EV-03 configuración del bloqueo. Cada vía de contraseña en uso (sshd con password o keyboard-interactive, login y los gestores de sesión) necesita una regla auth de pam_faillock o pam_tally2 que no sea opcional, con `deny` como máximo P-05 y sin desbloqueo automático. Los ajustes de pam_faillock salen de la regla, después de faillock.conf y después de sus valores por defecto (3, 600). Ninguna vía que acepte contraseñas: COMPLIANT.
- EV-04 fallos sin bloqueo. Por cuenta existente, el máximo de fallos en cualquier intervalo de 15 minutos, sumando todos los orígenes. Por encima de P-05 sin bloqueo de la cuenta en la ventana: NON_COMPLIANT. Ningún fallo: COMPLIANT cuando el registro llega a Wazuh.
- EV-05 antigüedad de la credencial. Cuentas que pueden iniciar sesión, con cualquier UID. Una contraseña más antigua que P-04, sin máximo o con un máximo por encima de P-04; ficheros de claves sin cambios durante más de P-04; login.defs que da a las cuentas nuevas un máximo por encima de P-04 o ninguno: NON_COMPLIANT. Un cambio forzado en el siguiente inicio de sesión cuenta como reciente.
- EV-06 inhabilitación tras un aviso. Para cada fila de P-12 de una cuenta que el historial de identidades conoce en este activo: las horas desde el aviso hasta la primera pasada que la vio deshabilitada o borrada o, si sigue habilitada, las horas transcurridas. Por encima de P-06: NON_COMPLIANT. Una cuenta ya deshabilitada la primera vez que se ve tras el aviso solo da un límite superior: dentro de P-06 está a tiempo; por encima, NOT_EVALUABLE por EVIDENCE. Ninguna fila para este activo: COMPLIANT.
- EV-07 canal remoto usado. Inicios de sesión remotos de la ventana por canal (sshd es `ssh`). Un canal que no está en la columna `canal` de P-07: NON_COMPLIANT. Ningún inicio de sesión remoto: COMPLIANT cuando el registro llega a Wazuh.
- EV-08 canales en escucha. Canales de autenticación: sshd (ssh), slapd (ldap, ldaps), xrdp (rdp), vnc, telnetd, vsftpd, proftpd y pure-ftpd (ftp), cockpit-ws (cockpit), webmin; canales de transporte: openvpn, tailscaled. Sin fila en P-07, sin cifrar o activado al arrancar mientras su fila dice `uso_constante` no: NON_COMPLIANT. Estado de arranque desconocido donde la fila lo necesita: NOT_EVALUABLE por EVIDENCE. Ningún canal en escucha: COMPLIANT.
- EV-09 reautenticación (ALTO). Punto `sudo`: NOPASSWD para ALL, `!authenticate` o `timestamp_timeout` por debajo de 0. Punto `sudo:<comando>`: NOPASSWD para ese comando. Punto `su`: pam_wheel con `trust`. Las concesiones del propio root quedan fuera. Un hallazgo en un punto de P-08: NON_COMPLIANT. Un Cmnd_Alias sin definir bajo NOPASSWD: NOT_EVALUABLE por COLLECTION.
- EV-10 falta de uso (ALTO). Cuentas que pueden iniciar sesión, con cualquier UID. El último uso es lo más reciente de wtmp, lastlog y las alertas de inicio de sesión (los inicios con clave sin terminal no están en wtmp); sin uso, la fecha de credencial más reciente. Inactiva más de P-09: NON_COMPLIANT. Sin uso ni fecha de credencial: NOT_EVALUABLE por EVIDENCE.
- EV-11 calidad de la contraseña. La pila password de passwd: pam_pwquality (regla, después pwquality.conf y drop-ins; por defecto minlen 8, dictcheck 1); si no, pam_cracklib (minlen 9, diccionario siempre); si no, pam_unix (minlen 6 con obscure, si no 1). Clases: minclass o el número de créditos negativos, el mayor. Historial: pam_pwhistory (por defecto 10) o `remember` de pam_unix. Un criterio por debajo de su mínimo de P-10: NON_COMPLIANT.
- EV-12 exposición antes de autenticarse. Según la configuración, sin abrir ninguna conexión. sshd sin instalar: COMPLIANT. Exposiciones: `sshd:version_software` siempre, `sshd:version_distribucion` con DebianBanner activado, `sshd:version_addendum`, `sshd:banner_previo`. Una que no está en P-11: NON_COMPLIANT.

## Decisiones sobre requisitos

op.acc.6 decide algunos requisitos por sí mismo, solo donde el requisito se aplica por nivel; una decisión sustituye a la agregación de sus evidencias y a cualquier atestación.

- P-01 sin definir o distinto de R1 a R4: los siete requisitos de mecanismo quedan NOT_EVALUABLE por CONFIGURATION y cuentan en contra; ninguna atestación prueba un refuerzo que nadie ha elegido. Definido: los requisitos de los demás mecanismos son NOT_APPLICABLE.
- EV-02 por requisito. r8.1: falla un inicio de sesión desde fuera de P-02 con un factor, o un canal expuesto que acepta un factor. r1.1: lo mismo para inicios de sesión y canales que usan contraseña. r2.1: falla cualquier inicio de sesión o canal con un factor. El veredicto de EV-02 es el peor de los requisitos aplicables.

## No se mide

- Los certificados (R3, R4) y el aviso de último acceso (r5.2) no dejan registro en el activo; se juzgan por atestación.
- La autenticación de directorio y de aplicación. El control lee PAM, sshd y sudo de cada activo; los servidores de directorio se miden como activos propias.
