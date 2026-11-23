# Agente de Windows

El agente OSCompliance para Windows recoge el mismo tipo de hechos que el agente de Linux y los escribe en `C:\ProgramData\oscompliance\facts.ndjson`. El agente de Wazuh envía el fichero al manager y el motor juzga los hechos con los mismos controles. El plugin muestra las máquinas Windows como cualquier otra.

El agente de Windows solo se ha probado en el laboratorio, todavía no en una máquina física. Pruébalo en una máquina de pruebas antes de desplegarlo.

## Requisitos

- Windows Server 2016, 2019, 2022 o 2025, o Windows 10 u 11, de 64 bits.
- Windows PowerShell 5.1, incluido en todas las versiones soportadas.
- El agente de Wazuh 4.x instalado en `C:\Program Files (x86)\ossec-agent` y registrado en el manager.
- Un PowerShell elevado para la instalación. El agente se ejecuta como SYSTEM.

## Instalar

Ejecuta un solo comando desde un PowerShell elevado, igual que `install.sh agent --group ens` en Linux:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((irm https://github.com/arseniteio/oscompliance-ens-wazuh/releases/latest/download/install.ps1))) -Group ens
```

El script descarga el paquete de Windows de la versión y lo comprueba con `SHA256SUMS`. Para revisar los ficheros antes de ejecutar nada, descarga `oscompliance-ens-wazuh-<versión>-windows-amd64.zip` y `SHA256SUMS`, comprueba el zip con `Get-FileHash`, descomprímelo y ejecuta `.\install.ps1 -Group ens` desde la carpeta descomprimida: el script usa el binario que tiene al lado. `-Release 1.3.0` instala otra versión. Ejecuta el mismo comando otra vez para actualizar.

El script:

- copia `oscompliance-agent.exe` a `C:\Program Files\OSCompliance`;
- crea `C:\ProgramData\oscompliance` y su carpeta `state` con acceso solo para SYSTEM y Administradores;
- escribe el grupo pedido en `C:\ProgramData\oscompliance\agent.json`, que el motor lee para añadir la máquina a ese grupo;
- añade el fichero de hechos al `ossec.conf` local del agente de Wazuh y lo reinicia, para que los primeros hechos lleguen al manager antes que la configuración del grupo;
- registra el origen `oscompliance-agent` en el registro Aplicación;
- programa `\OSCompliance\agent-pass` cada hora y `\OSCompliance\audit-guard` cada 2 minutos, ambas como SYSTEM, y lanza la primera pasada.

El motor añade la máquina al grupo en 15 minutos y escribe en la configuración del grupo un bloque `<agent_config os="Windows">` con el fichero de hechos, el canal de Microsoft Defender, las rutas gestionadas y las rutas de integridad de ficheros. Un grupo con máquinas Linux y Windows recibe un bloque por sistema operativo, así que ninguna máquina lee las rutas de la otra. Para configurarlo a mano, `wazuh/agent.conf.windows.fragment.xml` contiene las dos entradas `localfile`.

El manager necesita las reglas de esta versión: la regla 119007 decodifica el fichero de hechos de Windows y la 119008 alerta de las vigilancias de lectura suspendidas.

## Comprobar

```powershell
Get-ScheduledTask -TaskPath \OSCompliance\
Get-Content C:\ProgramData\oscompliance\facts.ndjson -Tail 5
& 'C:\Program Files\OSCompliance\oscompliance-agent.exe' -collect device -full
```

El último comando ejecuta un colector y escribe su hecho al momento.

## Qué lee el agente

| Colector | Hechos | Lee |
|---|---|---|
| `identity` | identity_record, identity_snapshot | cuentas locales (`Get-LocalUser`), o cuentas de Active Directory en un controlador de dominio (`Get-ADUser`, como máximo 20.000) |
| `groups` | group_record, group_snapshot | grupos locales y sus miembros por ADSI, o grupos de Active Directory en un controlador de dominio |
| `config` | config_file, config_snapshot | `secedit /export` (directiva de cuentas, de auditoría, derechos de usuario y opciones de seguridad), `auditpol /backup`, valores de seguridad del registro (UAC, RDP, LSA, firma SMB, WinRM, tamaño de los registros de eventos, SCHANNEL) |
| `device` | device_security | tipo de chasis, directiva de bloqueo por inactividad, protección BitLocker de la unidad del sistema, servidores DNS, carga, memoria |
| `firewall` | firewall_snapshot | perfiles del Firewall de Windows y sus acciones por defecto |
| `malware` | malware_protection | estado y ajustes de Microsoft Defender, aplicación de AppLocker, scripts de respuesta activa de Wazuh |
| `timesync` | time_sync | tipo, orígenes y sincronización de W32Time |
| `updates` | update_status | búsqueda sin conexión de Windows Update de actualizaciones pendientes y de seguridad, última búsqueda correcta |
| `transactions` | package_transaction, transaction_snapshot | historial de Windows Update |
| `packages` | package_selection | programas instalados según las claves Uninstall del registro y características de servidor instaladas |
| `units` | unit_snapshot | servicios en ejecución y servicios automáticos que se pararon con error |
| `listening` | listening_socket, listening_snapshot | puertos TCP en escucha y puertos UDP fuera del rango dinámico, su proceso y su servicio |
| `neighbours` | neighbour_snapshot | tabla de vecinos IPv4 (`Get-NetNeighbor`), sin entradas sin resolver, de difusión, de multidifusión ni de relleno de QEMU |
| `wazuh` | wazuh_agent_config | ossec.conf y el agent.conf compartido |
| `acl` | acl_record, acl_snapshot | propietario y reglas de acceso de las `acl_paths` |
| `audit` | audit_watch_snapshot | añade y quita las entradas SACL de las vigilancias de lectura y de cambio |
| `-guard-audit` | file_access | evento 4663 del registro Seguridad sobre las rutas vigiladas |

Windows traduce la salida de algunas herramientas. El agente lee `auditpol` por GUID de subcategoría, `secedit` por clave y `w32tm` por posición de línea, así que un Windows en español da los mismos hechos que uno en inglés. Los nombres de grupo también se traducen: el perfil `windows` lista los dos nombres de cada grupo integrado.

## Lecturas auditadas y volumen

Windows no limita el número de eventos 4663. El agente acota el volumen igual que en Linux:

- El colector `audit` añade una entrada SACL para Todos, solo de éxito, en cada vigilancia de lectura (`ReadData`) y de cambio (escritura, anexado, borrado, cambio de permisos y de propietario). Anota las entradas que añadió en `state\sacl-managed.json` y quita solo esas cuando la configuración del grupo deja de pedirlas. Activa la auditoría de éxito de la subcategoría Sistema de archivos.
- `-guard-audit` lee los eventos 4663 posteriores a su marcador, del más antiguo al más reciente y como máximo 2.000 por ejecución, y escribe un hecho `file_access` por cada acceso bajo una vigilancia. Los servicios que se ejecutan como SYSTEM, LOCAL SERVICE o NETWORK SERVICE aparecen con ese nombre y no con la cuenta del equipo.
- Cuando una vigilancia de lectura registra más de `audit_read_limit` lecturas por minuto (60 por defecto) desde la última ejecución, la guarda quita su entrada de lectura durante una hora y escribe el evento 1006 en el registro Aplicación. La regla 119008 alerta de ello con nivel 10.

El agente de Wazuh no reenvía el evento 4663: su consulta por defecto lo excluye, y el agente reenvía los accesos como hechos.

## Desinstalar

```powershell
& ([scriptblock]::Create((irm https://github.com/arseniteio/oscompliance-ens-wazuh/releases/latest/download/install.ps1))) -Uninstall
```

El script también quita la entrada de hechos que añadió a `ossec.conf`. Añade `-Purge` para borrar `C:\ProgramData\oscompliance`. Las entradas SACL que añadió el agente se quedan en las rutas vigiladas; quítalas con `Get-Acl -Audit` y `Set-Acl`.

## Límites

- `op.exp.10` lee los accesos a los almacenes de claves, pero el agente todavía no inventaría certificados ni claves en Windows.
- `op.exp.6` solo recibe las detecciones de Microsoft Defender por su canal de eventos; la evidencia que cuenta detecciones de ClamAV por regla todavía no las cuenta.
- Los inicios de sesión salen de los eventos 4624 de tipo 2, 10 y 11. Los inicios de red (tipo 3), como WinRM y SMB, y los de servicio (tipo 5) no son inicios de sesión de una persona y quedan fuera.
