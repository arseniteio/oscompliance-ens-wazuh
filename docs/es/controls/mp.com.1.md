# mp.com.1 Perímetro seguro

mp.com.1 juzga los dispositivos de perímetro por sus registros en Wazuh, los flujos que dejan pasar y la revisión de sus reglas; y, en cada activo, las formas de rodear el perímetro: interfaces, pasarelas, túneles y administración desde internet.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.4.1. Definición: [`catalog/controls/ens/mp.com.1.json`](../../../catalog/controls/ens/mp.com.1.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 1.1 perímetro que cruza todo el tráfico | B/M/A | EV-01, EV-03, EV-04, EV-05, EV-07, EV-08 |
| 1.2 flujos autorizados previamente | B/M/A | EV-01, EV-02, EV-06, EV-07, EV-08 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de cada dispositivo de P-01 | horas con alertas, una semana atrás; un dispositivo se identifica por `agent.name`, `predecoder.hostname` o `location` | EV-01, EV-08 |
| alertas de esos dispositivos con `data.action` accept, allow, pass o permit | `data.srcip`, `data.dstip`, `data.protocol`, `data.dstport` | EV-02 |
| `wazuh-states-inventory-interfaces-*`, `-networks-*`, `-protocols-*` | interfaces, direcciones y pasarelas | EV-03, EV-04, EV-05 |
| `wazuh-states-inventory-processes-*` | procesos de herramientas de túnel | EV-05 |
| alertas de autenticación (`sshd`, `authentication_*`) con `data.srcip` | orígenes de los inicios de sesión de cada activo | EV-07 |

El inventario del manager se lee mediante la API de Wazuh (`/syscollector/000/netiface`, `netaddr`, `netproto`, `processes`).

Herramientas de túnel: openvpn, openconnect, vpnc, charon, tailscaled, zerotier-one, ngrok, cloudflared, frpc, chisel, autossh, sshuttle, stunnel, iodine, ptunnel, dns2tcp, gost, tmate, teamviewerd, anydesk, rustdesk.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 dispositivos de perímetro `elemento \| tipo \| ubicacion \| fuente` | | EV-01, EV-02, EV-08 |
| P-02 flujos autorizados `origen \| destino \| protocolo \| puerto \| autorizado_por \| fecha` | CIDR, dirección o `*`; puerto, rango o `*` | EV-02, EV-06 |
| P-03 salidas `salida \| elemento \| pasarela` | | EV-04 |
| P-04 días entre revisiones de reglas | | EV-06 |
| P-05 reglas prohibidas, P-06 ITS de interconexión | documental | |
| P-07 interfaces esperadas | sistema; patrones glob; integradas por tipo de sistema | EV-03 |
| P-08 túneles autorizados | sistema; nombres de interfaz o de proceso | EV-05 |
| P-09 orígenes de internet autorizados para administrar | CIDR o dirección | EV-07 |
| P-10 horas sin registros del perímetro | | EV-01, EV-08 |
| P-11 revisiones de reglas `fecha \| elemento \| responsable \| hallazgos` | | EV-06 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpcom1`.

- EV-01 registros del perímetro. Cada dispositivo de P-01 con una alerta dentro de P-10 horas.
- EV-02 flujos. Cada flujo aceptado de la ventana coincide con una fila de P-02 con `autorizado_por`.
- EV-03 interfaces. Cada interfaz `up` coincide con un patrón de P-07.
- EV-04 salidas. Cada pasarela del activo es una `pasarela` de P-03.
- EV-05 túneles. Ninguna interfaz de túnel activa (tipo tunnel, ppp, tun, tap, wireguard; nombres tun, tap, wg, ppp, ipsec, vti, gre, tailscale, zt) ni herramienta de túnel en marcha fuera de P-08.
- EV-06 reglas. Ninguna fila de P-02 abierta a cualquier origen en todos los puertos o en un puerto de administración (22, 23, 139, 161, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017), y la revisión más reciente de P-11 dentro de P-04 días.
- EV-07 administración desde internet. Ninguna autenticación de la ventana desde una dirección pública fuera de P-09.
- EV-08 continuidad. Ningún dispositivo de P-01 más de P-10 horas sin alertas en la última semana.

## No se mide

- No se informa de las reglas sin tráfico: ninguna fuente las declara de una forma en la que pueda apoyarse un veredicto. EV-06 juzga en su lugar los flujos autorizados y su registro de revisiones.
