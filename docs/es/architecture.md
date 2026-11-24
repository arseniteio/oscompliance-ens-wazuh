# Arquitectura

OSCompliance ENS mide los controles del Esquema Nacional de Seguridad (Real Decreto 311/2022, Anexo II) sobre un despliegue de Wazuh existente. Añade dos binarios y cinco reglas de Wazuh. No sustituye ningún componente de Wazuh ni ejecuta su propio canal de recogida, base de datos o bus de mensajes.

En el activo auditado, `oscompliance-agent` escribe `facts.ndjson` y el agente de Wazuh lo envía junto con los registros de autenticación y auditoría, FIM, SCA e inventario. En el host del manager, las reglas 119000-119006 indexan los hechos. Cada 15 minutos, `oscompliance-engine` lee el indexer, escribe en él los veredictos y actualiza el `agent.conf` de los grupos mediante la API de Wazuh. El plugin Power ENS muestra los veredictos en el dashboard.

## Componentes

`oscompliance-agent` se ejecuta en cada activo Linux auditado, manager incluido. Lee el estado local y añade hechos a `/var/log/oscompliance/facts.ndjson`. No juzga, no guarda política y no abre ninguna conexión de red.

El agente de Wazuh envía ese fichero junto con los registros de autenticación y auditoría, el inventario, FIM y SCA. Nada en él es específico de OSCompliance.

Las reglas de Wazuh 119000 a 119006 se ejecutan en el manager. Indexan hechos, la sonda de autenticación, eventos de servicio y accesos auditados. No llevan ningún veredicto.

`oscompliance-engine` se ejecuta en el manager maestro, uno por despliegue. Llega a los indexers por la red, con conmutación entre ellos, y a la API de Wazuh en su propio host. Juzga cada evidencia, requisito y control y escribe los veredictos. No cambia nada en los activos auditados salvo mediante la configuración de grupo.

El plugin Power ENS se ejecuta en el dashboard de Wazuh. Guarda los parámetros de la organización y muestra veredictos e informes. No juzga.

## Flujo de datos

1. Recoger. Cron ejecuta el agente cada hora, y el barrido del sistema de ficheros una vez al día. Cada colector lee un área (cuentas, PAM, sshd, sudoers, puertos en escucha, paquetes, copias y otras) y emite hechos. Un colector cuya salida no ha cambiado no emite nada; cada hecho se envía de nuevo al menos cada tres días. Cada pasada termina con un hecho `agent_pass`.
2. Enviar. El agente de Wazuh lee `facts.ndjson` como localfile JSON. La regla 119001 indexa cada hecho válido en `wazuh-alerts-*`. Las reglas aceptan un hecho solo desde ese fichero, así que un usuario local no puede falsificarlo mediante syslog.
3. Leer. El motor lee, en cada pasada: los hechos de cada activo en la ventana, las alertas de Wazuh (autenticación, sudo, FIM, SCA, auditoría, antimalware, detección de vulnerabilidades), el inventario de Wazuh (`wazuh-states-inventory-*`, `wazuh-states-vulnerabilities-*`), los keepalive de los agentes (`wazuh-monitoring-*`), la configuración del manager mediante la API de Wazuh, los registros DNS para los controles de correo y los parámetros que el plugin guarda en `wazuh-ens-configuration`.
4. Juzgar. El juez de cada control convierte fuentes y parámetros en un veredicto por activo y evidencia. Las evidencias se suman en requisitos y los requisitos en una puntuación de control ([Veredictos](verdicts.md)).
5. Escribir. Los veredictos van a `oscompliance-verdicts`; el historial de identidades por cuenta, a `oscompliance-identity-history`.
6. Configurar. Algunos parámetros nombran rutas que los agentes deben leer o vigilar (rutas de ACL, vigilancias de auditoría, registros de servicio, directorios de FIM). El motor las escribe en una región marcada del `agent.conf` de cada grupo ENS mediante la API de Wazuh, y registra cada cambio en `oscompliance-config-history`. Wazuh distribuye el fichero a los agentes. El motor también crea los grupos del alcance ENS que no existen, y les añade los agentes cuyo `agent_pass` pide uno de ellos.
7. Mostrar. El plugin lee la última pasada de cada activo y el último veredicto de control de cada día, y presenta los motivos a partir de sus códigos en el idioma del usuario.

## Principios de diseño

- Los agentes emiten hechos, nunca veredictos. El activo auditado no decide si cumple. Un agente comprometido o mal configurado puede dejar de informar; no puede informar de que cumple.
- Lo que no se puede demostrar no cumple. Los datos que faltan son NOT_EVALUABLE, y un requisito con una evidencia NOT_EVALUABLE es NON_COMPLIANT, no evidenciado. El silencio nunca se lee como cumplimiento: un control que juzga inicios de sesión primero demuestra que el registro de autenticación llega a Wazuh.
- Primero Wazuh. Si Wazuh ya recoge algo (inicios de sesión, FIM, SCA, inventario, vulnerabilidades, auditd), el motor lo lee del índice. El agente solo cubre lo que Wazuh no ve.
- Una definición por control. `catalog/controls/ens/<control>.json` guarda requisitos, niveles, evidencias, parámetros y campos de informe. El motor lo integra; el plugin incluye una copia y sus pruebas fallan si difieren.
- La política vive en un solo lugar. Los agentes solo guardan rutas. Cada valor de política es un parámetro del plugin, que el motor lee en cada pasada.
- Juicio sin estado. Cada pasada juzga el estado actual a partir del índice. Repetir una pasada da los mismos veredictos.

## El manager se audita

El manager es un activo como cualquier otra y recibe todos los controles. Ejecuta el agente con su propio `ossec.conf` leyendo `facts.ndjson`, y lee las rutas que escribe el motor del `agent.conf` de un grupo ENS. Su inventario y su configuración vienen de la API de Wazuh. Las medidas que la norma exige en algún punto del sistema, en lugar de en cada activo, se juzgan en el manager: cuando ningún activo las tiene, el manager asume el incumplimiento.

## Escala

Medido con `oscompliance-fleetsim`, que carga una flota sintética en un indexer de Wazuh y ejecuta pasadas reales. Una pasada sobre 1.000 agentes hace unas 760 peticiones y tarda de 6 a 8 segundos. Una pasada sobre 10.000 agentes hace unas 7.200 peticiones y tarda de 100 a 130 segundos.

El motor lee en bloques de 500 agentes con agregaciones compuestas, ejecuta los controles en paralelo, mantiene como máximo cuatro peticiones en curso y reintenta ante HTTP 429. El coste crece linealmente con la flota. El intervalo por defecto de 15 minutos deja mucho margen con 10.000 agentes.

En el lado del agente, una pasada lee ficheros locales y ejecuta unos pocos comandos (`sshd -T`, `systemctl`, el gestor de paquetes); los colectores sin cambios no envían nada. Un activo estable envía unos 115 hechos al día.

## Estructura del repositorio

| Ruta | Contenido |
|---|---|
| `catalog/controls/ens/` | definiciones de los controles |
| `catalog/schemas/facts/`, `catalog/fact/` | esquemas de hechos y sus tipos Go |
| `catalog/schemas/verdicts/` | esquema de veredictos |
| `catalog/messages/` | textos de los motivos, en inglés y español |
| `catalog/templates/`, `catalog/system-types.json` | valores de parámetros integrados por tipo de sistema |
| `catalog/wazuh/` | reglas, fragmento de agent.conf, roles del indexer y de la API, script de usuarios, unidad de servicio y fichero de compose del motor |
| `agent/` | `oscompliance-agent` y sus colectores |
| `engine/` | `oscompliance-engine`, fuentes, jueces, agregación, configuración de grupo; `oscompliance-policy`; `oscompliance-fleetsim` |
| `docs/` | esta documentación, en `en/` y `es/` |
| `ci/`, `.github/workflows/` | empaquetado y CI |

## Añadir un control

1. `catalog/`: la definición del control, los esquemas de hechos y tipos Go, los mensajes de motivo en los dos idiomas, las plantillas.
2. `agent/`: colectores para lo que Wazuh no recoge ya.
3. `engine/internal/controls/ens/<control>`: el juez, con pruebas.
4. `docs/en/controls/<control>.md` y `docs/es/controls/<control>.md`: la página, con las secciones que tiene cada control.
5. power-ens-wazuh: `npx tsx config/sync-catalog.ts` para incluir el catálogo.
6. Laboratorio: llegan los hechos, el motor escribe veredictos, el plugin los muestra.
