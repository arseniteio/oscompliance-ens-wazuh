# op.exp.6 Protección frente a código dañino

op.exp.6 juzga que cada activo ejecuta su antimalware con firmas actualizadas y los ajustes correctos, que las detecciones se resuelven, que todo el sistema se analiza con regularidad, que las rutas críticas se comprueban al arrancar y, en ALTA, la lista de aplicaciones permitidas y la capa EDR que aporta Wazuh: reputación, reglas de contenido, detección de rootkits y contención automática. Wazuh no es el antimalware: muestra que existe, funciona y está bien configurado.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.6. Definición: [`catalog/controls/ens/op.exp.6.json`](../../../catalog/controls/ens/op.exp.6.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 6.1 prevención y reacción | B/M/A | EV-01, EV-04, EV-10, EV-11 |
| 6.2 antimalware en cada activo | B/M/A | EV-01 |
| 6.3 ficheros externos analizados antes de usarlos | B/M/A | EV-12 |
| 6.4 bases de detección actualizadas | B/M/A | EV-02 |
| 6.5 ajustes correctos y protección en tiempo real | B/M/A | EV-03 |
| r1.1 análisis completo periódico | M/A | EV-05 |
| r2.1 funciones críticas comprobadas al arrancar | M/A | EV-06 |
| r3.1 lista de aplicaciones permitidas | A | EV-07 |
| r4.1 EDR | A | EV-08 a EV-11 |
| r5.1, r5.2 | ninguno | EV-12, EV-03 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| hecho `malware_protection` | productos y si se ejecutan, firmas de ClamAV, ajustes y último análisis completo, fapolicyd, scripts de respuesta activa, YARA | EV-01 a EV-03, EV-05, EV-07, EV-09, EV-11 |
| alertas de ClamAV, reglas 52502 y 52511 | detecciones, y la misma detección repetida | EV-04 |
| `wazuh_agent_config` | rutas de FIM y `scan_on_start`, rootcheck, integraciones del manager, respuestas activas que envía el manager | EV-06, EV-08, EV-10, EV-11 |
| alertas de VirusTotal, regla 87105 | ficheros que VirusTotal marca | EV-08 |
| alertas de USB, regla 81101 | almacenamiento extraíble conectado | EV-12 |

Wazuh decodifica ClamAV desde syslog: `LogSyslog` debe estar activado para que EV-04 vea las detecciones.

### `malware_protection`

Uno por pasada: `products` (`product`, `running`) entre clamav, mdatp, falcon-sensor, sophos-spl, eset, sentinelone y trendmicro-ds; `signatures`, la hora de compilación de la base diaria de ClamAV; `enabled_settings`, los ajustes activados (`proteccion_tiempo_real`: clamonacc en marcha u `OnAccessIncludePath` definido; `actualizacion_automatica_firmas`: freshclam en marcha; `analisis_comprimidos`: `ScanArchive` no desactivado; `registro_syslog`: `LogSyslog` activado); `last_scan`, el `End Date` más reciente de un resumen de clamscan en `/var/log/clamav/*.log`; `allowlist`, fapolicyd como `enforcing`, `permissive`, `stopped` o `absent`; `responses`, los scripts de `/var/ossec/active-response/bin`; `yara`, el script y el binario de YARA presentes.

### `wazuh_agent_config`, campos adicionales

`syscheck_scan_on_start`, `rootcheck_disabled`, `integrations` (en el hecho del propio manager: virustotal y otras) y `active_responses` (scripts de `shared/ar.conf`, sin los reinicios de Wazuh).

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 producto antimalware por tipo de activo | documental | |
| P-02 antimalware que se espera en marcha | sistema; integrado por tipo de sistema | EV-01 |
| P-03 horas de antigüedad máxima de las firmas | | EV-02 |
| P-04 ajustes esperados `ajuste \| valor` | `si` o `no` | EV-03 |
| P-05 rutas de entrada de ficheros externos | documental | |
| P-06 días entre análisis completos | | EV-05 |
| P-07 rutas críticas comprobadas al arrancar | sistema; integradas por tipo de sistema | EV-06 |
| P-08 aplicaciones permitidas | documental | |
| P-09 capacidades EDR `capacidad \| activada \| alcance` | `virustotal`, `yara`, `rootcheck`, `active_response` | EV-08 a EV-11 |
| P-10 política de dispositivos extraíbles | `bloqueados`, `analisis` o `lectura` | EV-12 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp6`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION.

- EV-01 antimalware presente. Cada producto de P-02 debe ejecutarse; si no, NON_COMPLIANT. Sin ningún antimalware: NON_COMPLIANT.
- EV-02 firmas. La base diaria de ClamAV debe haberse compilado dentro de P-03 horas. Otro producto: NOT_EVALUABLE por COLLECTION, no se leen sus firmas.
- EV-03 ajustes. Cada fila de P-04 debe coincidir con lo observado.
- EV-04 detecciones. Una detección repetida (regla 52511) en la ventana: NON_COMPLIANT, la infección no se ha resuelto. Las demás detecciones se listan. ClamAV sin registrar en syslog: NOT_EVALUABLE por COLLECTION.
- EV-05 análisis completo. El último análisis completo debe haber terminado dentro de P-06 días.
- EV-06 comprobaciones al arrancar. FIM debe analizar al arrancar y cubrir cada ruta de P-07, y rootcheck debe ejecutarse.
- EV-07 lista de permitidas. fapolicyd debe estar en `enforcing`.
- EV-08 reputación. Cuando P-09 activa `virustotal`, el manager debe tener la integración con VirusTotal y el activo FIM activado. Se listan los ficheros marcados en la ventana.
- EV-09 reglas de contenido. Cuando P-09 activa `yara`, su script y su binario deben estar en el activo.
- EV-10 actividad sospechosa. Cuando P-09 activa `rootcheck`, debe ejecutarse.
- EV-11 contención. Cuando P-09 activa `active_response`, el manager debe enviar al menos una y cada script debe estar en el activo.
- EV-12 ficheros externos. Almacenamiento USB conectado en la ventana con P-10 en `bloqueados`: NON_COMPLIANT. Con `analisis`, la protección en tiempo real debe estar activada. Si no, COMPLIANT.

Una capacidad que P-09 no activa deja su evidencia en NON_COMPLIANT: R4 las pide todas.

## No se mide

- El antimalware de las pasarelas de correo (amavis): el agente solo lee el antimalware de la propia activo.
