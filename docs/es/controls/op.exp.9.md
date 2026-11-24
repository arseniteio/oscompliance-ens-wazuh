# op.exp.9 Registro de la gestión de incidentes

op.exp.9 juzga los datos de cada incidente del registro de op.exp.7: los eventos que lo causaron, sus informes, las acciones de emergencia y los cambios de sistema que provocó, las evidencias capaces de sostenerse ante un tribunal y la revisión posterior de los eventos auditables.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.9. Definición: [`catalog/controls/ens/op.exp.9.json`](../../../catalog/controls/ens/op.exp.9.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 9.1 informes, acciones y cambios registrados | B/M/A | EV-01 a EV-04, EV-09 |
| 9.2 evidencias con valor legal | B/M/A | EV-05, EV-07, EV-09 |
| 9.3 eventos auditables revisados tras los incidentes | B/M/A | EV-08, EV-09 |

## Fuentes

El registro de incidentes es P-13 de op.exp.7 ([op.exp.7](op.exp.7.md)). Además:

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de Wazuh del activo | alertas de las horas previas a cada incidente y de cada uno de sus días | EV-01, EV-07 |
| alertas de respuesta activa | acciones de emergencia | EV-03 |
| alertas de FIM y `package_transaction` ([op.exp.5](op.exp.5.md)), P-10 de op.exp.5 | cambios durante cada incidente y sus peticiones | EV-04 |
| registros de alertas sellados del manager ([op.exp.7](op.exp.7.md)) | | EV-05 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 sistema de registro de incidentes | documental; el registro es P-13 de op.exp.7 | |
| P-02 fases de los informes `fase \| contenido_minimo \| exigible_desde_horas` | | EV-02 |
| P-03 composición de la evidencia legal | documental | |
| P-04 criterios de relevancia jurídica | documental; el registro marca `relevancia_juridica` | |
| P-05 custodia de las evidencias | documental | |
| P-06 conservación de las evidencias | documental | |
| P-07 revisión de eventos auditables `severidad \| plazo_dias \| procedimiento` | | EV-08 |
| P-08, P-09 | documental | |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp9`; incidentes de los últimos 90 días que afectan al activo.

- EV-01 eventos de origen. Las alertas del activo de las 24 horas previas a cada fase inicial deben seguir en el índice.
- EV-02 informes. Un incidente cerrado debe tener cada fase de P-02 que su duración hace exigible (`exigible_desde_horas`).
- EV-03 acciones de emergencia. Como EV-06 de op.exp.7.
- EV-04 cambios de sistema. Los cambios del activo entre las fases inicial y final deben estar cubiertos por peticiones de P-10 de op.exp.5.
- EV-05 evidencias selladas. Un incidente con `relevancia_juridica` en `si` debe llevar `referencia` y tener cada día sellado en el manager.
- EV-07 registros del periodo conservados. Cada día de un incidente con relevancia jurídica, o aún abierto, debe conservar alertas del activo en el índice.
- EV-08 eventos auditables revisados. Un incidente cerrado cuya severidad tiene fila en P-07 debe rellenar `revision_eventos` dentro de `plazo_dias` desde su cierre.
- EV-09 registro completo. Un incidente debe llevar `referencia`, su fase inicial y, una vez cerrado, su fase final.

## No se mide

- La cadena de custodia. Los accesos al repositorio de custodia no dejan ningún hecho. Queda declarada en P-05.
