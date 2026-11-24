# op.cont.2 Plan de continuidad

op.cont.2 juzga lo que deja registro del plan: su aprobación vigente, los contratos de sus medios alternativos y la formación de su personal; y, como refuerzo que ninguna categoría exige, si cada activo comprueba su integridad al volver de una interrupción.

Niveles: ALTO. Anexo II, apartado 4.6.2. Definición: [`catalog/controls/ens/op.cont.2.json`](../../../catalog/controls/ens/op.cont.2.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 2.1 funciones y actividades | A | EV-01 |
| 2.2 coordinación de medios alternativos | A | EV-01 |
| 2.3 medios alternativos bajo contrato | A | EV-01, EV-04 |
| 2.4 formación de las personas | A | EV-01, EV-06 |
| 2.5 integración con otros planes | A | EV-01 |
| r1.1 plan de emergencia y contingencia | ninguno | |
| r2.1 integridad tras una interrupción | ninguno | EV-03 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| P-01, P-03, P-04, P-05 | registros del plan | EV-01, EV-04, EV-06 |
| hecho `wazuh_agent_config` | directorios de FIM y `scan_on_start` | EV-03 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 aprobaciones `referencia \| version \| fecha_aprobacion \| aprobado_por \| responsable` | | EV-01 |
| P-02 servicios esenciales, P-06 otros planes | documental | |
| P-03 funciones `funcion \| responsable \| suplente \| actividades` | | EV-06 |
| P-04 medios alternativos `medio \| proveedor \| contrato \| vigencia_hasta \| activacion` | | EV-04 |
| P-05 formación `persona \| formacion \| fecha \| vigente_hasta` | | EV-06 |
| P-07 rutas comprobadas tras una interrupción | sistema | EV-03 |
| P-08 meses entre revisiones del plan | | EV-01 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opcont2`.

- EV-01 plan. La `fecha_aprobacion` más reciente de P-01, que no esté en el futuro, dentro de P-08 meses.
- EV-04 contratos. Cada medio de P-04 con un `contrato` y una `vigencia_hasta` no vencida.
- EV-06 formación. Cada `responsable` y `suplente` de P-03 con una fila de P-05 cuyo `vigente_hasta` no ha vencido; los nombres se comparan sin mayúsculas ni acentos.
- EV-03 integridad tras una interrupción. FIM activado con `scan_on_start`, y cada ruta de P-07 bajo un directorio de FIM.

## No se mide

- EV-02, EV-05, EV-07 y EV-08: ninguna fuente produce un veredicto para ellas.
