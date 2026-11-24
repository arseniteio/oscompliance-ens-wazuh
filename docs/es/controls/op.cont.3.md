# op.cont.3 Pruebas periódicas

op.cont.3 juzga las pruebas del plan de continuidad: que ejercitan los medios alternativos, que se hacen con la frecuencia prevista para cada tipo y escenario, que cada activo participante volvió dentro de su RTO según la monitorización de Wazuh, y que se corrigen las deficiencias que revelan.

Niveles: ALTO. Anexo II, apartado 4.6.3. Definición: [`catalog/controls/ens/op.cont.3.json`](../../../catalog/controls/ens/op.cont.3.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 3.1 pruebas periódicas y correcciones | A | EV-01 a EV-05 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| P-04 registro de pruebas, P-05 registro de deficiencias | | EV-01, EV-02, EV-05 |
| `wazuh-monitoring-*` | estado del agente cada pocos minutos durante cada prueba y el día siguiente | EV-03, EV-04 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 meses entre pruebas | | EV-01, EV-02 |
| P-02 tipos `tipo \| descripcion \| periodicidad_meses` | | EV-01, EV-02 |
| P-03 escenarios `escenario \| sistemas` | | EV-02 |
| P-04 pruebas `inicio \| fin \| tipo \| escenario \| sistemas \| resultado \| deficiencias \| informe` | `sistemas` son nombres de agente | EV-01 a EV-05 |
| P-05 deficiencias `deficiencia \| prueba \| responsable \| plazo \| estado \| cierre \| version_plan` | `prueba` es la fecha de la prueba | EV-05 |
| P-06 ventanas previstas | documental | |
| P-07 RTO `sistema \| rto_horas \| tolerancia_min` | | EV-04 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opcont3`. Una prueba parcial o un simulacro completo (`parcial`, `simulacro`) es la que ejercita los medios alternativos.

- EV-01 pruebas registradas. P-02 prevé una prueba parcial o un simulacro, y se ha hecho uno dentro de P-01 meses.
- EV-02 periodicidad. La prueba más reciente, la más reciente de cada tipo de P-02 (con sus meses o P-01) y la de cada escenario de P-03, dentro de P-01 meses.
- EV-03 medido. Registros de monitorización del activo en cada prueba parcial o simulacro del periodo en que participó; ninguno: NOT_EVALUABLE.
- EV-04 RTO. En esas pruebas, el tramo más largo en que el activo no estuvo `active`, desde `inicio` hasta un día después de `fin`, dentro de `rto_horas` más `tolerancia_min`, y el activo activa al final. Un activo que no participó en ninguna prueba: COMPLIANT.
- EV-05 deficiencias. Ninguna deficiencia abierta pasada de `plazo` o más antigua que la prueba más reciente, y cada prueba con al menos sus `deficiencias` en P-05.

## No se mide

- EV-06 a EV-08: ninguna fuente produce un veredicto para ellas.
