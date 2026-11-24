# op.mon.2 Sistema de métricas

op.mon.2 juzga los datos que recoge la organización para medir su seguridad: los ciclos de métricas que consolida y valida, los datos que necesitan sus indicadores de incidentes, los recursos que registra y si la medida de cada activo es fiable.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.7.2. Definición: [`catalog/controls/ens/op.mon.2.json`](../../../catalog/controls/ens/op.mon.2.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 2.1 datos de implantación e informe del artículo 32 | B/M/A | EV-01, EV-02, EV-04, EV-05 |
| r1.1 datos de gestión de incidentes | M/A | EV-03 |
| r2.1 eficiencia: horas y presupuesto | M/A | EV-06 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `oscompliance-verdicts` | los veredictos de control de las pasadas anteriores | EV-01, EV-05 |
| P-06 registro de ciclos | | EV-02, EV-06 |
| P-13 de op.exp.7, registro de incidentes ([op.exp.7](op.exp.7.md)) | | EV-03 |
| `wazuh-monitoring-*` | estado del agente | EV-04 |
| hecho `agent_pass` | la pasada de OSCompliance más reciente del activo | EV-04 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 declaración de aplicabilidad `medida \| aplica \| nivel \| refuerzos` | | EV-01 |
| P-02 días de un ciclo | | EV-02, EV-03, EV-06 |
| P-03 días de margen tras un ciclo | | EV-02, EV-06 |
| P-04 indicadores de incidentes | `incidentes_por_tipo`, `incidentes_por_severidad`, `tiempo_medio_contencion`, `tiempo_medio_resolucion`, `notificados_ccn_cert`, `notificados_aepd` | EV-03 |
| P-05 validadores `responsable \| rol \| ambito` | `metricas`, `recursos` o `ambos` | EV-02, EV-06 |
| P-06 ciclos `fecha_consolidacion \| periodo \| implantacion_global \| validado_por \| horas_internas \| horas_externas \| presupuesto` | | EV-02, EV-06 |
| P-07 criterios de recursos | documental | |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opmon2`.

- EV-01 grado de implantación. No evaluable por CONFIGURATION sin P-01. Si no, la media de la puntuación de los veredictos de control aplicables del activo en la ventana, con los controles medidos y las medidas que P-01 declara aplicables. Lee los veredictos que escribieron las pasadas anteriores.
- EV-05 controles no evaluables por falta de parámetros. Lista los controles con alguna evidencia no evaluable por CONFIGURATION en el activo. Es la deuda de configuración como un número que seguir, no un incumplimiento.
- EV-02 ciclos. La fila más reciente de P-06 validada por una persona de P-05 para `metricas` debe quedar dentro de P-02 más P-03 días.
- EV-03 datos de incidentes. Cada incidente de op.exp.7 abierto dentro de P-02 días debe llevar lo que necesita cada indicador de P-04: `clasificacion`, `severidad`, una fase intermedia o final, su fase inicial, `notificacion_ccn_cert` o `datos_personales`.
- EV-04 medida fiable. El agente del activo activo (el manager mientras se ejecuta su análisis) y un `agent_pass` dentro de la ventana.
- EV-06 recursos. Como EV-02, para un validador de `recursos` y una fila con las tres columnas de recursos rellenas.
