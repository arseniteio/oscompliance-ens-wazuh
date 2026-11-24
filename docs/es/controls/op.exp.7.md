# op.exp.7 Gestión de incidentes

op.exp.7 compara las detecciones de Wazuh con el registro de incidentes que la organización mantiene en Configuración: las alertas relevantes se convierten en incidentes, los incidentes se escalan, se contienen y se cierran dentro de sus plazos, se informa a las personas y organismos adecuados, se conservan las evidencias y se registran las lecciones. op.exp.9 juzga el mismo registro por sus datos.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.7. Definición: [`catalog/controls/ens/op.exp.7.json`](../../../catalog/controls/ens/op.exp.7.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 7.1 proceso de gestión de incidentes | B/M/A | EV-01, EV-02, EV-04 |
| 7.2 incidentes con datos personales | B/M/A | EV-07 |
| r1.1 notificación al CCN-CERT | M/A | EV-08 |
| r2.1 medidas urgentes y evidencias | M/A | EV-05, EV-06 |
| r2.2 recursos para investigar y resolver | M/A | EV-03 |
| r2.3 información a los responsables | M/A | EV-04 |
| r2.4 medidas contra la repetición | M/A | EV-12 |
| r3.1 reconfiguración dinámica | A | EV-09 |
| r3.2 avisos del CCN-CERT | A | EV-10 |
| r4.1 prevención y respuesta automáticas | ninguno | EV-11 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de Wazuh del activo | recuentos por hora iguales o superiores a los niveles de P-01 | EV-01, EV-02 |
| alertas de respuesta activa (`rule.groups: active_response`) | contención ejecutada en el activo | EV-06, EV-09 |
| `wazuh_agent_config` del manager, campos adicionales | días con los registros de alertas sellados (`.sum`), listas CDB y sus fechas | EV-05, EV-10 |
| `wazuh_agent_config`, `malware_protection` | respuestas activas enviadas e instaladas ([op.exp.6](op.exp.6.md)) | EV-11 |
| P-13 | el registro de incidentes | EV-02 a EV-09, EV-12 |

### `wazuh_agent_config`, campos adicionales

`sealed_days`: los días de los últimos 400 cuyo registro de alertas tiene firma (`logs/alerts/<año>/<mes>/ossec-alerts-<día>.log.sum`); `lists`: las listas CDB de `etc/lists` con `name` y `modified`. Ambos están vacíos fuera del manager.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 clasificación `categoria \| severidad \| nivel_minimo \| notificable_ccn_cert \| criterio` | el nivel más bajo de Wazuh de cada severidad | EV-01, EV-02, EV-08 |
| P-02 escalado `severidad \| destinatario \| plazo_horas \| canal` | | EV-02, EV-04 |
| P-03 sistema de gestión de incidentes | obligatorio; si no, EV-02 no queda evidenciada | EV-02 |
| P-04 responsables de información y servicio `sistema \| responsable_informacion \| responsable_servicio` | | EV-04 |
| P-05 plazos de respuesta `severidad \| contencion_horas \| resolucion_horas` | | EV-03 |
| P-06 ventanilla única del CCN-CERT | obligatorio; si no, EV-08 no queda evidenciada | EV-08 |
| P-07 sistemas con datos personales `sistema \| tratamientos` | | EV-07 |
| P-08 evidencias que conservar | documental | |
| P-09 acciones de respuesta automática | documental | |
| P-10 elementos de reconfiguración dinámica | obligatorio; si no, EV-09 no queda evidenciada | EV-09 |
| P-11 avisos del CCN-CERT `canal \| responsable \| lista_cdb \| plazo_dias` | | EV-10 |
| P-12 reglas no conciliadas `regla \| motivo` | | EV-02 |
| P-13 registro de incidentes | una fila por fase | EV-02 a EV-09, EV-12 |

Columnas de P-13: `incidente | fase | fecha | severidad | sistemas | clasificacion | escalado_a | notificado_a | datos_personales | notificacion_ccn_cert | relevancia_juridica | medidas_mejora | referencia | revision_eventos`. `fase` es `inicial`, `intermedio` o `final`; `sistemas` son nombres de agente separados por comas; las fechas, como en op.exp.5 (Europe/Madrid salvo que lleven zona).

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp7`. Un incidente son las filas que comparten `incidente`; afecta al activo cuando `sistemas` la nombra. Se juzgan los incidentes de los últimos 90 días.

- EV-01 detección. Alertas del activo iguales o superiores al nivel más bajo de P-01 en la ventana, por severidad: COMPLIANT. P-01 vacío: NOT_EVALUABLE. Sin alertas de un activo que no ha informado en la ventana: NOT_EVALUABLE por COLLECTION.
- EV-02 conciliación. Cada hora con una alerta igual o superior al nivel de una severidad, fuera de P-12, necesita un incidente del activo abierto dentro del `plazo_horas` de esa severidad en P-02; si no, NON_COMPLIANT.
- EV-03 tiempos. La fase intermedia dentro de `contencion_horas` y la final dentro de `resolucion_horas` desde la inicial, por severidad de P-05; un incidente abierto que los supera también falla.
- EV-04 escalado e información. `escalado_a` debe contener el destinatario de P-02 para la severidad, y `notificado_a` los responsables de P-04 de cada sistema.
- EV-05 evidencias conservadas. Cada día de un incidente del activo debe tener su registro de alertas sellado en el manager.
- EV-06 medidas urgentes. Un incidente alto o crítico necesita una respuesta activa en el activo entre sus fases inicial y final, o una fase intermedia.
- EV-07 datos personales. P-07 vacío: NOT_EVALUABLE; una organización sin esos sistemas declara una fila `ninguno`. Un incidente en un sistema de P-07 debe rellenar `datos_personales`; si es `si`, `notificado_a` debe rellenarse en las 72 horas siguientes a la fase inicial.
- EV-08 CCN-CERT. Un incidente cuya clasificación marca P-01 como notificable debe llevar una fecha en `notificacion_ccn_cert`.
- EV-09 reconfiguración dinámica. Un incidente crítico necesita una respuesta activa en el activo entre sus fases inicial y final.
- EV-10 avisos. La lista CDB de P-11 debe existir en el manager y haberse modificado dentro de `plazo_dias`.
- EV-11 respuesta automática. Como EV-11 de op.exp.6.
- EV-12 mejora. Un incidente cerrado debe rellenar `medidas_mejora`.
