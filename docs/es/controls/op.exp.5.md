# op.exp.5 Gestión de cambios

op.exp.5 compara los cambios que ocurren de verdad en cada activo con el registro de cambios que la organización mantiene en Configuración: cada cambio necesita una petición aprobada, las peticiones llevan información suficiente, las de alto riesgo las aprueba antes el responsable de seguridad, el servicio sigue en marcha, la documentación se actualiza y, en ALTA, existe un punto de reversión.

Niveles: MEDIO, ALTO. Anexo II, apartado 4.3.5. Definición: [`catalog/controls/ens/op.exp.5.json`](../../../catalog/controls/ens/op.exp.5.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 5.1 peticiones registradas y numeradas | M/A | EV-01, EV-02 |
| 5.2 información suficiente para autorizar | M/A | EV-03 |
| 5.3 pruebas en una preproducción equivalente | M/A | EV-05 |
| 5.4 aprobación previa de los cambios de alto riesgo | M/A | EV-04 |
| 5.5 pruebas de aceptación y documentación | M/A | EV-06, EV-07 |
| r1.1 reversión prevista | A | EV-07, EV-09 |
| r1.2 fallos notificados al responsable de seguridad | A | atestación (P-ATT) |
| r1.3 cambios documentados con su impacto de seguridad | A | EV-03 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de FIM (`syscheck`, [op.acc.2](op.acc.2.md)) | ficheros cambiados, cuándo | EV-01, EV-02, EV-07, EV-09 |
| registros `package_transaction` ([op.exp.4](op.exp.4.md)) | cambios de software, cuándo y por quién | EV-01, EV-02, EV-05, EV-07, EV-09 |
| `wazuh_agent_config` | FIM activado en el activo | EV-01 |
| `unit_snapshot` ([op.exp.3](op.exp.3.md)), campo `failed` | servicios fallidos ahora | EV-07 |
| alertas de dpkg, regla 2902 | versiones instaladas en el activo de preproducción | EV-05 |
| `snapshot_list` ([op.exp.4](op.exp.4.md)) | puntos de reversión | EV-09 |
| P-10 | el registro de cambios | EV-02 a EV-04, EV-06, EV-07 |

Un cambio es una alerta de FIM o una transacción de apt de la ventana. Su hora es la de la alerta o la del inicio de la transacción.

### `unit_snapshot`, campo adicional

`failed`: los servicios que lista `systemctl list-units --type=service --state=failed`.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 sistema de gestión de cambios `herramienta \| ubicacion \| prefijo_referencia` | | EV-03 |
| P-02 columnas que debe rellenar una petición | | EV-03 |
| P-03 criterios de alto riesgo | documental | |
| P-04 responsable de seguridad `nombre \| cuenta` | | EV-04 |
| P-06 documentos de configuración `documento \| ubicacion \| plazo_dias` | | EV-06 |
| P-07 canal de notificación de fallos | documental | |
| P-09 horas tras un cambio en las que un fallo es efecto suyo | | EV-07 |
| P-10 registro de cambios | una petición por fila, columnas abajo | EV-02 a EV-04, EV-06, EV-07 |
| P-06 de op.exp.4, pares de preproducción | la misma declaración | EV-05 |
| P-07 de op.exp.4, mecanismo de reversión | la misma declaración | EV-09 |
| P-ATT atestaciones documentales | r1.2 | |

Columnas de P-10: `peticion | fecha_registro | sistema | descripcion | riesgo | aprobado_por | fecha_aprobacion | ventana_inicio | ventana_fin | estado | documentacion | impacto_seguridad`. `sistema` es un nombre de agente o `*`; `estado` es `registrada`, `aprobada`, `implantada`, `revertida` o `rechazada`; `riesgo` es `alto`, `medio` o `bajo`. Las fechas y horas son `2026-10-20 06:00` (Europe/Madrid) o RFC 3339. Una `ventana_fin` vacía deja la ventana abierta: un cambio estándar.

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp5`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION. Una petición cubre un cambio cuando su `sistema` es el activo o `*`, su `estado` es `aprobada`, `implantada` o `revertida`, se aprobó antes del cambio y su ventana contiene el cambio.

- EV-01 cambios reales. FIM activado y el historial de apt leído: COMPLIANT con los cambios de la ventana. FIM desactivado: NON_COMPLIANT.
- EV-02 cambios sin petición. Un cambio que ninguna petición cubre: NON_COMPLIANT con los cambios.
- EV-03 información de la petición. Cada petición autorizada del activo cuya ventana toca los últimos 90 días debe rellenar las columnas de P-02, su `peticion` debe empezar por el prefijo de P-01 si lo tiene y, en ALTA, debe rellenar `impacto_seguridad`; si no, NON_COMPLIANT.
- EV-04 aprobación de alto riesgo. Cada petición de alto riesgo del activo implantada en los últimos 90 días debe aprobarla la cuenta de P-04 antes de abrirse su ventana; si no, NON_COMPLIANT.
- EV-05 preproducción. Como EV-08 de op.exp.4 sobre el software de la ventana, con los pares de P-06 de op.exp.4.
- EV-06 documentación. Cada petición implantada hace más de `plazo_dias` de su documento debe nombrar en `documentacion` los documentos de P-06 que ha actualizado; si no, NON_COMPLIANT.
- EV-07 estabilidad. Un servicio fallido ahora, con un cambio en las P-09 horas anteriores, cuya petición no está `revertida`: NON_COMPLIANT. Sin systemd: NOT_EVALUABLE por COLLECTION.
- EV-09 punto de reversión. Como EV-09 de op.exp.4, sobre cada cambio de la ventana, con P-07 de op.exp.4.

EV-05 de op.exp.3 juzga las ediciones de la configuración de seguridad (cambios de FIM bajo P-04 de op.exp.3) frente al mismo registro.

## No se mide

- Los fallos notificados al responsable de seguridad. La comunicación no deja ningún hecho. r1.2 se acredita por atestación.
