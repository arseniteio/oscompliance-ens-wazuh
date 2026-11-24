# op.acc.5 Mecanismo de autenticación (usuarios externos)

op.acc.5 juzga los servicios donde inician sesión personas ajenas a la organización: una sede electrónica, un portal ciudadano, una API pública, una extranet de proveedores. Ningún fichero del sistema dice qué servicio es ni cómo autentica, así que cada servicio escribe sus eventos de autenticación según el contrato de abajo, Wazuh los recoge y el motor los juzga.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.2.5. Definición: [`catalog/controls/ens/op.acc.5.json`](../../../catalog/controls/ens/op.acc.5.json).

## Requisitos

| Requisito | Niveles | Evidencias | Se prueba con |
|---|---|---|---|
| 5.1, 5.2, 5.3, 5.9 | B/M/A | | P-ATT |
| 5.4 cambio periódico de credenciales | B/M/A | EV-04 | P-05 |
| 5.5, 5.6 inhabilitación por compromiso o fin de la relación | B/M/A | EV-05 | P-06 |
| 5.7 el rechazo no revela nada | B/M/A | EV-06 | |
| 5.8 límite de intentos y reactivación | B/M/A | EV-02, EV-03 | P-03, P-04 |
| r1.1 contraseña (R1) | B/M/A | EV-07 | P-01 |
| r1.2 complejidad de la contraseña (R1) | B/M/A | EV-02 | P-01 |
| r2.1 contraseña y OTP (R2) | B/M/A | EV-07 | P-01 |
| r3.1, r4.1 certificado cualificado (R3, R4) | B/M/A | EV-08 | P-01, P-07 |
| r3.2, r4.2 segundo factor en el certificado | B/M/A | EV-07 | P-01 |
| r3.3, r4.3 registro cualificado | B/M/A | | P-01, P-ATT |
| r5.1 registro de accesos conservado y continuo | M/A | EV-01, EV-09 | P-08 |
| r5.2 aviso de último acceso | M/A | | P-09, P-ATT |
| r6.1, r7.1 | ninguno | | siempre NOT_APPLICABLE |

## Fuentes

Cada fila de P-02 (`servicio | host | log`) se convierte en un `<localfile>` de la configuración de grupo, dentro de un bloque `<agent_config>` con el nombre del activo y una etiqueta con el nombre del servicio. El motor escribe estos bloques mediante la API de Wazuh:

```xml
<agent_config name="sede-01">
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/sede/autenticacion.json</location>
    <label key="oscompliance_service">sede</label>
  </localfile>
</agent_config>
```

La regla 119003 indexa cada evento JSON con `oscompliance_service` y `tipo`. El servicio escribe una línea JSON por evento; `ts` (RFC 3339) y `tipo` son obligatorios:

```json
{"ts":"…","tipo":"autenticacion","usuario":"u","origen":"203.0.113.7","resultado":"exito","factores":["password","otp"]}
{"ts":"…","tipo":"autenticacion","usuario":"u","origen":"203.0.113.7","resultado":"fallo","mensaje":"texto mostrado al usuario"}
{"ts":"…","tipo":"autenticacion","usuario":"u","resultado":"exito","factores":["certificado","pin"],"certificado_emisor":"FNMT-RCM","revocacion":"ocsp"}
{"ts":"…","tipo":"bloqueo","usuario":"u"}
{"ts":"…","tipo":"desbloqueo","usuario":"u","modo":"intervencion"}
{"ts":"…","tipo":"cambio_credencial","usuario":"u"}
{"ts":"…","tipo":"notificacion_compromiso","usuario":"u","referencia":"INC-12"}
{"ts":"…","tipo":"fin_relacion","usuario":"u","referencia":"BAJA-7"}
{"ts":"…","tipo":"inhabilitacion","usuario":"u"}
{"ts":"…","tipo":"politica","bloqueo":"activado","max_intentos":5,"reactivacion":"intervencion","longitud_minima":12,"complejidad":"activada"}
```

Factores: `password`, `otp`, `certificado`, `tarjeta`, `pin`, `biometria`.

| Fuente | Contenido | Lo usa |
|---|---|---|
| regla 119003 | los eventos de autenticación del servicio | EV-01 a EV-08 |
| `service_log_snapshot`, `service_log` (`services`) | para cada localfile etiquetado que se aplica al agente: inodo, tamaño, hora de modificación, copias rotadas y el `ts` de la línea más antigua en disco | EV-01, EV-03, EV-09 |

Los servicios de un activo son sus filas de P-02, los localfiles etiquetados que lee su agente y los servicios con eventos procedentes de él.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 mecanismo: R1, R2, R3 o R4 | uno, no acumulativo | decisiones, EV-07, EV-08 |
| P-02 `servicio \| host \| log` | sistema | los servicios de cada activo |
| P-03 máximo de intentos fallidos | | EV-02, EV-03 |
| P-04 procedimiento de reactivación | | decisión sobre 5.8 |
| P-05 días entre cambios de credencial | | EV-04 |
| P-06 horas para inhabilitar una credencial | | EV-05 |
| P-07 autoridades admitidas `ac \| validacion` | | EV-08 |
| P-08 días de conservación del registro de accesos | | EV-01 |
| P-09 aviso de último acceso, sí o no | | decisión sobre r5.2 |
| P-ATT atestaciones documentales | | requisitos documentales |
| P-DA declaración de aplicabilidad | | exclusión |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opacc5`. Un activo sin servicios deja todas las evidencias en NOT_EVALUABLE por CONFIGURATION, salvo que P-DA excluya el control en ella.

- EV-01 conservación. Por servicio, el registro llega hasta lo más antiguo entre su evento más antiguo en Wazuh y su línea más antigua en disco. Menos de P-08 días: NON_COMPLIANT, así que un servicio nuevo falla hasta que lleve P-08 días registrando.
- EV-02 bloqueo. La `politica` más reciente de cada servicio: bloqueo desactivado, `max_intentos` 0 o por encima de P-03, o reactivación automática: NON_COMPLIANT. Una serie de fallos de una cuenta mayor que P-03 en la ventana, sin un éxito, un bloqueo o un desbloqueo que la corte: NON_COMPLIANT. Los fallos con la cuenta bloqueada no cuentan. Sin política declarada: NOT_EVALUABLE por EVIDENCE.
- EV-03 fallos por origen. Por servicio y origen, el máximo de fallos en cualquier intervalo de 15 minutos; por encima de P-03: NON_COMPLIANT. Ningún fallo de un servicio cuya línea más reciente no está en Wazuh: NOT_EVALUABLE por COLLECTION.
- EV-04 antigüedad de la credencial. Cuentas que han iniciado sesión o cambiado su credencial y no se han inhabilitado después. Un último cambio más antiguo que P-05: NON_COMPLIANT. Sin cambio registrado: la credencial es al menos tan antigua como el evento más antiguo del servicio; por encima de P-05 es NON_COMPLIANT y, si no, NOT_EVALUABLE por EVIDENCE.
- EV-05 demora de inhabilitación. Cada `notificacion_compromiso` o `fin_relacion` se cierra con la siguiente `inhabilitacion` de la misma cuenta y servicio; una abierta cuenta las horas transcurridas. Por encima de P-06: NON_COMPLIANT. Ningún aviso nunca: NOT_EVALUABLE por EVIDENCE, porque si no pasaría un servicio que no registra avisos.
- EV-06 mensajes de rechazo. Un mensaje que dice que la cuenta no existe, que solo falló la contraseña, el estado de la cuenta o detalles técnicos (excepciones, estados SQL, versiones de servidor): NON_COMPLIANT. "Usuario o contraseña incorrectos" no revela nada. Un servicio que nunca ha registrado un mensaje: NOT_EVALUABLE por EVIDENCE.
- EV-07 mecanismo usado. Cada inicio de sesión con éxito se clasifica por sus factores: R4 tarjeta con PIN o biometría, R3 certificado con PIN o biometría, R2 contraseña con OTP, R1 solo contraseña. Uno que no es P-01: NON_COMPLIANT. Inicios de sesión sin factores: NOT_EVALUABLE por EVIDENCE; ninguno en la ventana: NOT_EVALUABLE por COLLECTION.
- EV-08 validación del certificado. Solo con R3 o R4; si no, NOT_APPLICABLE. Un emisor que no está en P-07, o una comprobación de revocación que su fila no admite: NON_COMPLIANT. Ninguno en la ventana: NOT_EVALUABLE por COLLECTION.
- EV-09 continuidad. Cada lectura de los registros frente a la anterior: el registro ha desaparecido, se ha sustituido sin una copia rotada que conserve el inodo antiguo o ha encogido sin rotar; el fichero se ha escrito después del evento más reciente que Wazuh tiene de él; o un servicio de P-02 que el agente no lee. Cualquiera de ellos: NON_COMPLIANT. Menos de dos lecturas: NOT_EVALUABLE por COLLECTION.

## Decisiones sobre requisitos

op.acc.5 decide algunos requisitos por sí mismo, solo donde el requisito se aplica por nivel:

- P-DA con motivo, referencia y enlace utilizable, en un activo sin servicios: todos los requisitos NOT_APPLICABLE. En un activo con un servicio la declaración queda contradicha y se ignora.
- P-01 no utilizable: los nueve requisitos de mecanismo quedan NOT_EVALUABLE por CONFIGURATION, y ninguna atestación prueba r3.3 o r4.3. Los requisitos de los mecanismos no elegidos: NOT_APPLICABLE. R1 por encima de BAJO: r1.1 y r1.2 NON_COMPLIANT; el ENS solo permite contraseña sola en BAJO.
- r1.2 con R1: una política declarada con la complejidad desactivada o sin longitud mínima es NON_COMPLIANT; sin política declarada es NOT_EVALUABLE; si no, EV-02.
- 5.8: P-04 sin definir es NOT_EVALUABLE, salvo que EV-02 o EV-03 ya hayan fallado.
- r5.2: P-09 no es NON_COMPLIANT; sin definir, NOT_EVALUABLE; sí lo deja en manos de P-ATT.

## No se mide

- Los servicios que no escriben el contrato. El control no puede ver dentro de una aplicación. Un servicio sin el registro es NOT_EVALUABLE, nunca COMPLIANT.
- Los fallos sin origen cuentan para EV-03 solo como límite superior y nunca acusan.
