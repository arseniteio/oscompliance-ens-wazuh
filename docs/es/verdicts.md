# Veredictos

Cada pasada del motor escribe tres tipos de veredicto en `oscompliance-verdicts`, uno por activo: evidencia, requisito y control. Esquema: [`catalog/schemas/verdicts/verdict.v1.json`](../../catalog/schemas/verdicts/verdict.v1.json).

La regla detrás de cada estado: lo que no se puede demostrar no cumple.

Los estados y las causas son valores literales del índice, así que no se traducen. En las pantallas de Power ENS aparecen como Cumple, No cumple, No evaluable y No aplica.

## Evidencia

Una evidencia es un hecho medible sobre un activo, como «ningún UID está compartido» o «el registro de autenticación llega a Wazuh».

| Estado | Significado |
|---|---|
| `COMPLIANT` | Medido y correcto. |
| `NON_COMPLIANT` | Medido e incorrecto. El motivo nombra lo que falla: la cuenta, el fichero, el puerto. |
| `NOT_EVALUABLE` | No se ha podido medir. Siempre lleva una causa. |
| `NOT_APPLICABLE` | No se aplica a la categoría del sistema configurada, el control está desactivado o el activo está fuera del alcance del control. |

| Causa | Significado | Se arregla |
|---|---|---|
| `CONFIGURATION` | Falta un parámetro que la evidencia necesita o no se puede usar. | Definiendo el parámetro en Power ENS. |
| `COLLECTION` | No ha llegado una fuente: ninguna pasada del agente en la ventana, un fichero ilegible, un registro que no llega a Wazuh, auditd parado. | Arreglando el activo o su agente de Wazuh. |
| `EVIDENCE` | Los datos han llegado pero no pueden decidir este caso, por ejemplo una cuenta cuyo estado depende de claves que oculta un `AuthorizedKeysCommand`. | Revisando el caso a mano o cambiando el sistema para que se pueda medir. |

Un motivo `CONFIGURATION` nombra el activo. Si lo que falta es un parámetro, nombra también el parámetro y dice que no tiene valor o da el valor vigente y de dónde sale: el activo, una plantilla, un perfil o la organización. Una lista muestra cinco elementos y cuenta el resto.

## Requisito

Un requisito es un punto del Anexo II, como op.acc.1.4 «ciclo de vida de las cuentas». Su estado sale de sus evidencias:

1. No exigido en la categoría del sistema configurada, o control desactivado: `NOT_APPLICABLE`, fuera de la puntuación.
2. Sin evidencia técnica: `COMPLIANT`, `attested`, cuando una fila de atestación (P-ATT: `requisito | referencia | enlace | fecha | responsable`) tiene una referencia y un enlace utilizable (`http(s)://`, `file://`, `\\host` o una ruta absoluta). Si no, `NON_COMPLIANT`, no evidenciado. Un documento nunca cubre un requisito que tiene evidencia técnica.
3. Alguna evidencia `NON_COMPLIANT`: `NON_COMPLIANT`, evidenciado.
4. Alguna evidencia `NOT_EVALUABLE`: `NON_COMPLIANT`, no evidenciado (`evidenced: false`), con cada carencia y su causa.
5. Todas las evidencias `NOT_APPLICABLE`: `NOT_APPLICABLE`, fuera de la puntuación.
6. Si no, `COMPLIANT`.

`NOT_EVALUABLE` nunca llega a un requisito. Un auditor ve un requisito como cumplido o no; `evidenced` distingue un fallo medido de una prueba que falta.

Algunos controles deciden un requisito directamente donde la norma pide elegir: op.acc.5 y op.acc.6 solo aplican el mecanismo de autenticación que declara la organización (R1 a R4), y op.acc.5 acepta una declaración de aplicabilidad en activos sin servicios externos.

## Control

Un control se juzga por su nivel CMM, no a todo o nada. `score` es la proporción de requisitos aplicables que se cumplen, de 0 a 100; la escala de madurez lo convierte en un nivel, y `compliance` lleva el porcentaje, el nivel, el nivel exigido y la categoría.

| Estado | Cuándo |
|---|---|
| `COMPLIANT` | el nivel llega al exigido: L2 en BÁSICO, L3 en MEDIO, L4 en ALTO |
| `PARTIAL` | por debajo del nivel exigido, por encima del 0 % |
| `NON_COMPLIANT` | 0 % |
| `NOT_APPLICABLE` | no se aplica nada |

6 de 8 requisitos es un 75 %, L3: `COMPLIANT` en un control de nivel MEDIO.

`coverage` es la proporción de requisitos aplicables que se han medido, frente a los fallados por falta de prueba. Un control con 60 y cobertura 100 es un 60 medido; con cobertura 40, la mayor parte de la diferencia es configuración o recogida.

## Recuentos

Una evidencia que juzga un conjunto de elementos lleva `tally`: los elementos que la cumplen, los juzgados y el porcentaje, redondeado hacia abajo. mp.info.6 cuenta copias en EV-01 (hechas), EV-02 (dentro de su intervalo) y EV-03 (conservadas su retención). op.acc.1 cuenta cuentas, op.exp.2 paquetes y op.exp.10 certificados y claves.

El veredicto `organization` de cada control juzgado también lleva `tally`: los activos cuyo control es `COMPLIANT` sobre aquellas a las que se aplica.

`tally.level` traduce el porcentaje a L0-L5 con una escala de `configuration.maturity.scales`:

```json
{ "controlId": "mp.info.6", "agentId": "001", "thresholds": [50, 70, 80, 90, 98] }
```

`thresholds` contiene el porcentaje mínimo de L1 a L5, en orden creciente. Una escala con `agentId` se aplica a ese activo y prevalece sobre la del control. Sin escala, el motor usa la tabla facilitada por un auditor del CCN ([`catalog/maturity.json`](../../catalog/maturity.json)): 20, 40, 60, 80 y 100, con el nombre y el significado de cada nivel. El nivel exigido por categoría sale de la CCN-STIC 808 y está en el mismo fichero, que también lee Power ENS: aplica la misma regla a una selección de activos, donde el porcentaje de la flota es la media de sus activos y un activo sin puntuación cuenta como 0 %.

El nivel decide el estado de una evidencia con recuento. L2 cumple en un sistema BÁSICO, L3 en uno MEDIO y L4 en uno ALTO, al nivel al que se juzga el control. 36 copias correctas de 40 es un 90 %, L4: `COMPLIANT` en un sistema ALTO, y el motivo sigue listando las cuatro copias fallidas. Los juicios NOT_EVALUABLE y NOT_APPLICABLE conservan su estado.

## Madurez

El apdo. 6 del Anexo II valora cada medida como un proceso con los niveles CMM
L0 a L5. El semáforo y la puntuación anteriores son indicadores operativos; el
nivel de madurez es la valoración del ENS.

La evidencia solo puede mostrar que una práctica existe y que se repite. Cada
veredicto de control lleva `maturity.accredited` para ese activo:

| Nivel | Condición en los últimos 30 días, hoy incluido |
|---|---|
| L0 | ningún día con un requisito cumplido con evidencia |
| L1 | algún día así, o no hoy |
| L2 | hoy y al menos 27 de los 30 días |

`working_days` es el número de esos días. L3 a L5 exigen un proceso escrito,
medido y mejorado. Las personas los declaran en Power ENS (`maturity` en la
configuración: nivel, objetivo, autor, fecha y referencias); el motor nunca
sube un nivel por encima de L2 a partir de la evidencia.

Cada pasada escribe además veredictos `organization`, con `agent.id`
`organization`:

- uno por control juzgado: el nivel acreditado más bajo de sus activos, el
  nivel y el objetivo declarados, el número de activos e `incoherent` cuando
  el nivel declarado es L3 o más y la evidencia acredita L0 o L1;
- uno por medida declarada que el motor no juzga, como org.2: solo el nivel
  declarado;
- uno con `control` `ENS`: la distribución de niveles acreditados y declarados
  sobre las medidas aplicables, las medidas sin medición, sin nivel declarado y
  por debajo de su objetivo, y dos niveles globales. Un nivel global es el más
  alto que alcanza al menos el 80 % de las medidas; el acreditado solo cuenta
  las medidas que juzga el motor.

## Alcance

Algunas medidas solo se aplican a algunas activos: la protección del correo a los servidores de correo, el bloqueo de pantalla a los puestos de trabajo, el cifrado a los dispositivos portátiles, las copias a los activos con copias declaradas. Cada página de control indica su alcance. Los activos fuera de él reciben `NOT_APPLICABLE`.

Cuando la norma exige una medida en algún punto del sistema y ningún activo la tiene, el sistema falla: el manager asume el veredicto `NON_COMPLIANT`, de modo que una flota no puede cumplir sin declarar nada.

## Qué activos se juzgan

Los activos del alcance ENS (`scope` en la configuración de Power ENS): las de sus grupos, por defecto `ens`, y el manager, que no está en ningún grupo. Con `-wazuh-api`, el motor lee los grupos de cada agente de la API de Wazuh al empezar cada pasada; sin ella, de la última muestra de `wazuh-monitoring-*`, que puede ir unos minutos por detrás de un cambio de grupo. Si no puede leer los grupos, la pasada no juzga nada. Cuando el alcance o una exclusión dependen de los grupos, un agente cuyos grupos se desconocen no se juzga en esa pasada, y la pasada termina con un error que lo nombra. Un activo fuera del alcance no recibe veredicto y no cuenta en los controles que miran toda la flota; aun así se puede nombrar en un parámetro, como un host de preproducción. Cuando no se puede leer la configuración, el motor mantiene el último alcance leído, y no juzga nada hasta haber leído uno.

Con `scope.controlGroups` activado, un activo del grupo de Wazuh `ens-excluir-<control>` (por ejemplo `ens-excluir-op.acc.1`) queda fuera de ese control: sus veredictos son `NOT_APPLICABLE` y nombran el grupo, y no cuenta como activo donde exista el control. Sus hechos siguen llegando, así que al sacarlo del grupo se vuelve a juzgar en la siguiente pasada. El manager no está en ningún grupo y no se puede excluir de esta forma.

Un agente del alcance que deja de enviar mantiene sus veredictos como `NOT_EVALUABLE` por `COLLECTION` mientras Wazuh lo tenga registrado; no desaparece del informe.

## Sistemas ENS

Una instalación puede tener varios sistemas ENS, cada uno con su categoría, su alcance, sus parámetros y su madurez. La configuración guardada en Power ENS antes de que existieran los sistemas es el sistema `default`; cada uno de los demás tiene su propio documento `SYSTEM_CONFIGURATION`. El motor juzga cada sistema en su propia pasada y escribe su identificador en el campo `system` de cada veredicto. Los veredictos sin ese campo son de `default`. Los veredictos de organización y la madurez se cuentan por sistema.

Cada activo pertenece a un solo sistema. Los sistemas distintos de `default` tienen que indicar grupos o activos en su alcance; reclaman sus activos primero, y `default` se queda con el resto de su propio alcance. Un activo que reclaman dos sistemas, porque ambos la nombran o nombran uno de sus grupos, no se juzga en ninguno, y la pasada termina con un error que la nombra junto a los sistemas. El manager soporta las medidas de las que dependen todos los sistemas, así que cada sistema lo juzga.

## Tiempo

| Ajuste | Por defecto | Significado |
|---|---|---|
| ventana | 26 h | cuentan los eventos más recientes que esto para las evidencias de eventos (inicios de sesión, fallos, cambios) |
| periodo de consulta | 7 días | se juzgan los activos con hechos así de recientes |
| intervalo | 15 min | tiempo entre pasadas |

Los veredictos de evidencia se escriben por activo y pasada del agente; juzgar de nuevo la misma pasada los sustituye. Los de requisito y control conservan el último de cada día, que da la serie diaria que dibuja el plugin.

## Motivos

Los veredictos llevan `reason_code` y `reason_args` junto con un `reason` en inglés. El plugin presenta el código en el idioma del usuario a partir de [`catalog/messages`](../../catalog/messages). Los motivos nombran lo encontrado: «cuentas con UID 1001: alice, backup», no «se han encontrado UID duplicados».
