# op.nub.1 Protección de servicios en la nube

op.nub.1 juzga los servicios en la nube que usa la organización: si sus registros llegan a Wazuh, quién los administra y su expediente de certificación, conformidad con el ENS, pruebas de penetración, cifrado y jurisdicción de los datos.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.5.1. Definición: [`catalog/controls/ens/op.nub.1.json`](../../../catalog/controls/ens/op.nub.1.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 1.1 medidas del servicio prestado | B/M/A | atestación (P-ATT) |
| 1.2 conformidad de los servicios de terceros | B/M/A | EV-01, EV-04, EV-09 |
| r1.1 servicios de terceros certificados | M/A | EV-08 |
| r1.2 servicios de seguridad según op.pl.5 | M/A | atestación (P-ATT) |
| r2.1 configuración según la guía CCN-STIC | A | EV-02 |

P-01 decide lo que se aplica: `usuario` los requisitos de servicios de terceros, `prestador` 1.1, `ambos` los dos, `ninguna` nada; r2.1 se aplica en todas las posiciones salvo `ninguna`.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de los módulos de nube, por grupo de reglas | registro más reciente de cada módulo, una semana atrás | EV-01 |
| CloudTrail mediante `aws-s3` | `data.aws.readOnly` false, sin `errorCode`: actor `userIdentity.arn` | EV-04 |
| Office 365 mediante `office365` | `RecordType` 1 u 8, sin fallo: actor `UserId` | EV-04 |
| registro de actividad de Azure mediante `azure-logs` | `CategoryValue` Administrative, `ActivityStatusValue` Succeeded: actor `Caller` | EV-04 |
| auditorías de directorio de Entra ID mediante `ms-graph` | `result` success: actor `initiatedBy.user.userPrincipalName` | EV-04 |
| registro de auditoría Admin Activity de Google mediante `gcp-pubsub` o `gcp-bucket` | sin `status.code`: actor `protoPayload.authenticationInfo.principalEmail` | EV-04 |
| alertas del grupo de reglas de cada fila de P-07 | hallazgos de postura de una semana, y los iguales o superiores a P-14 | EV-02 |
| P-02 a P-12 | | EV-08, EV-09 |

Grupos de reglas por módulo: `aws-s3` amazon o aws, `azure-logs` azure, `gcp-pubsub` y `gcp-bucket` gcp, `office365`, `ms-graph`, `github`.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 posición | `usuario`, `prestador`, `ambos`, `ninguna` | todas |
| P-02 servicios `servicio \| modelo \| proveedor \| informacion \| criticidad \| uso` | `uso` utilizado o prestado | EV-08, EV-09 |
| P-03 conformidad con el ENS `servicio \| conformidad \| alcance \| vigencia \| referencia` | | EV-09 |
| P-04 certificación `servicio \| metodologia \| certificado \| vigencia` | | EV-08 |
| P-05 servicios de seguridad | documental | |
| P-07 guías de configuración `servicio \| guia \| estandar \| grupo_reglas` | | EV-02 |
| P-06 integraciones de Wazuh `servicio \| modulo \| ambito` | | EV-01, EV-04 |
| P-08 jurisdicción `servicio \| ubicacion \| copias \| jurisdiccion` | | EV-09 |
| P-09 cifrado `servicio \| cifrado \| gestion_claves` | | EV-09 |
| P-10 pruebas de penetración del proveedor `servicio \| informe \| fecha \| alcance` | | EV-09 |
| P-11 administradores `servicio \| identidad` | | EV-04 |
| P-12 meses de una prueba de penetración del proveedor | | EV-09 |
| P-13 horas sin registros de la nube | | EV-01 |
| P-14 nivel de un hallazgo de postura grave | | EV-02 |
| P-ATT atestaciones documentales | 1.1, r1.2 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opnub1`. El control se juzga igual en todos los activos: sus datos son de la organización.

- EV-01 registros. Cada servicio de P-06 con un módulo debe tener un registro de ese módulo dentro de P-13 horas; ningún módulo: NON_COMPLIANT.
- EV-02 postura. Cada fila de P-07 con un `grupo_reglas` tiene alertas de ese grupo en la última semana, ninguna de nivel P-14 o superior. Sin esa fila: NON_COMPLIANT. El proveedor juzga su tenant frente a su estándar (AWS Security Hub, Microsoft Defender for Cloud, Google Security Command Center); Wazuh trae los hallazgos y el motor los juzga.
- EV-04 administradores. Cada actor de una operación administrativa con éxito en la ventana en `aws-s3`, `office365`, `azure-logs`, `ms-graph`, `gcp-pubsub` o `gcp-bucket` debe estar en P-11 para el servicio de ese módulo. Un servicio integrado con `github`: NOT_EVALUABLE.
- EV-08 certificación. Cada servicio utilizado de P-02 con un `certificado` en P-04 cuya `vigencia` no ha vencido.
- EV-09 expediente. Cada servicio utilizado con una conformidad de P-03 vigente, una prueba de penetración de P-10 dentro de P-12 meses, una fila de P-09 y una fila de P-08. Los servicios se comparan sin mayúsculas ni acentos.

## No se mide

- EV-03, EV-05, EV-06 y EV-07: ninguna fuente produce un veredicto para ellas.
- La postura en la nube (R2) se juzga por atestación: Wazuh no incluye evaluación de la configuración del tenant y el motor no llama a las API de los proveedores.
