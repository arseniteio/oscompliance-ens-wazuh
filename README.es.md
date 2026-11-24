# OSCompliance ENS

[English version](README.md)

OSCompliance ENS mide el Esquema Nacional de Seguridad (Real Decreto 311/2022) sobre un despliegue de Wazuh. Convierte lo que hacen tus activos en un veredicto por control, por requisito y por activo, con el motivo de cada resultado, cada 15 minutos.

Añade un binario de agente en cada activo auditado y un motor en el manager maestro de Wazuh. Wazuh sigue haciendo la recogida. No se juzga nada en el activo auditado, y lo que no se puede demostrar no cuenta como cumplido. El plugin [Power ENS](https://github.com/arseniteio/power-ens-wazuh) muestra los resultados en el dashboard de Wazuh.

Funciona en Wazuh 4.14.7, 4.14.8 y 4.14.9, con los activos auditados en Linux. El agente de Windows se incluye, pero todavía no se ha probado en una máquina física.

## Primeros pasos

Ejecuta el mismo comando en cada nodo servidor de Wazuh instalado por paquetes, como un usuario con sudo. Empieza por el manager maestro, o por el servidor de un despliegue todo en uno, y sigue con los managers worker y los nodos de dashboard. Los nodos de indexer no necesitan nada.

```bash
curl -fsSL https://github.com/arseniteio/oscompliance-ens-wazuh/releases/latest/download/install.sh | sudo bash -s -- server
```

El script detecta el nodo. En el maestro instala las reglas, el motor y sus usuarios, y audita el manager. Pide la contraseña de `wazuh-wui` y dos contraseñas nuevas, y la contraseña del usuario `admin` del indexer cuando el host no tiene el certificado de administración del indexer. En un worker espera las reglas que el maestro sincroniza a través del clúster y reinicia el manager. En un nodo de dashboard instala el plugin Power ENS. En un servidor todo en uno lo hace todo.

En cada activo que se audita:

```bash
curl -fsSL https://github.com/arseniteio/oscompliance-ens-wazuh/releases/latest/download/install.sh | sudo bash -s -- agent --group ens
```

En Windows, desde un PowerShell elevado (consulta [Agente de Windows](docs/es/install-windows.md)):

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((irm https://github.com/arseniteio/oscompliance-ens-wazuh/releases/latest/download/install.ps1))) -Group ens
```

El motor añade cada activo al grupo `ens` en menos de 15 minutos, y los primeros veredictos aparecen en Power ENS tras su siguiente pasada. Hasta que se guarda una configuración en Power ENS, el motor juzga con nivel MEDIO y el grupo `ens` en alcance. Ejecuta los mismos comandos con una versión más nueva para actualizar, y con `uninstall` en cada nodo para quitarlo todo.

Para revisar los ficheros antes de ejecutar nada, descarga el paquete y compruébalo. El `install.sh` del paquete usa los ficheros que tiene al lado.

```bash
v=2.1.0
url=https://github.com/arseniteio/oscompliance-ens-wazuh/releases/download/v$v
curl -fLO "$url/oscompliance-ens-$v-linux-amd64.tar.gz" -O "$url/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar xzf "oscompliance-ens-wazuh-$v-linux-amd64.tar.gz"
sudo "./oscompliance-ens-$v-linux-amd64/install.sh" agent --group ens
```

En un nodo de dashboard, el script descarga el plugin de la versión de power-ens-wazuh y lo comprueba. Para instalar sin acceso a GitHub, copia antes el zip del plugin y `deploy-plugin.sh` en la carpeta del paquete.

Para Wazuh en Docker o el detalle de cada paso, sigue las guías completas:

- [Instalación por paquetes](docs/es/install.md)
- [Instalación con Docker](docs/es/install-docker.md)
- [Agente de Windows](docs/es/install-windows.md)

## Cómo funciona

El agente escribe hechos en un fichero local. El agente de Wazuh envía ese fichero al manager junto con los registros, FIM, SCA e inventario, y el manager indexa los hechos mediante las reglas 119000 a 119006. Cada 15 minutos, el motor lee el indexer y escribe veredictos, y Power ENS los muestra.

El agente informa de hechos, nunca de veredictos: cuentas, PAM, sshd, sudoers, puertos en escucha, paquetes, copias y claves, tal como están.

El motor juzga. Lee los hechos, las alertas y el inventario de Wazuh, el manager mediante la API de Wazuh y los parámetros que declara tu organización, y escribe un veredicto por evidencia, requisito y control.

La falta de prueba es un fallo. Un registro que no llega a Wazuh, un parámetro sin definir o un agente que ha dejado de informar aparece como no evaluable, con la causa, y el requisito no se cumple.

Una pasada sobre 10.000 agentes simulados tarda unos dos minutos en un indexer de un solo nodo.

## Controles

Cubre 34 controles del Anexo II, cada uno con los requisitos de sus categorías (BAJO, MEDIO, ALTO): control de acceso (op.acc), explotación (op.exp), continuidad (op.cont), monitorización (op.mon), servicios en la nube (op.nub), comunicaciones (mp.com), equipos (mp.eq), información (mp.info), servicios (mp.s) y software (mp.sw).

Cada control tiene una página con lo que exige el ENS, cómo se mide cada evidencia, sus parámetros y lo que queda para la atestación documental. Consulta [Controles](docs/es/controls/README.md).

## Documentación

- [Instalación por paquetes](docs/es/install.md) y [con Docker](docs/es/install-docker.md): instalar, comprobar, actualizar y desinstalar.
- [Configuración](docs/es/configuration.md): flags del motor, ajustes del agente y parámetros ENS.
- [Arquitectura](docs/es/architecture.md): componentes, flujo de datos y escala.
- [Veredictos](docs/es/verdicts.md): estados, causas y puntuación.
- [Controles](docs/es/controls/README.md): una página por control.
- [Hechos](docs/es/facts.md): cada hecho que emite el agente.
- [Seguridad](docs/es/security.md): privilegios, tratamiento de datos y modelo de amenazas.
- [Operación](docs/es/operations.md): registros, resolución de problemas y capacidad.

## Compilar y probar

Comprueba el formato y ejecuta go vet, golangci-lint y las pruebas. Necesita golangci-lint 2.15.0 o posterior.

```bash
make check
```

Compila los paquetes en `dist/`, con `install.sh` y `SHA256SUMS`. Hace falta Go 1.27.2 o posterior.

```bash
make dist VERSION=2.1.0
```

## Seguridad

Notifica las vulnerabilidades en privado mediante un aviso de seguridad de GitHub. Consulta [Seguridad](docs/es/security.md).

## Licencia

Copyright (c) 2026 Quer System Informática.

OSCompliance ENS se distribuye bajo la GNU Affero General Public License versión 3 (AGPL-3.0-only). Consulta [LICENSE](LICENSE).

Quer System Informática ofrece también OSCompliance ENS con una licencia comercial, para organizaciones que no pueden cumplir las obligaciones de la AGPL, como mantener privados los cambios en un producto o en un servicio en red. Escribe a devqs@quersystem.com para conocer las condiciones.
