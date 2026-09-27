RF-01 — Ingesta de eventos del honeypot
Descripción

El sistema deberá ser capaz de capturar de forma continua y en tiempo real (o cuasi-real) los registros de actividad generados por el honeypot Cowrie. El componente de ingesta leerá la salida estructurada del honeypot y transportará los datos de manera segura hacia el backend o pipeline de procesamiento del sistema, garantizando que no se pierdan eventos críticos.Criterios de Aceptación (Funcionales)El componente de ingesta debe recolectar, como mínimo, los siguientes tipos de eventos nativos de Cowrie mediante la lectura de su archivo JSON:Eventos de Conexión y Sesión: Registro de IP de origen, puerto de origen, puerto de destino (SSH o Telnet) e inicios/cierres de conexiones (cowrie.session.connect, cowrie.session.closed).Eventos de Autenticación: Intentos de inicio de sesión, incluyendo combinaciones de usuario y contraseña provistas por el atacante, así como el resultado de la autenticación (éxito simulado o fallo) (cowrie.login.success, cowrie.login.failed).Eventos de Comandos Ejecutados: Comandos interactivos completos y argumentos ingresados por el atacante dentro de la shell simulada (cowrie.command.success, cowrie.command.failed).Eventos de Transferencias y Descargas: Intentos de descargar herramientas maliciosas, scripts o binarios (URLs utilizadas, hashes MD5/SHA256 generados por Cowrie para el archivo y nombres de archivos asignados) (cowrie.session.file_download, cowrie.client.fingerprint).Requisitos Técnicos y de ArquitecturaFormato de Origen: La ingesta se realizará exclusivamente a partir del archivo estructurado cowrie.json. Queda descartado el uso de logs en formato de texto plano (cowrie.log) debido a la ineficiencia de parseo.Mecanismo de Captura (Agente): Se utilizará un agente de transporte de logs ligero (por ejemplo, Filebeat, Fluent Bit o un script/daemon propio en Python/Go) instalado en la máquina del honeypot para evitar sobrecargar los recursos del contenedor o servidor.Modo de Lectura: El agente operará en modo "Tail" (lectura continua desde el final del archivo) y deberá mantener un registro del último estado de lectura (registry/checkpoint). Esto garantiza que, ante una caída del sistema de ingesta, la recolección se reanude exactamente en el último evento enviado, evitando la pérdida o duplicación masiva de datos.Seguridad en el Transporte: El canal de comunicación entre el agente de ingesta (Honeypot) y el sistema receptor central (Backend/SIEM) deberá estar estrictamente cifrado mediante TLS 1.3 (Transport Layer Security) para evitar la interceptación o manipulación de la telemetría en tránsito.

Prioridad: Alta
MVP: Sí

RF-02 — Normalización de eventos
Descripción

El sistema deberá transformar los eventos obtenidos de Cowrie a un formato estructurado y uniforme, independientemente del tipo de evento recibido.

Como mínimo, los eventos deberán poder asociarse con:

    Fecha y hora.

    Dirección IP de origen.

    Tipo de evento.

    Sesión.

    Usuario utilizado, cuando corresponda.

    Información específica del evento.

Prioridad: Alta
MVP: Sí

RF-03 — Almacenamiento de eventos

El sistema deberá persistir en PostgreSQL los eventos normalizados provenientes del componente de ingesta, permitiendo su consulta, filtrado, ordenamiento y agregación desde el backend.

Los eventos deberán conservar los atributos comunes utilizados por el sistema, incluyendo timestamp, IP de origen, tipo de evento y session ID cuando estén disponibles. Los atributos específicos de cada evento podrán almacenarse mediante un campo JSONB.

La base de datos deberá utilizar almacenamiento persistente para evitar la pérdida de información ante reinicios de los servicios.
Base de datos: PostgreSQL
Ejecución: Docker
Persistencia: Docker Volume
Datos variables: JSONB
ORM/driver: se definirá al implementar FastAPI
Índices: timestamp, src_ip, event_type, session_id

Prioridad: Alta
MVP: Sí

RF-04 — Dashboard de resumen
Descripción

El sistema deberá proporcionar un dashboard que presente un resumen de la actividad registrada por el honeypot.

El dashboard deberá mostrar como mínimo:

    Cantidad total de eventos.

    Cantidad de IPs únicas.

    Cantidad de sesiones.

    Cantidad de intentos de autenticación.

    Cantidad de comandos registrados.

    Cantidad de alertas generadas.

Prioridad: Alta
MVP: Sí

RF-05 — Visualización temporal de actividad
Descripción

El sistema deberá permitir visualizar la evolución de los eventos registrados a lo largo del tiempo.

El usuario deberá poder identificar períodos de mayor o menor actividad.

Prioridad: Baja
MVP: Hay que ver

RF-06 — Consulta de eventos
Descripción
El sistema deberá permitir al usuario consultar los eventos almacenados.
La consulta deberá permitir, como mínimo:
* Visualizar los eventos.
* Ordenarlos por fecha y hora.
* Ordenarlos de forma ascendente o descendente.
* Filtrarlos por tipo de evento.
* Filtrarlos por dirección IP de origen.
* Buscar eventos mediante texto.
* Combinar múltiples filtros.
* Navegar los resultados de forma paginada.

Los resultados deberán mostrar la información relevante del evento y permitir acceder a su información detallada mediante RF-07.

Prioridad: Alta

MVP: Sí


# RF-07 — Visualización del detalle de un evento

## Descripción

El sistema deberá permitir al usuario seleccionar un evento y consultar toda la información disponible asociada al mismo.

La información mostrada podrá variar según el tipo de evento y los datos disponibles.

Cuando corresponda, el detalle deberá permitir identificar la relación del evento con otros elementos registrados, como una sesión o una dirección IP de origen.

## Prioridad

Alta

## MVP

Sí


RF-08 — Consulta de sesiones
Descripción

El sistema deberá permitir consultar las sesiones registradas por el honeypot.

Para cada sesión deberá poder visualizarse, cuando la información esté disponible:

    Identificador de sesión.

    IP de origen.

    Inicio.

    Finalización o duración.

    Eventos asociados.

    Comandos ejecutados.

Prioridad: Alta
MVP: No — segunda iteración.

RF-09 — Visualización de comandos ejecutados
Descripción

El sistema deberá permitir consultar los comandos ejecutados durante las sesiones registradas.

Deberá ser posible identificar:

    Comando.

    Fecha y hora.

    IP de origen.

    Sesión asociada.

Prioridad: Media
MVP: No — segunda iteración.

RF-10 — Consulta de actividad por dirección IP
Descripción

El sistema deberá permitir consultar la actividad asociada a una dirección IP de origen.

La consulta deberá mostrar, cuando exista información:

    Cantidad de eventos.

    Sesiones asociadas.

    Intentos de autenticación.

    Comandos ejecutados.

    Otros eventos relacionados.

Prioridad: Media
MVP: No — segunda iteración.

# RF-11 — Detección de actividad sospechosa

## Descripción

El sistema deberá analizar los eventos registrados por el honeypot e identificar patrones de actividad que coincidan con reglas de detección configuradas.

Las reglas deberán permitir identificar actividad potencialmente sospechosa a partir de eventos individuales, repetición de eventos, frecuencia de ocurrencia y combinación de diferentes eventos relacionados.

Cuando una actividad cumpla las condiciones de una regla de detección, el sistema deberá identificarla como una actividad sospechosa y permitir la generación de una alerta asociada.

## Detecciones iniciales

Como parte de la primera versión del sistema, se contemplarán reglas básicas como:

* Múltiples intentos de autenticación fallidos.
* Repetición de intentos de autenticación desde una misma dirección IP.
* Ejecución de determinados comandos considerados relevantes para la investigación.
* Descarga o transferencia de archivos.
* Combinaciones simples de eventos relacionados.

Las reglas iniciales deberán utilizar información disponible en los eventos almacenados y deberán ser explícitas y determinísticas.

## MVP

Para el MVP se implementará un conjunto reducido de reglas básicas, priorizando aquellas que puedan ser evaluadas directamente a partir de los eventos disponibles.

Como mínimo, el MVP deberá contemplar:

1. **Múltiples intentos de autenticación desde una misma IP**

   * Detectar una cantidad configurable de intentos dentro de un período determinado.
   * Registrar la IP involucrada y los eventos que provocaron la detección.

2. **Ejecución de comandos relevantes**

   * Detectar la ejecución de comandos incluidos en una lista de comandos de interés.
   * Registrar el comando, la IP, la sesión y el evento asociado cuando esta información esté disponible.

3. **Descarga o transferencia de archivos**

   * Detectar eventos de descarga o transferencia de archivos registrados por el honeypot.
   * Registrar la información disponible asociada al evento.

El MVP no deberá implementar técnicas de machine learning, análisis avanzado de comportamiento, inteligencia de amenazas externa ni correlaciones complejas entre grandes cantidades de eventos.

## Evolución posterior

La versión completa podrá ampliar el motor de detección para contemplar:

* Reglas configurables sin modificar el código de la aplicación.
* Diferentes niveles de severidad.
* Ventanas temporales configurables.
* Correlación de múltiples eventos.
* Detección de secuencias de comportamiento.
* Agrupación de eventos relacionados con una misma actividad.
* Reglas específicas por dirección IP, sesión o tipo de evento.
* Habilitación y deshabilitación de reglas.
* Registro de la evidencia que provocó cada detección.
* Prevención de generación de alertas duplicadas.
* Incorporación de nuevas reglas sin modificar el funcionamiento del resto del sistema.

Las reglas deberán diseñarse de forma que puedan ampliarse progresivamente sin modificar la estructura principal del sistema.

## Prioridad

Alta

## MVP

Sí — con reglas básicas.


# RF-12 — Generación de alertas

## Descripción

Cuando una regla de detección definida en RF-11 se cumpla, el sistema deberá generar una alerta asociada al evento o conjunto de eventos que provocó la detección.

La alerta deberá conservar la información necesaria para identificar y analizar la actividad detectada.

La alerta deberá incluir, cuando corresponda:

* Tipo de alerta.
* Fecha y hora de generación.
* Dirección IP de origen.
* Sesión relacionada.
* Evidencia que provocó la detección.
* Nivel de severidad.

La evidencia deberá permitir identificar los eventos que provocaron la generación de la alerta.

Cuando una misma actividad provoque múltiples evaluaciones de una regla, el sistema deberá evitar la generación innecesaria de alertas duplicadas, cuando sea posible identificar que corresponden a la misma detección.

## MVP

El MVP deberá:

* Generar una alerta cuando una regla de RF-11 sea activada.
* Asociar la alerta con el evento o eventos que provocaron la detección.
* Registrar la información disponible de la actividad detectada.
* Asignar un nivel de severidad definido por la regla.
* Persistir las alertas para su posterior consulta desde el dashboard.

El MVP no requiere notificaciones externas, como correo electrónico, Discord, Telegram o servicios similares.

## Evolución posterior

La generación de alertas podrá ampliarse posteriormente para contemplar:

* Estados de alerta, como pendiente, revisada o resuelta.
* Agrupación de alertas relacionadas.
* Deduplicación más avanzada.
* Reglas para controlar la frecuencia de generación de alertas.
* Notificaciones externas.
* Priorización y gestión de incidentes.

## Prioridad

Alta

## MVP

Sí


RF-13 — Consulta de alertas
Descripción

El sistema deberá permitir al usuario consultar las alertas generadas y acceder al detalle de cada una.

Deberá ser posible filtrar las alertas por:

    Severidad.

    Tipo.

    Fecha.

    Dirección IP.

Prioridad: Media
MVP: No — segunda iteración.

RF-13 — Consulta de alertas
Descripción

El sistema deberá permitir al usuario consultar las alertas generadas y acceder al detalle de cada una.

Deberá ser posible filtrar las alertas por:

    Severidad.

    Tipo.

    Fecha.

    Dirección IP.

Prioridad: Media
MVP: No — segunda iteración.

RF-14 — Consulta de logs originales
Descripción

El sistema deberá permitir acceder a los datos originales generados por Cowrie para facilitar la investigación de eventos.

La visualización deberá permitir relacionar el log original con el evento normalizado correspondiente cuando sea posible.

Prioridad: Baja
MVP: No — Segunda iteración.

RF-15 — Actualización de información
Descripción

El sistema deberá permitir actualizar la información mostrada en el dashboard mediante una actualización manual o automática de los datos disponibles.

Para una primera versión, puede utilizarse actualización periódica.

Prioridad: Media
MVP: Sí.