RF-01 — Ingesta de eventos del honeypot
Descripción

El sistema deberá recibir y procesar los eventos generados por Cowrie, incluyendo como mínimo eventos de autenticación, sesiones, comandos ejecutados y transferencias de archivos cuando estén disponibles.

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
Descripción

El sistema deberá almacenar los eventos procesados en una base de datos persistente, permitiendo su posterior consulta y análisis.

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

    Visualizar eventos.

    Ordenarlos por fecha.

    Filtrarlos por tipo.

    Filtrarlos por dirección IP.

    Buscar eventos.

Prioridad: Alta
MVP: Sí

RF-07 — Visualización del detalle de un evento
Descripción

El sistema deberá permitir seleccionar un evento y consultar toda la información disponible asociada al mismo.

La información mostrada dependerá del tipo de evento.

Prioridad: Alta
MVP: Sí

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

RF-11 — Detección de actividad sospechosa
Descripción

El sistema deberá analizar los eventos almacenados y identificar patrones de actividad que cumplan reglas de detección configuradas.

Inicialmente podrá contemplar reglas como:

    Múltiples intentos de autenticación.

    Repetición de intentos desde una misma IP.

    Ejecución de determinados comandos.

    Descarga de archivos.

    Combinaciones de eventos consideradas relevantes.

Prioridad: Alta
MVP: Sí, pero con reglas básicas.

RF-12 — Generación de alertas
Descripción

Cuando una regla de detección se cumpla, el sistema deberá generar una alerta asociada al evento o conjunto de eventos correspondiente.

La alerta deberá incluir, cuando corresponda:

    Tipo de alerta.

    Fecha y hora.

    IP de origen.

    Sesión relacionada.

    Evidencia que provocó la alerta.

    Nivel de severidad.

Prioridad: Alta
MVP: Sí.

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