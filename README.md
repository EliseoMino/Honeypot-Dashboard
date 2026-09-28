# Honeypot-Dashboard

Sistema de monitoreo que recoge, normaliza, almacena y analiza los eventos que
genera un honeypot SSH/Telnet de Cowrie, y los presenta en un dashboard web.

```
Cowrie  ->  agente  ->  backend  ->  PostgreSQL  ->  dashboard
   :2222     mTLS        mTLS          RF-03          nginx
   :2223   TLS 1.3     TLS 1.3
```

## Puesta en marcha

Requisitos: Docker con Compose v2. Nada más; el stack construye sus propias
imágenes y genera su propia PKI.

```bash
cp .env.example .env
docker compose up -d --build
```

Cuando los contenedores estén healthy, abrir <http://127.0.0.1:3000>.

No hay paso manual de certificados: el servicio `cert-init` genera la CA de
desarrollo y los pares que necesita el transporte TLS en un volumen de Docker la
primera vez que arranca.

Para comprobar el estado:

```bash
docker compose ps
docker compose logs -f agent
```

### Desarrollo con watch

```bash
docker compose up --watch
```

Sin salir de ese comando, los cambios se aplican solos:

| Cambio | Efecto |
| --- | --- |
| `backend/src/**` | Se sincroniza al contenedor y el backend se reinicia. |
| `agent/src/**` | Se sincroniza al contenedor y el agente se reinicia. |
| `infrastructure/detection/**` | Reinicia el backend, que lee las reglas al arrancar. |
| `backend/pyproject.toml`, `agent/pyproject.toml` | Reconstruye la imagen: las dependencias se resuelven al construir. |
| `dashboard/src/**` y su configuración | Reconstruye la imagen del dashboard y nginx sirve el bundle nuevo. |
| `infrastructure/nginx/**` | Se sincroniza la configuración y nginx se reinicia. |

El backend y el agente se ejecutan con `PYTHONPATH=/app/src` en modo watch, así
que el proceso importa el código sincronizado y no la copia que `pip install .`
deja en `site-packages`. Fuera del modo watch se usa el comando normal de la
imagen.

El dashboard es un bundle estático servido por nginx, por eso un cambio de
código implica reconstruir la imagen y no un simple `sync`. Para iterar sobre
el front con HMR hay que levantar `npm run dev` por fuera y apuntar el proxy de
Vite al dashboard.

## Puertos

Todo se publica solo en `127.0.0.1`. El backend **no** se publica: la única
forma de alcanzarlo es a través de nginx, con un certificado de cliente.

| Puerto | Servicio | Notas |
| --- | --- | --- |
| 3000 | dashboard (nginx) | El único puerto que ve el navegador. |
| 2222 | Cowrie SSH | Bucle local únicamente. |
| 2223 | Cowrie Telnet | Bucle local únicamente. |
| 5432 | PostgreSQL | Bucle local únicamente, para `psql` y para la suite de tests. |
| 8443 | backend | **No** publicado. Solo alcanzable desde las redes de Compose. |

## Atacar el honeypot

El honeypot está en `127.0.0.1:2222` (SSH) y `127.0.0.1:2223` (Telnet). Un
intento de login cualquiera genera eventos; una sesión interactiva que ejecute
comandos genera los eventos que disparan las reglas de detección.

```bash
ssh -p 2222 root@127.0.0.1
```

Para no depender de un atacante real hay un simulador que recorre escenarios
reproducibles y dice qué eventos se espera ver en cada uno:

```bash
pip install -e "agent[dev]"
python scripts/simulate-attack.py --list
python scripts/simulate-attack.py --all
python scripts/simulate-attack.py bruteforce session
```

Dos advertencias sobre el comportamiento real de Cowrie, porque desconciertan:

- Las credenciales válidas no son las obvias. El simulador las descubre
  probando y no las asume, así que no hace falta conocerlas de antemano.
- El escenario `download` necesita salida a Internet: Cowrie se niega a
  descargar desde direcciones que no sean globalmente enrutables, por protección
  contra SSRF. Un servidor en la red de Docker o en la máquina host no sirve.

Las reglas de detección se evalúan bajo demanda, no al ingerir. Para que los
eventos del simulador se conviertan en alertas hace falta disparar la corrida:

```bash
curl -s -X POST http://127.0.0.1:3000/api/v1/detections/run \
  -H 'Content-Type: application/json' -d '{}'
```

Reevaluar la misma actividad no duplica alertas: solo una detección nueva las
genera.

## Componentes

| Ruta | Qué es |
| --- | --- |
| `backend/` | API de ingesta, normalización, persistencia y detección. |
| `agent/` | Agente de transporte: hace tail de `cowrie.json` y lo envía por mTLS. |
| `dashboard/` | Frontend (React + Vite) servido por nginx. |
| `infrastructure/cowrie/` | Configuración de Cowrie y sus datos de ejecución. |
| `infrastructure/nginx/` | Proxy mTLS: el puente entre el navegador y el backend. |
| `infrastructure/detection/` | Reglas de detección. |
| `scripts/` | Utilidades, incluidos la PKI de desarrollo y el simulador de ataques. |
| `docs/requirements/` | Requisitos funcionales. |

## Desarrollo fuera de Docker

El backend, el agente y el dashboard se pueden ejecutar en el host durante el
desarrollo. En ese caso los certificados se generan a mano:

```bash
python scripts/generate-dev-certs.py --out var/certs
```

`--key-mode 0600` es el valor por defecto y sirve para el host. El compose usa
`0644` porque varios contenedores sin privilegios tienen que leer el material
desde un volumen compartido.

`dashboard/vite.config.ts` apunta por defecto a nginx en `http://127.0.0.1:3000`
y no al backend: el backend exige un certificado de cliente que un navegador no
puede presentar. Para hablar con el backend desde el host hacen falta
`--cert var/certs/agent.crt --key var/certs/agent.key --cacert var/certs/ca.crt`.

### Tests

```bash
cd backend  && python -m pytest
cd agent    && python -m pytest
cd dashboard && npm test
```

Los tests del backend que necesitan PostgreSQL se saltan salvo que
`TEST_DATABASE_URL` apunte a una base desechable: los fixtures borran el esquema
RF-03/RF-11/RF-12 antes y después de cada test. Ver el aviso al final de
`.env.example`.

### Rotación de `cowrie.json`

El agente sobrevive a que el log se renueve o se trunque, pero no puede tratar
los dos casos igual porque no son igual de graves.

Una rotación reemplaza el archivo, así que cambia el inode y no se pierde nada:
el agente reabre y sigue. Un truncado conserva el inode y vacía el archivo, que es
lo que hace `copytruncate`. En ese caso, **todo lo que se escribió entre la
última lectura y el truncado ya no está en disco y no hay offset que lo
recupere**. El agente reinicia desde el principio del contenido nuevo y lo
registra como lo que es: pérdida de evidencia.

Por eso el agente cuenta los dos casos por separado y los publica en sus
estadísticas (`rotations` y `truncations`) además de loguearlos. Un
`truncations` distinto de cero significa que faltan eventos, y conviene leer las
estadísticas del agente (`docker compose logs agent`) antes de sacar conclusiones
de un período con huecos.

Para no perder nada hay que rotar por *rename*, no con `copytruncate`: la
configuración recomendada en `logrotate.conf` es la que mueve el archivo y le
avisa a Cowrie, por ejemplo con `postrotate` haciendo que Cowrie cierre y
reabra su salida. Con el cowsignal de Cowrie, algo del orden de:

```
/cowrie/cowrie-git/var/log/cowrie/cowrie.json {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /cowrie/bin/cowrie.py -n 2>/dev/null || kill -HUP $(cat /cowrie/cowrie-git/var/run/cowrie.pid)
    endscript
}
```

Está fuera del alcance de la fase actual porque el despliegue en VPS no está
implementado, pero conviene adoptarlo antes de exponer el honeypot.

## Problemas frecuentes

**`Failed to load output engine: jsonlog` con
`No such file or directory: var/log/cowrie/cowrie.json`**

El bind mount de `infrastructure/cowrie/data` sobre `/cowrie/cowrie-git/var`
reemplaza el árbol de directorios que trae la imagen, y Cowrie no crea el
directorio donde escribe. El esqueleto de directorios está en git justamente
para que esto no ocurra en un clon nuevo. Si se borró a mano, restaurar con:

```bash
git checkout -- infrastructure/cowrie/data
```

**`Name or service not known` en los logs del agente**

El agente no resuelve `backend`. Suele significar que el contenedor del agente es
anterior al cambio de red: los alias de nombre de servicio están declarados de
forma explícita en `compose.yaml`, así que la solución es recrear, no reiniciar.

```bash
docker compose up -d --force-recreate agent backend
```

**El backend se reinicia en bucle con `TLS_CERTFILE does not exist`**

Falta material en el volumen `certs`. `cert-init` lo genera solo cuando el
volumen está vacío; si se borró a mano:

```bash
docker compose run --rm cert-init
```

**La contraseña de PostgreSQL no coincide**

El volumen `pgdata` conserva la contraseña con la que se inicializó. Cambiarla en
`.env` no cambia la del volumen. Con la contraseña original:

```bash
docker compose exec postgres psql -U honeypot -c "ALTER USER honeypot PASSWORD 'change-me';"
```

O, para empezar de cero destruyendo los datos de desarrollo:

```bash
docker compose down -v
```

**Un puerto 2222 ya está ocupado**

Algo más está usando el puerto. Buscarlo con `docker ps --filter publish=2222`.
Los contenedores sueltos que quedaron de pruebas anteriores también cuentan.

## Seguridad

- La clave de la CA de desarrollo existe solo en un volumen de Docker local. No
  usarla para nada que salga de esta máquina.
- El backend acepta cualquier certificado firmado por esa CA, así que el
  material debe tratarse como un secreto aunque sea de desarrollo.
- No exponer los puertos del honeypot fuera del bucle local sin un firewall
  deliberado delante.
- No commitear registros reales del honeypot. `infrastructure/cowrie/data`
  ignora su contenido por directorio, pero revisa `git status` antes de commitear.
- La fase de despliegue en VPS queda fuera del alcance actual.
