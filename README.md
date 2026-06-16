# NetMap Builder v.1.5.1
By V4mp3rbl4ck https://www.linkedin.com/in/v4mp3rbl4ck/

Plataforma web para diseñar, documentar y analizar mapas de red. Permite crear topologías interactivas con inventario de dispositivos, segmentos, relaciones, servicios, análisis de impacto por falla, importación Nmap y versionamiento de proyectos.

---

## Arquitectura

```
Frontend  →  React + React Flow + Vite, servido por Nginx
Backend   →  FastAPI + SQLAlchemy (Python 3.12)
Base de datos  →  PostgreSQL 16
Contenedores  →  docker compose
```

| Contenedor | Descripción |
|---|---|
| `netmap-builder-web` | Frontend React/Nginx |
| `netmap-builder-api` | Backend FastAPI |
| `netmap-builder-db` | PostgreSQL 16 |

---

## Inicio rápido

### 1. Copiar y editar la configuración

```bash
cp .env.example .env
```

Editar `.env` con contraseñas reales antes de levantar:

```env
POSTGRES_PASSWORD=tu-password-segura
AUTH_SECRET=cadena-aleatoria-de-al-menos-32-chars
NETMAP_ADMIN_USER=admin
NETMAP_ADMIN_PASSWORD=tu-password-admin
CORS_ORIGINS=http://localhost:8080,http://127.0.0.1:8080
COOKIE_SECURE=false
TOKEN_TTL_SECONDS=28800
MAX_UPLOAD_BYTES=5242880
```

> **Importante:** Si el volumen de PostgreSQL ya fue inicializado, `POSTGRES_PASSWORD` debe coincidir con el valor original. Para empezar desde cero: `docker compose down -v`.

### 2. Construir y levantar

```bash
docker compose up --build -d
```

### 3. Acceder

| Recurso | URL |
|---|---|
| Aplicación | http://localhost:8080 |
| API (health check) | http://localhost:8000/api/health |
| PostgreSQL (local) | `localhost:5433` / usuario `netmap` / base `netmap` |

---

## Roles y permisos

| Rol | Lectura | Escribir | Exportar | Admin |
|---|---|---|---|---|
| `admin` | ✓ | ✓ | ✓ | ✓ |
| `editor` | ✓ | ✓ | ✓ | — |
| `viewer` | ✓ | — | — | — |
| `auditor` | ✓ | — | ✓ | — |

El usuario `admin` inicial se crea automáticamente con las credenciales definidas en `.env`. Desde el módulo **Usuarios** se pueden crear y gestionar cuentas adicionales.

---

## Módulos

### Mapa de red

Canvas interactivo basado en React Flow.

- Drag & drop de nodos y segmentos.
- Zoom, minimapa y centrado automático.
- Modo pantalla completa para el canvas.
- Layout automático con seis modos: jerarquía, segmento, CIDR/VLAN, tipo, estado y dependencia.
- Agrupación visual de dispositivos en segmentos con colapsar/expandir, color personalizado y conteo de hosts.
- Menú contextual con clic derecho sobre cualquier nodo.
- Resaltado de nodos afectados al simular una falla.
- Selección múltiple de nodos para acciones masivas.

**Panel izquierdo colapsable:** el botón `‹` / `›` reduce el sidebar a 52 px (solo iconos) para maximizar el área del canvas.

**Panel derecho contextual:** arranca cerrado. Se abre automáticamente al seleccionar un nodo, enlace o dependencia. Se cierra con el botón `×`.

### Inventario

Tabla enterprise con todas las operaciones sobre dispositivos.

- Crear, editar, duplicar y eliminar dispositivos.
- Filtros por nombre, IP, CIDR, tipo, segmento, estado y VLAN.
- Edición masiva de tipo, estado, icono, segmento y VLAN.
- Relación masiva: conectar varios dispositivos seleccionados hacia un equipo principal con un solo clic, con opción de actualizar el parent/upstream.
- Agrupación por CIDR / VLAN.
- Vista de conectividad: interfaces, enlaces paralelos, grupos LAG y roles de enlace.
- Carga rápida de `interfaces.csv`, `links.csv` y `dependencies.csv` sin salir del módulo.

### Relaciones

- Crear enlaces entre dispositivos especificando interfaz origen, interfaz destino, tipo, estado, etiqueta y grupo LAG.
- Crear dependencias entre entidades (dispositivo, segmento o servicio).
- Tipos de enlace disponibles: `physical_link`, `l2_link`, `l3_link`, `firewall_link`, `vpn_link`, `wireless_link`, `service_dependency`, `uplink`, `backup_link`, `internet_link`.
- Los enlaces paralelos entre los mismos dos equipos se dibujan como una sola línea agrupada con badge `N enlaces · GRUPO`.

### Servicios

Catálogo de servicios y aplicaciones para análisis de dependencia e impacto.

- Registrar servicios con tipo, criticidad, estado y propietario.
- Vincular servicios a dispositivos mediante dependencias.

### Importar

Carga masiva de datos desde archivos:

| Archivo | Endpoint | Descripción |
|---|---|---|
| `devices.csv` | `POST /api/import/devices` | Inventario de equipos |
| `interfaces.csv` | `POST /api/import/interfaces` | Puertos y NICs |
| `links.csv` | `POST /api/import/links` | Conexiones entre interfaces |
| `dependencies.csv` | `POST /api/import/dependencies` | Dependencias entre entidades |
| `nmap-scan.xml` | `POST /api/import/nmap` | Resultado de escaneo Nmap |

Templates descargables desde el módulo **Importar** o desde **Inventario**.

Archivos de ejemplo en `samples/`.

### Impacto

Simulación de falla propagada desde un dispositivo.

- Calcula qué dispositivos, segmentos y servicios quedan afectados.
- Muestra rutas de causa raíz.
- Se activa desde el canvas (clic derecho → Simular falla) o desde el panel de propiedades del dispositivo.

### Versiones

Snapshots del mapa completo almacenados en la base de datos.

- Guardar una versión con nombre y etiqueta libre.
- Restaurar una versión (reemplaza el estado actual).
- Comparar dos versiones: dispositivos, enlaces y servicios añadidos o eliminados.
- **Exportar proyecto JSON:** descarga el mapa completo como archivo `.json` portable.
- **Importar proyecto JSON:** carga un archivo exportado previamente y reemplaza el mapa actual. Útil para mover proyectos entre instancias o como respaldo offline.

### Usuarios *(solo admin)*

- Crear, editar y eliminar usuarios.
- Cambiar rol, nombre visible, contraseña y estado (activo/inactivo).
- Todos los cambios quedan registrados en el historial de auditoría.

### Auditoría

Historial completo de acciones con usuario, rol, tipo de entidad, mensaje y fecha.

---

## Exportación

| Formato | Descripción |
|---|---|
| PNG | Imagen del canvas en alta resolución |
| PDF | Reporte con diagrama, inventario, relaciones y dependencias |
| HTML | Diagrama interactivo autocontenido (sin servidor) |
| JSON | Estado completo de la base de datos (backup) |
| CSV | Inventario de dispositivos |

---

## Importación Nmap

Comando recomendado contra el Docker local:

```bash
nmap -sV -p 8080 --open -T3 -oX nmap-scan.xml 127.0.0.1
```

Contra una red autorizada:

```bash
nmap -sV --open --top-ports 1000 -T3 -oX nmap-scan.xml 192.168.1.0/24
```

Luego cargar `nmap-scan.xml` desde el módulo **Importar**.

---

## Modelado de interfaces y enlaces múltiples

Para representar LAG, Port-Channel, EtherChannel o enlaces redundantes:

```
devices.csv     → inventario general y parent lógico principal
interfaces.csv  → puertos físicos, NICs e interfaces lógicas
links.csv       → conexiones reales entre interfaces
link_group      → nombre del grupo (LAG-01, PC-01, etc.)
link_role       → primary / backup / redundant / member
```

Ejemplo de dos uplinks agrupados:

```csv
source_device,source_interface,target_device,target_interface,link_type,status,label,link_group,link_role
SW-ACCESS-01,Gi1/0/49,SW-CORE-01,Gi1/0/1,physical_link,UP,Uplink 1,LAG-01,primary
SW-ACCESS-01,Gi1/0/50,SW-CORE-01,Gi1/0/2,physical_link,UP,Uplink 2,LAG-01,primary
```

---

## Exportar e importar proyecto JSON

El módulo **Versiones** permite guardar y cargar el mapa completo como archivo `.json`.

**Exportar:**
```
Versiones → Exportar proyecto JSON
```

**Importar (reemplaza el mapa actual):**
```
Versiones → Cargar proyecto JSON
```

**Endpoint directo:**
```http
POST /api/import/project
Content-Type: application/json
Authorization: Bearer <token>
```

Acepta el mismo formato JSON que produce la exportación. Requiere rol `editor` o `admin`.

---

## Referencia de API

### Autenticación

```http
POST /api/auth/login
POST /api/auth/logout
```

### Estado

```http
GET  /api/health
GET  /api/state
POST /api/reset            (admin)
POST /api/seed-demo        (admin)
```

### Dispositivos

```http
POST   /api/devices
PATCH  /api/devices/{id}
PATCH  /api/devices/{id}/position
POST   /api/devices/{id}/duplicate
POST   /api/devices/bulk
POST   /api/devices/bulk-relate
POST   /api/devices/bulk-delete
DELETE /api/devices/{id}
```

### Interfaces y enlaces

```http
POST   /api/interfaces
PATCH  /api/interfaces/{id}
DELETE /api/interfaces/{id}

POST   /api/links
PATCH  /api/links/{id}
DELETE /api/links/{id}
```

### Segmentos

```http
POST   /api/segments
PATCH  /api/segments/{id}
PATCH  /api/segments/{id}/position
DELETE /api/segments/{id}
```

### Servicios y dependencias

```http
POST   /api/services
DELETE /api/services/{id}

POST   /api/dependencies
DELETE /api/dependencies/{id}
```

### Importación

```http
POST /api/import/devices
POST /api/import/interfaces
POST /api/import/links
POST /api/import/dependencies
POST /api/import/nmap
POST /api/import/project
```

### Exportación

```http
GET /api/export/inventory.csv
```

### Versiones

```http
POST /api/versions
GET  /api/versions
GET  /api/versions/{id}
POST /api/versions/{id}/restore
GET  /api/versions/compare/{a_id}/{b_id}
```

### Usuarios *(admin)*

```http
POST   /api/users
PATCH  /api/users/{id}
DELETE /api/users/{id}
```

### Impacto

```http
GET /api/impact/{device_id}
```

---

## Comandos de operación

```bash
# Ver logs en tiempo real
docker compose logs -f

# Detener sin eliminar datos
docker compose down

# Detener y eliminar volumen de base de datos
docker compose down -v

# Reconstruir desde cero
docker compose down -v
docker compose up --build -d

# Reconstruir solo el frontend (cambios en React/CSS)
docker compose build --no-cache frontend
docker compose up -d

# Reconstruir solo el backend (cambios en Python)
docker compose build --no-cache backend
docker compose up -d
```
