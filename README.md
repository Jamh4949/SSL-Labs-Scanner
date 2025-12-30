# SSL Labs Scanner

Herramienta en Go para analizar la seguridad TLS de dominios usando la API pública de SSL Labs v4.

## Requisitos Previos

### 1. Registrar tu email en SSL Labs

**Importante:** Antes de usar esta herramienta, debes registrar tu email corporativo en SSL Labs.

```bash
curl --location 'https://api.ssllabs.com/api/v4/register' \
  --header 'Content-Type: application/json' \
  --data '{
    "firstName": "Tu Nombre",
    "lastName": "Tu Apellido",
    "email": "tu.email@empresa.com",
    "organization": "Nombre de tu Organización"
  }'
```

**Nota:** No se permiten emails de servicios gratuitos como Gmail, Yahoo o Hotmail.

### 2. Go instalado (versión 1.21 o superior)

## Instalación

```bash
# Clonar o descargar el proyecto
cd ssllabs-scanner

# No hay dependencias externas, solo la librería estándar de Go
```

## Uso

```bash
# Compilar
go build -o ssllabs-scanner.exe

# Ejecutar con flag
./ssllabs-scanner.exe -email tu.email@empresa.com -host www.google.com

# O usar variable de entorno (recomendado para no exponer email en historial)
export SSLLABS_EMAIL="tu.email@empresa.com"  # Linux/Mac
set SSLLABS_EMAIL=tu.email@empresa.com        # Windows CMD
$env:SSLLABS_EMAIL="tu.email@empresa.com"     # PowerShell
./ssllabs-scanner.exe -host www.google.com

# Con timeout personalizado (default: 10 minutos)
./ssllabs-scanner.exe -email tu@empresa.com -host example.com -timeout 5m

# Deshabilitar colores ANSI
./ssllabs-scanner.exe -host www.google.com -no-color

# O ejecutar directamente
go run main.go -email tu.email@empresa.com -host www.google.com
```

### Parámetros

| Parámetro   | Obligatorio | Descripción                                           |
|-------------|-------------|-------------------------------------------------------|
| `-email`    | Sí*         | Email registrado en SSL Labs                          |
| `-host`     | Sí          | Dominio a analizar                                    |
| `-timeout`  | No          | Timeout máximo (default: 10m). Ej: 5m, 1h              |
| `-no-color` | No          | Desactiva los colores ANSI en la salida               |

\* El email puede proporcionarse via variable de entorno `SSLLABS_EMAIL` (prioridad: flag > env var)

### Variables de Entorno

| Variable        | Descripción                                           |
|-----------------|-------------------------------------------------------|
| `SSLLABS_EMAIL` | Email para autenticación (alternativa a `-email`)     |
| `NO_COLOR`      | Si existe, desactiva colores (estándar de facto)      |
| `HTTP_PROXY`    | Proxy HTTP a usar para las peticiones                 |
| `HTTPS_PROXY`   | Proxy HTTPS a usar para las peticiones                |

### Cancelación

Puedes cancelar el análisis en cualquier momento con `Ctrl+C`. El programa mostrará los resultados parciales si están disponibles.

## Salida Esperada

La herramienta utiliza colores ANSI y símbolos Unicode para una visualización clara:

```
╔══════════════════════════════════════╗
║      SSL Labs Scanner  v1.0          ║
║   TLS Security Analysis Tool         ║
╚══════════════════════════════════════╝

→ Verificando disponibilidad de SSL Labs...
✓ SSL Labs disponible
  Engine: 2.4.0 │ Criteria: 2009q
  Assessments: 0/25

● Analizando: www.google.com
  (Esto puede tomar varios minutos... Ctrl+C para cancelar)

  [DNS] Resolving domain names
  [IN_PROGRESS] Waiting for analysis to complete

╔══════════════════════════════════════╗
║           RESULTADOS                 ║
╚══════════════════════════════════════╝

  Dominio: www.google.com
  Puerto:  443

──────────────────────────────────────────
  ■ Endpoint 1
──────────────────────────────────────────

  IP:     142.250.185.36
  Server: www.google.com

  ┌─────────────────────────────┐
  │   Grade: A+  ★              │
  │   Excelente                 │
  └─────────────────────────────┘

  Vulnerabilidades Críticas

  ✓ Heartbleed     Seguro
  ✓ DROWN          Seguro
  ✓ ROBOT          Seguro
  ✓ OpenSSL CCS    Seguro
  ✓ Lucky Minus 20 Seguro
  ✓ Ticketbleed    Seguro

  ✓ Sin vulnerabilidades críticas

  Información Adicional
  (Históricas o mitigadas en navegadores modernos)

  ○ BEAST          No detectado
  ○ POODLE (SSL3)  No detectado
  ○ FREAK          No detectado
  ○ Logjam         No detectado
  ...
```

### Clasificación de Vulnerabilidades

| Categoría | Vulnerabilidades | Descripción |
|-----------|------------------|-------------|
| **Críticas** | Heartbleed, DROWN, ROBOT, OpenSSL CCS, Lucky-13, Ticketbleed | Exploits activos que requieren acción inmediata |
| **Informativas** | BEAST, POODLE, FREAK, Logjam, Zombie/Golden/Sleeping POODLE | Históricas o mitigadas en navegadores modernos |

> **Nota sobre BEAST:** SSL Labs reporta `vulnBeast=true` por compatibilidad histórica, pero está mitigado en TLS 1.1+ y en todos los navegadores modernos (client-side mitigation). No se considera crítico.

**Colores utilizados:**
- 🟢 Verde: Seguro, Grade A+/A/A-
- 🟡 Amarillo: Advertencia, Grade B/C
- 🔴 Rojo: Vulnerable, Grade D/E/F/T/M
- 🔵 Cyan: Información, headers
- ⚪ Gris: Texto secundario

## Estructura del Proyecto

```
ssllabs-scanner/
├── main.go           # Punto de entrada, CLI y presentación
├── go.mod            # Módulo Go
├── README.md         # Este archivo
├── client/
│   └── client.go     # Cliente HTTP para SSL Labs API v4
└── models/
    └── models.go     # Estructuras de datos JSON
```

## Características

- ✅ Consume API v4 de SSL Labs
- ✅ **context.Context** para cancelación (Ctrl+C) y timeouts
- ✅ Respeta **NewAssessmentCoolOff** antes de iniciar análisis
- ✅ Lee headers **X-Max-Assessments** y **X-Current-Assessments** (thread-safe)
- ✅ Polling automático con intervalos variables (5s inicial, 10s durante IN_PROGRESS)
- ✅ **Reintentos automáticos** para errores 503/529 con backoff aleatorio
- ✅ **Reintentos para errores de red transitorios** (timeout, conexión rechazada, etc.)
- ✅ **Honra header Retry-After** en respuestas 429 si está presente
- ✅ **Límite de tamaño de respuesta** (10 MB) para seguridad
- ✅ **http.Transport configurado** con soporte para proxy y keep-alive
- ✅ Headers **User-Agent** y **Accept: application/json**
- ✅ Parseo estructurado de errores de la API
- ✅ Validación de email (warning para dominios gratuitos)
- ✅ **Email via variable de entorno** (`SSLLABS_EMAIL`) para mayor seguridad
- ✅ Muestra: Dominio, IP, Grade (de la API), Vulnerabilidades
- ✅ **Clasificación correcta de vulnerabilidades** (críticas vs informativas/históricas)
- ✅ Sin dependencias externas (solo librería estándar)
- ✅ Thread-safe (mutex para rate limiting)
- ✅ Código limpio y bien estructurado
- ✅ **Salida con colores ANSI** (símbolos Unicode, grades coloreados, vulnerabilidades destacadas)
- ✅ Opción `--no-color` y variable `NO_COLOR` para entornos sin soporte

## API v4 - Endpoints Utilizados

| Endpoint        | Método | Descripción                                           |
|-----------------|--------|-------------------------------------------------------|
| `/api/v4/info`  | GET    | Verificar disponibilidad del servicio                 |
| `/api/v4/analyze` | GET  | Iniciar/consultar análisis (requiere header `email`)  |

## Códigos de Error y Manejo

| Código | Descripción               | Acción del cliente                        |
|--------|---------------------------|-------------------------------------------|
| 400    | Parámetros inválidos      | Mostrar error estructurado                |
| 429    | Demasiadas peticiones     | Error (el cliente debe reducir concurrencia) |
| 441    | No autorizado             | Registrar email primero                   |
| 500    | Error interno             | Error fatal                               |
| 503    | Servicio no disponible    | **Reintento automático** con delay        |
| 529    | Servicio sobrecargado     | **Reintento automático** con delay mayor  |

## Detalles Técnicos

### Polling Variable
Según la documentación oficial:
- 5 segundos hasta que el estado sea `IN_PROGRESS`
- 10 segundos durante el análisis activo

### Rate Limiting
El cliente lee los headers de respuesta para tracking:
- `X-Max-Assessments`: Límite máximo de assessments concurrentes
- `X-Current-Assessments`: Assessments en uso actualmente

### Reintentos
Para errores temporales (503/529):
- Máximo 3 reintentos
- Delay con jitter aleatorio (±20%) para evitar thundering herd
- Respeta context para cancelación durante el wait

**Nota:** Los delays están reducidos para demo (30s/45s). En producción, según la documentación oficial, deberían ser ~15min para 503 y ~30min para 529.

### Errores de Red
Para errores transitorios de red (timeout, EOF, conexión rechazada):
- Máximo 2 reintentos con delay de 5s + jitter
- Detecta errores usando `net.Error` y patrones comunes

## Licencia

Este código fue desarrollado como parte de un challenge técnico.

---

**Autor:** Jose Martínez  
**Fecha:** Diciembre 2024
