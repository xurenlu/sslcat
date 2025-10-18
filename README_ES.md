# SSLcat - Servidor Proxy SSL

## ⏱️ Inicio Rápido con SSLcat en 1 Minuto

```bash
# 1) Instalación con un clic (Linux)
# Para usuarios en China continental (acelerado via sslcat.com)
curl -fsSL https://sslcat.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.0.11
# Usuarios fuera de China continental pueden usar directamente GitHub raw:
# curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.0.11

# 2) Prueba rápida local en macOS (o descargar paquete darwin manualmente)
curl -fsSL https://sslcat.com/xurenlu/sslcat/releases/download/v1.3.3/sslcat_v1.3.3_darwin-arm64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz && sudo install -m 0755 sslcat /usr/local/bin/sslcat
sslcat --config sslcat.conf --port 8080
# Acceso por navegador: http://localhost:8080/sslcat-panel/
# Primer login: admin / admin*9527 (forzará cambio de contraseña y generará admin.pass)

# 3) Opcional: Inicio con un clic usando Docker Compose
docker compose up -d
```

SSLcat es un potente servidor proxy SSL que soporta gestión automática de certificados, reenvío de dominios, protección de seguridad y panel de administración web, con soporte para protocolos HTTP/3 (QUIC) y HTTP/2 (negociación automática, compatible hacia atrás).

## 📚 Navegación de Documentación

- 📑 [Índice Completo de Documentación](DOCS.md) - Índice y navegación para todos los documentos
- 📖 [Resumen del Proyecto](项目总结.md) - Introducción detallada de funciones y documentación técnica
- 🚀 [Guía de Despliegue (Chino)](DEPLOYMENT.md) - Documentación completa de despliegue y operaciones
- 🚀 [Guía de Despliegue (Inglés)](DEPLOYMENT_EN.md) - Guía de despliegue en inglés

### 🌍 Versiones Multiidioma
- 🇨🇳 [中文 README](README.md) - Versión china
- 🇺🇸 [English README](README_EN.md) - Versión inglesa
- 🇯🇵 [日本語 README](README_JA.md) - Versión japonesa  
- 🇫🇷 [Français README](README_FR.md) - Versión francesa
- 🇷🇺 [Русский README](README_RU.md) - Versión rusa

## Características

### 🌏 Optimización de Red para China
- **Optimización de Proxy CDN**: Utiliza el servicio proxy [CDNProxy](https://cdnproxy.shifen.de/docs)
- **Aceleración de Acceso**: Resuelve problemas de acceso a jsdelivr CDN en China continental
- **Estabilidad**: Asegura carga estable de recursos a través del servicio proxy

### 🔒 Gestión Automática de Certificados SSL
- Obtención automática de certificados SSL de Let's Encrypt
- Soporte para renovación automática de certificados
- Soporte para entornos de staging y producción
- Caché de certificados y optimización de rendimiento
- **Operaciones de Certificados en Lote**: Descarga/importación de todos los certificados con un clic (formato ZIP)

### 🔄 Reenvío Inteligente de Dominios
- Reenvío de proxy inteligente basado en nombres de dominio
- Soporte para protocolos HTTP/HTTPS
- Soporte para proxy WebSocket
- Pool de conexiones y balanceador de carga

### 🛡️ Mecanismos de Protección de Seguridad
- Bloqueo de IP y control de acceso
- Protección anti-fuerza bruta
- Validación de User-Agent
- Registro de accesos
- **Fingerprinting de Cliente TLS**: Identificación de cliente basada en características ClientHello
- **Optimización para Entorno de Producción**: Umbrales de seguridad más tolerantes para escenarios de alto tráfico

### 🎛️ Panel de Administración Web
- Interfaz web intuitiva
- Monitoreo y estadísticas en tiempo real
- Gestión de reglas de proxy
- Gestión de certificados SSL
- Configuración de seguridad
- **Gestión de Tokens API**: Control de acceso API de solo lectura/lectura-escritura
- **Estadísticas de Huellas TLS**: Datos de análisis de huellas de cliente en tiempo real

### 🔄 Reinicio Elegante
- Reinicio sin tiempo de inactividad
- Preservación de conexiones y recuperación de estado
- Mecanismo de apagado elegante

## Requisitos del Sistema

- Sistema Linux (Ubuntu/Debian/CentOS/RHEL)
- Go 1.21 o superior
- Privilegios root
- Puertos 80 y 443 disponibles

## 📥 Obtener Código Fuente

### Repositorio GitHub

Proyecto alojado en GitHub: **[https://github.com/xurenlu/sslcat](https://github.com/xurenlu/sslcat)**

### Descarga de Última Versión

```bash
# Clonar código fuente más reciente
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# O descargar versión específica (recomendado)
wget https://github.com/xurenlu/sslcat/archive/refs/heads/main.zip
unzip main.zip
cd sslcat-main
```

## 🚀 Instalación Rápida

### Instalación Automática (Recomendado)

```bash
# Descargar script de instalación desde GitHub
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh -o install.sh

# Ejecutar script de instalación
sudo bash install.sh
```

### Despliegue Embebido (Archivo Único)

```bash
# Generar paquete de despliegue embebido
./deploy-embedded.sh

# O generar versión Linux
./deploy-embedded.sh linux

# Luego subir directorio deploy/ al servidor
```

### Instalación Manual

1. **Instalar Dependencias**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y curl wget git build-essential ca-certificates certbot

# CentOS/RHEL
sudo yum update -y
sudo yum install -y curl wget git gcc gcc-c++ make ca-certificates certbot
```

2. **Instalar Go**
```bash
# Descargar e instalar Go 1.21
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

3. **Compilar SSLcat**
```bash
git clone https://github.com/xurenlu/sslcat.git
cd sslcat
go mod download
go build -o sslcat main.go
```

4. **Crear Usuario y Directorios**
```bash
sudo useradd -r -s /bin/false sslcat
sudo mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs}
sudo chown -R sslcat:sslcat /var/lib/sslcat
```

5. **Configurar e Iniciar**
```bash
sudo cp sslcat /opt/sslcat/
sudo cp sslcat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sslcat
sudo systemctl start sslcat
```

## Configuración

### Ubicación del Archivo de Configuración
- Archivo de configuración principal: `/etc/sslcat/sslcat.conf`
- Directorio de certificados: `/var/lib/sslcat/certs`
- Directorio de claves: `/var/lib/sslcat/keys`
- Directorio de logs: `/var/lib/sslcat/logs`

### Configuración Básica

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "ssl": {
    "email": "your-email@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password_file": "./data/admin.pass",
    "first_run": true
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": true
      }
    ]
  },
  "security": {
    "max_attempts": 3,
    "block_duration": "1m",
    "max_attempts_5min": 10
  },
  "admin_prefix": "/sslcat-panel"
}
```

### Recuperación de Contraseña (Recuperación de Emergencia)

SSLcat usa la estrategia de seguridad "archivo marcador + cambio forzado de contraseña en primer uso":

- Archivo marcador: `admin.password_file` (por defecto `./data/admin.pass`). El archivo guarda la contraseña actual del admin con permisos 0600.
- Primer login: Si el archivo marcador no existe, o el contenido del archivo sigue siendo la contraseña por defecto `admin*9527`, el admin será forzado a la página "cambiar contraseña" después del login exitoso para establecer nueva contraseña y escribir al archivo marcador.

Pasos de recuperación de contraseña:

1. Detener servicio (o mantener ejecutándose, se recomienda detener).
2. Eliminar archivo marcador (si la ruta cambió, eliminar según la ruta real de configuración):
   ```bash
   rm -f ./data/admin.pass
   ```
3. Reiniciar servicio, login con cuenta por defecto (admin / admin*9527).
4. El sistema forzará entrar a la página "cambiar contraseña", establecer nueva contraseña para restaurar operación normal.

Nota: Por razones de seguridad, `sslcat.conf` ya no persiste `admin.password` en texto plano al guardar; en tiempo de ejecución la contraseña real usa `admin.password_file` como estándar.

## Uso

### Iniciar Servicio
```bash
sudo systemctl start sslcat
```

### Detener Servicio
```bash
sudo systemctl stop sslcat
```

### Reiniciar Servicio
```bash
sudo systemctl restart sslcat
```

### Reinicio Elegante
```bash
sudo systemctl reload sslcat
# o enviar señal SIGHUP
sudo kill -HUP $(pgrep sslcat)
```

### Ver Logs
```bash
# Ver estado del servicio
sudo systemctl status sslcat

# Ver logs en tiempo real
sudo journalctl -u sslcat -f

# Ver logs de error
sudo journalctl -u sslcat -p err
```

## Panel de Administración Web

### Acceder al Panel de Administración

**⚠️ Importante: Método de Acceso Inicial**

Como el sistema no tiene certificados SSL cuando se instala por primera vez, por favor usa el siguiente método para el acceso inicial:

1. **Primer Acceso** (usando dirección IP del servidor):
   ```
   http://YOUR_SERVER_IP/sslcat-panel
   ```
   Nota: Usa `http://` (no https) porque aún no hay certificados SSL

2. **Después de configurar dominio y obtener certificados**:
   ```
   https://your-domain/your-custom-panel-path
   ```

**Proceso de Login:**
1. Login con credenciales por defecto:
   - Nombre de usuario: `admin`
   - Contraseña: `admin*9527`
2. El primer login forzará:
   - Cambiar contraseña del administrador
   - Personalizar ruta de acceso del panel (por seguridad)
3. **¡Por favor recuerda la nueva ruta del panel!** El sistema redirigirá automáticamente a la nueva ruta

### Funciones del Panel de Administración
- **Dashboard**: Ver estado del sistema y estadísticas
- **Configuración de Proxy**: Gestionar reglas de reenvío de dominios
- **Certificados SSL**: Ver y gestionar certificados SSL
- **Configuraciones de Seguridad**: Configurar políticas de seguridad y ver IPs bloqueadas
- **Configuraciones del Sistema**: Modificar configuración del sistema

## Configuración de Proxy

### Agregar Regla de Proxy
1. Login al panel de administración
2. Ir a la página "Configuración de Proxy"
3. Hacer clic en "Nueva Regla de Proxy"
4. Llenar configuración:
   - Dominio: Dominio a proxificar
   - Objetivo: IP o dominio del servidor backend
   - Puerto: Puerto del servicio backend
   - Habilitado: Si habilitar esta regla
   - Solo SSL: Si permitir solo acceso HTTPS

### Ejemplo de Regla de Proxy
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "127.0.0.1",
        "port": 3000,
        "enabled": true,
        "ssl_only": true
      },
      {
        "domain": "app.example.com",
        "target": "192.168.1.100",
        "port": 8080,
        "enabled": true,
        "ssl_only": false
      }
    ]
  }
}
```

## Gestión de Certificados SSL

### Adquisición Automática de Certificados
SSLcat obtiene automáticamente certificados SSL para dominios configurados sin intervención manual.

### Renovación de Certificados
Los certificados se renuevan automáticamente 30 días antes del vencimiento, o pueden ser activados manualmente.

### Almacenamiento de Certificados
- Archivo de certificado: `/var/lib/sslcat/certs/domain.crt`
- Archivo de clave privada: `/var/lib/sslcat/keys/domain.key`

## Funciones de Seguridad

### Mecanismo de Bloqueo de IP
- Bloqueo automático después de 3 intentos fallidos en 1 minuto
- Bloqueo automático después de 10 intentos fallidos en 5 minutos
- Duración de bloqueo configurable
- Soporte para desbloqueo manual

### Control de Acceso
- Validación de User-Agent
- Rechazar acceso con User-Agent vacío
- Rechazar acceso con User-Agent de navegadores poco comunes

### Desbloquear IPs
```bash
# Eliminar archivo de bloqueo y reiniciar servicio
sudo rm /var/lib/sslcat/sslcat.block
sudo systemctl restart sslcat
```

## Argumentos de Línea de Comandos

```bash
sslcat [opciones]

Opciones:
  --config string        Ruta del archivo de configuración (por defecto: "/etc/sslcat/sslcat.conf")
  --admin-prefix string  Prefijo de ruta del panel de administración (por defecto: "/sslcat-panel")
  --email string         Email para certificado SSL
  --staging             Usar entorno de staging de Let's Encrypt
  --port int            Puerto de escucha (por defecto: 443)
  --host string         Dirección de escucha (por defecto: "0.0.0.0")
  --log-level string    Nivel de log (por defecto: "info")
  --version             Mostrar información de versión
```

## Solución de Problemas

### Problemas Comunes

1. **Falla al iniciar servicio**
   ```bash
   # Verificar sintaxis del archivo de configuración
   sudo withssl --config /etc/sslcat/sslcat.conf --log-level debug
   
   # Verificar uso de puerto
   sudo netstat -tlnp | grep :443
   ```

2. **Falla en adquisición de certificado SSL**
   - Asegurar que la resolución del dominio sea correcta
   - Asegurar que el puerto 80 sea accesible
   - Verificar configuraciones del firewall
   - Usar entorno de staging para pruebas

3. **Falla en reenvío de proxy**
   - Verificar si el servidor objetivo es alcanzable
   - Verificar que el puerto sea correcto
   - Revisar logs de acceso

4. **Panel de administración inaccesible**
   - Verificar configuraciones del firewall
   - Verificar que el certificado SSL sea válido
   - Revisar logs del servicio

### Análisis de Logs
```bash
# Ver logs detallados
sudo journalctl -u sslcat -f --no-pager

# Filtrar logs de error
sudo journalctl -u sslcat -p err --since "1 hour ago"

# Ver logs de período específico
sudo journalctl -u sslcat --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"
```

## Optimización de Rendimiento

### Optimización del Sistema
```bash
# Aumentar límite de descriptores de archivo
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimizar parámetros de red
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### Optimización de Configuración
```json
{
  "server": {
    "debug": false
  },
  "proxy": {
    "rules": []
  },
  "security": {
    "max_attempts": 5,
    "block_duration": "5m"
  }
}
```

## Optimización de Red

### Optimización para Usuarios de China Continental

SSLcat ha sido optimizado para el entorno de red de China continental, usando el servicio proxy [CDNProxy](https://cdnproxy.shifen.de/docs) para resolver problemas de acceso a jsdelivr CDN.

#### Uso de Proxy CDN
- **Dirección original**: `https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`
- **Dirección proxy**: `https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`

#### Archivos de Recursos Involucrados
- Bootstrap 5.1.3 CSS
- Bootstrap Icons 1.7.2
- Bootstrap 5.1.3 JavaScript
- Biblioteca Axios JavaScript

#### Control de Acceso
Según la documentación de CDNProxy, el servicio implementa políticas de control de acceso. Si el acceso es bloqueado, usualmente es porque el dominio Referer de la petición no está en la lista blanca. Contactar al administrador del servicio para agregar su dominio a la lista blanca si es necesario.

## Guía de Desarrollo

### Estructura del Proyecto
```
sslcat/
├── main.go                 # Entrada principal del programa
├── go.mod                  # Archivo de módulo Go
├── internal/               # Paquetes internos
│   ├── config/            # Gestión de configuración
│   ├── logger/            # Gestión de logs
│   ├── ssl/               # Gestión de certificados SSL
│   ├── proxy/             # Gestión de proxy
│   ├── security/          # Gestión de seguridad
│   ├── web/               # Servidor web
│   └── graceful/          # Reinicio elegante
├── web/                   # Recursos web
│   ├── templates/         # Plantillas HTML
│   └── static/            # Recursos estáticos
├── install.sh             # Script de instalación
└── README.md              # Documentación
```

### Configuración del Entorno de Desarrollo
```bash
# Clonar proyecto
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# Instalar dependencias
go mod download

# Ejecutar servidor de desarrollo
go run main.go --config sslcat.conf --log-level debug
```

### Guía de Contribución
1. Fork del proyecto
2. Crear rama de funcionalidad
3. Confirmar cambios
4. Push a la rama
5. Crear Pull Request

## Licencia

Este proyecto usa la licencia MIT. Ver archivo [LICENSE](LICENSE) para detalles.

## Soporte

Si encuentras problemas o tienes sugerencias:
1. Revisar la sección [Solución de Problemas](#solución-de-problemas)
2. Buscar en [Issues](https://github.com/xurenlu/sslcat/issues)
3. Crear un nuevo Issue
4. Contactar a los mantenedores

## Registro de Cambios

Para el historial completo de actualizaciones de versión, consulte: **[CHANGELOG.md](CHANGELOG.md)**

### Última Versión v1.1.0 (2025-09-08)
- Añadido: soporte de gestión para Sitios Estáticos y Sitios PHP
- Tiempos de espera configurables del servidor: `read_timeout_sec`, `write_timeout_sec`, `idle_timeout_sec` (por defecto: 30min lectura/escritura, 120s inactivo)
- Carga mejorada: `max_upload_bytes` (por defecto 1 GiB); cargas individuales y ZIP por streaming con límite total para evitar uso de memoria
- Consistencia UI: orden unificado de la barra lateral; añadido "Idioma" y "Sitio Oficial" en Dashboard/Sitios Estáticos/Sitios PHP; corregidos iconos faltantes
- Inicio de sesión y seguridad: captcha temporalmente deshabilitado (reversible)
- Documentación e i18n: READMEs multilenguaje actualizados; hoja de ruta actualizada

### Última Versión v1.0.15 (2025-01-03)
- 🌐 Arquitectura de clúster Master-Slave: Soporte para despliegue multi-nodo con alta disponibilidad
- 🔄 Sincronización automática de configuración: Envío en tiempo real desde Master a todos los nodos Slave
- 🔒 Control de separación de permisos: Restricciones funcionales estrictas en modo Slave
- 🖥️ Interfaz de gestión de clúster: Monitoreo completo del estado de nodos y gestión
- 📊 Información de monitoreo detallada: Dirección IP, puerto, recuento de certificados, MD5 de configuración, y más