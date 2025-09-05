# SSLcat - Servidor Proxy SSL

SSLcat es un potente servidor proxy SSL que soporta gestión automática de certificados, reenvío de dominios, protección de seguridad y panel de administración web.

## 📚 Documentación

- 📑 [Índice Completo de Documentación](DOCS.md) - Índice y navegación para todos los documentos
- 📖 [Resumen del Proyecto (Chino)](项目总结.md) - Introducción detallada de características y documentación técnica
- 🚀 [Guía de Despliegue (Inglés)](DEPLOYMENT_EN.md) - Documentación completa de despliegue y operaciones
- 🚀 [部署指南 (中文)](DEPLOYMENT.md) - Guía de despliegue en chino
- 🇨🇳 [中文 README](README.md) - Versión china de este documento
- 🇺🇸 [English README](README_EN.md) - Versión inglesa de este documento

## Características

### 🌏 Optimización de Red para China
- **Optimización de Proxy CDN**: Utiliza el servicio [CDNProxy](https://cdnproxy.some.im/docs)
- **Aceleración de Acceso**: Resuelve problemas de acceso a jsdelivr CDN en China continental
- **Estabilidad**: Garantiza carga estable de recursos a través del servicio proxy

### 🔒 Gestión Automática de Certificados SSL
- Obtención automática de certificados SSL de Let's Encrypt
- Soporte para renovación automática de certificados
- Soporte para entornos de staging y producción
- Caché de certificados y optimización de rendimiento

### 🔄 Reenvío Inteligente de Dominios
- Reenvío de proxy inteligente basado en nombres de dominio
- Soporte para protocolos HTTP/HTTPS
- Soporte para proxy WebSocket
- Pool de conexiones y balanceador de carga

### 🛡️ Protección de Seguridad
- Bloqueo de IP y control de acceso
- Protección contra ataques de fuerza bruta
- Validación de User-Agent
- Registro de accesos

### 🎛️ Panel de Administración Web
- Interfaz web intuitiva
- Monitoreo y estadísticas en tiempo real
- Gestión de reglas de proxy
- Gestión de certificados SSL
- Configuración de seguridad

### 🔄 Reinicio Elegante
- Reinicio sin tiempo de inactividad
- Preservación de conexiones y recuperación de estado
- Mecanismo de apagado elegante

## Requisitos del Sistema

- Sistema Linux (Ubuntu/Debian/CentOS/RHEL)
- Go 1.21 o superior
- Privilegios root
- Puertos 80 y 443 disponibles

## Instalación Rápida

### Instalación Automática

```bash
# Descargar script de instalación
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh -o install.sh

# Ejecutar script de instalación
sudo bash install.sh
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
cd withssl
go mod download
go build -o withssl main.go
```

## Configuración

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
    "password": "admin*9527",
    "first_run": true
  },
  "admin_prefix": "/sslcat-panel"
}
```

## Uso

### Iniciar Servicio
```bash
sudo systemctl start withssl
```

### Detener Servicio
```bash
sudo systemctl stop withssl
```

### Panel de Administración Web

1. Abrir navegador y visitar: `https://your-domain/sslcat-panel`
2. Iniciar sesión con credenciales predeterminadas:
   - Usuario: `admin`
   - Contraseña: `admin*9527`
3. Cambiar contraseña después del primer inicio de sesión

## Argumentos de Línea de Comandos

```bash
withssl --help
```

Opciones disponibles:
- `--config`: Ruta del archivo de configuración (predeterminado: "/etc/withssl/withssl.conf")
- `--admin-prefix`: Prefijo de ruta del panel de administración (predeterminado: "/sslcat-panel")
- `--email`: Email para certificado SSL
- `--port`: Puerto de escucha (predeterminado: 443)
- `--host`: Dirección de escucha (predeterminado: "0.0.0.0")
- `--version`: Mostrar información de versión

## Licencia

Este proyecto utiliza la licencia MIT. Consulte el archivo [LICENSE](LICENSE) para más detalles.

## Soporte

Si encuentra problemas o tiene sugerencias:
1. Buscar en [Issues](https://github.com/xurenlu/sslcat/issues)
2. Crear un nuevo Issue
3. Contactar a los mantenedores
