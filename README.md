# Sistema de Monitoreo de Logs de Ciberseguridad

## Descripción
Una herramienta de monitoreo de logs avanzada para Ubuntu, diseñada para análisis forense y seguridad informática. Permite registrar y monitorear diferentes tipos de eventos del sistema.

## Características Principales
- Monitoreo de múltiples tipos de logs
- Registro continuo de eventos
- Opciones flexibles de selección de logs
- Almacenamiento organizado por fecha

## Tipos de Logs Disponibles
0. Todos los logs
1. Sistema
2. Autenticación
3. Red
4. Procesos
5. Conexiones Activas
6. Actividad de Usuario
7. Malware y Rootkits

## Requisitos
- Python3
- Sistema Operativo: Ubuntu (probado en versiones recientes)
- Permisos de administrador, con sudo

## Dependencias
- psutil
- chkrootkit

## Instalación de Dependencias
```bash
sudo apt update
sudo apt install python3-pip python3-psutil chkrootkit
pip3 install psutil
```

## Uso
1. Clonar el repositorio
2. Dar permisos de ejecución al script si es necesario
```bash
chmod +x herramienta_monitor_log.py
```

3. Ejecutar con permisos de administrador
```bash
sudo python3 herramienta_monitor_log.py
```

## Ejemplos de Ejecución
- Monitorear todos los logs: `0`
- Monitorear logs de Sistema, Autenticación y Red: `1,2,3`
- Monitorear solo Actividad de Usuario: `6`

## Ubicación de Logs
Los logs se almacenan en `/var/log/security_monitoring/YYYY-MM-DD/`

## Notas de Seguridad
- Requiere permisos de root
- Maneja información sensible del sistema
- Recomendado para uso en entornos controlados

## Contribuciones
Las contribuciones son bienvenidas. Por favor, abrir un issue o enviar un pull request.

## Licencia
Licencia MIT.

## Descargo de Responsabilidad
Esta herramienta está destinada a profesionales de seguridad informática y administradores de sistemas. El uso indebido puede violar políticas de privacidad o leyes locales.
