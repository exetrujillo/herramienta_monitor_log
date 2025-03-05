#!/usr/bin/env python3

import os
import sys
import logging
import subprocess
import time
from datetime import datetime
import threading
import psutil

class HerramientaMonitorLog:
    def __init__(self, log_base_dir='/var/log/security_monitoring'):
        """
        Constructor de la clase HerramientaMonitorLog.
        - Organiza los logs por fecha
        - Crea el directorio de logs si no existe
        """
        self.log_base_dir = log_base_dir
        self.current_date = datetime.now().strftime('%Y-%m-%d')
        self.log_dir = os.path.join(log_base_dir, self.current_date)
        
        # Crear directorio base para logs
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Diccionario para almacenar loggers y manejadores
        self.loggers = {}
        
        # Definición de tipos de logs que se pueden monitorear
        self.log_types = {
            0: "todos",
            1: "sistema",
            2: "autenticacion",
            3: "red",
            4: "procesos",
            5: "conexiones", 
            6: "actividad_usuario",
            7: "malware_rootkits"
        }
        
        self.active_threads = []  # Lista de hilos activos
        
    def setup_logging(self, log_type):
        """
        Configura el sistema de logging para un tipo de log específico.
        - Crea un único archivo de log por tipo durante la ejecución
        """
        # Obtener el nombre del tipo de log en minúsculas
        log_type_dir = self.log_types.get(log_type, str(log_type).lower())
        
        # Si ya existe un logger para este tipo, usarlo
        if log_type_dir in self.loggers:
            return self.loggers[log_type_dir]
        
        # Crear ruta completa para el archivo de log
        log_file = os.path.join(
            self.log_dir, 
            f"{log_type_dir}_log_{self.current_date}.log"
        )
        
        # Configurar logging
        logger = logging.getLogger(log_type_dir)
        logger.setLevel(logging.INFO)
        
        # Limpiar cualquier manejador existente
        logger.handlers.clear()
        
        # Crear un nuevo manejador de archivo
        file_handler = logging.FileHandler(log_file, mode='a')  # Modo append
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s: %(message)s', 
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        
        # Añadir manejador al logger
        logger.addHandler(file_handler)
        
        # Almacenar el logger para reutilización
        self.loggers[log_type_dir] = logger
        
        return logger
    
    def log_system_info(self):
        """Registra información general del sistema"""
        logger = self.setup_logging(1)
        try:
            logger.info("--- Inicio de Monitoreo de Sistema ---")
            logger.info(f"Hostname: {subprocess.check_output(['hostname']).decode().strip()}")
            logger.info(f"Distribución: {subprocess.check_output(['lsb_release', '-a']).decode().strip()}")
            logger.info(f"Kernel: {subprocess.check_output(['uname', '-r']).decode().strip()}")
            logger.info(f"Espacio en disco:\n{subprocess.check_output(['df', '-h']).decode()}")
        except Exception as e:
            logger.error(f"Error capturando información del sistema: {e}")
        
    def log_authentication(self):
        """Monitorea los logs de autenticación del sistema"""
        logger = self.setup_logging(2)
        try:
            logger.info("--- Inicio de Monitoreo de Autenticación ---")
            logger.info("Últimos inicios de sesión:")
            logger.info(subprocess.check_output(['last', '-a']).decode())

            logger.info("\nIntentos de inicio de sesión fallidos:")
            logger.info(subprocess.check_output(['lastb']).decode())
        except Exception as e:
            logger.error(f"Error capturando logs de autenticación: {e}")
        
    def log_network_connections(self):
        """Registra las conexiones de red activas en el sistema"""
        logger = self.setup_logging(3)
        try:
            logger.info("--- Inicio de Monitoreo de Red ---")
            logger.info("Conexiones TCP establecidas:")
            logger.info(subprocess.check_output(['ss', '-tuonp']).decode())
        except Exception as e:
            logger.error(f"Error capturando conexiones de red: {e}")
        
    def log_processes(self):
        """Monitorea los procesos en ejecución en el sistema"""
        logger = self.setup_logging(4)
        try:
            logger.info("--- Inicio de Monitoreo de Procesos ---")
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
                logger.info(f"PID: {proc.info['pid']}, Nombre: {proc.info['name']}, "
                             f"Usuario: {proc.info['username']}, Estado: {proc.info['status']}")
        except Exception as e:
            logger.error(f"Error capturando información de procesos: {e}")
        
    def log_user_activity(self):
        """Registra la actividad de los usuarios conectados"""
        logger = self.setup_logging(6)
        try:
            logger.info("--- Inicio de Monitoreo de Actividad de Usuario ---")
            logger.info("Usuarios conectados:")
            logger.info(subprocess.check_output(['w']).decode())

            logger.info("\nÚltimos comandos ejecutados:")
            try:
                # Intentar obtener historial del usuario actual
                logger.info(subprocess.check_output(['history']).decode())
            except:
                logger.warning("No se pudo obtener el historial de comandos")
        except Exception as e:
            logger.error(f"Error capturando actividad de usuario: {e}")
        
    def log_malware_checks(self):
        """Realiza una verificación básica de malware"""
        logger = self.setup_logging(7)
        try:
            logger.info("--- Inicio de Monitoreo de Malware y Rootkits ---")
            logger.info("Verificación de Rootkits con chkrootkit:")
            logger.info(subprocess.check_output(['chkrootkit']).decode())
        except Exception as e:
            logger.error(f"Error en verificación de malware: {e}")
        
    def start_continuous_monitoring(self, log_types):
        """Inicia el monitoreo continuo de los tipos de logs seleccionados"""
        monitoring_methods = {
            1: self.log_system_info,
            2: self.log_authentication,
            3: self.log_network_connections,
            4: self.log_processes,
            5: self.log_network_connections,
            6: self.log_user_activity,
            7: self.log_malware_checks
        }
        
        # Si se selecciona "todos" (0), monitorear todos los tipos de log
        if 0 in log_types:
            log_types = list(monitoring_methods.keys())
        
        for log_type in log_types:
            method = monitoring_methods.get(log_type)
            if method:
                thread = threading.Thread(target=self._continuous_log_thread, args=(method,))
                thread.start()
                self.active_threads.append(thread)
                print(f"Monitoreando: {self.log_types[log_type]}")
    
    def _continuous_log_thread(self, method, interval=300):
        """
        Hilo para monitoreo continuo.
        - Ejecuta el método de monitoreo en intervalos de 5 minutos.
        """
        while True:
            method()
            time.sleep(interval)
    
    def display_menu(self):
        """Muestra un menú con los tipos de logs disponibles para monitoreo"""
        print("\n--- Sistema de Monitoreo de Logs de Ciberseguridad ---")
        for key, value in self.log_types.items():
            print(f"{key}. {value.capitalize()}")
        print("\nSeleccione los números de los logs que desea monitorear (separados por comas)")
        print("Ejemplo: 1,2,3 para monitorear logs de Sistema, Autenticación y Red")
        print("Ejemplo: 0 para monitorear todos los logs")
    
    def main(self):
        """Función principal que gestiona la selección del usuario y el inicio del monitoreo"""
        self.display_menu()
        try:
            selected_logs = input("\nIngrese su selección: ")
            log_types = [int(x.strip()) for x in selected_logs.split(',')]
            
            # Validar selección del usuario
            if not all(log_type in self.log_types for log_type in log_types):
                print("Selección inválida. Por favor, use solo los números mostrados.")
                return
            
            self.start_continuous_monitoring(log_types)
            
            # Mantener el script en ejecución mientras los hilos están activos
            for thread in self.active_threads:
                thread.join()
        
        except KeyboardInterrupt:
            print("\nMonitoreo detenido por el usuario.")
        except ValueError:
            print("Por favor, ingrese números válidos separados por comas.")

if __name__ == "__main__":
    # Verificar si el script tiene permisos de root antes de ejecutarse
    if os.geteuid() != 0:
        print("Este script requiere permisos de administrador (root). Use sudo.")
        sys.exit(1)
    
    log_tool = HerramientaMonitorLog()
    log_tool.main()
