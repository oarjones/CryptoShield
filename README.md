# CryptoShield

**GuardianFile** es un programa que se ejecuta en el kernel de Windows para detectar y prevenir la encriptación maliciosa de archivos por parte de ransomware. El programa monitorea las operaciones de archivos en tiempo real, analiza cambios sospechosos y solicita confirmación del usuario antes de permitir la encriptación.

## Características Principales
- Detección de encriptación mediante análisis de entropía y comparación de archivos.
- Protección contra desactivación con contraseña y mecanismos de autorreplicación.
- Interceptación de operaciones de archivos a nivel de kernel.

## Requisitos
- Windows 10/11.
- Windows Driver Kit (WDK).
- Visual Studio 2019 o superior.

## Instalación
1. Clona este repositorio.
2. Abre el proyecto en Visual Studio.
3. Compila el driver usando el WDK.

## Contribución
¡Las contribuciones son bienvenidas! Si deseas colaborar, por favor abre un issue o envía un pull request.

## Licencia
Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
