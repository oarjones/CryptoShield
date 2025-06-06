@echo off
REM CryptoShield Installation Script
REM Run as Administrator

setlocal enabledelayedexpansion

REM --- Configuration ---
REM Set the build configuration: Release or Debug
set BUILD_CONFIG=Debug
REM Para usar Release, cambia a: set BUILD_CONFIG=Release
REM --- End Configuration ---

echo ===============================================
echo CryptoShield Anti-Ransomware Installation
echo Version 1.0.0 (Using %BUILD_CONFIG% build)
echo ===============================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Set paths based on BUILD_CONFIG
set SCRIPT_DIR=%~dp0
set DRIVER_BASE_PATH=%SCRIPT_DIR%Driver\CryptoShield\x64\%BUILD_CONFIG%
set SERVICE_BASE_PATH=%SCRIPT_DIR%Driver\CryptoShield\x64\%BUILD_CONFIG%

set DRIVER_PATH=%DRIVER_BASE_PATH%\CryptoShield.sys
set DRIVER_INF=%DRIVER_BASE_PATH%\CryptoShield.inf
set SERVICE_PATH=%SERVICE_BASE_PATH%\CryptoShieldService.exe

set INSTALL_DIR=C:\Program Files\CryptoShield
set DATA_DIR=C:\ProgramData\CryptoShield
set LOG_FILE=%DATA_DIR%\install_%BUILD_CONFIG%.log

REM Ensure DATA_DIR exists for logging early
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\Logs" mkdir "%DATA_DIR%\Logs"

echo Script started on %date% at %time% > "%LOG_FILE%"
echo Using BUILD_CONFIG: %BUILD_CONFIG% >> "%LOG_FILE%"
echo Driver Path: %DRIVER_PATH% >> "%LOG_FILE%"
echo Driver INF: %DRIVER_INF% >> "%LOG_FILE%"
echo Service Path: %SERVICE_PATH% >> "%LOG_FILE%"
echo Install Dir: %INSTALL_DIR% >> "%LOG_FILE%"
echo Data Dir: %DATA_DIR% >> "%LOG_FILE%"
echo. >> "%LOG_FILE%"

REM Check if files exist
if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver file not found: %DRIVER_PATH%
    echo ERROR: Driver file not found: %DRIVER_PATH% >> "%LOG_FILE%"
    echo Please build the driver in %BUILD_CONFIG% configuration or check BUILD_CONFIG setting in this script.
    echo Please build the driver in %BUILD_CONFIG% configuration or check BUILD_CONFIG setting in this script. >> "%LOG_FILE%"
    pause
    exit /b 1
)

if not exist "%DRIVER_INF%" (
    echo ERROR: Driver INF file not found: %DRIVER_INF%
    echo ERROR: Driver INF file not found: %DRIVER_INF% >> "%LOG_FILE%"
    echo Please ensure the INF file is present for the %BUILD_CONFIG% configuration.
    echo Please ensure the INF file is present for the %BUILD_CONFIG% configuration. >> "%LOG_FILE%"
    pause
    exit /b 1
)

if not exist "%SERVICE_PATH%" (
    echo ERROR: Service file not found: %SERVICE_PATH%
    echo ERROR: Service file not found: %SERVICE_PATH% >> "%LOG_FILE%"
    echo Please build the service in %BUILD_CONFIG% configuration or check BUILD_CONFIG setting and SERVICE_BASE_PATH in this script.
    echo Please build the service in %BUILD_CONFIG% configuration or check BUILD_CONFIG setting and SERVICE_BASE_PATH in this script. >> "%LOG_FILE%"
    pause
    exit /b 1
)

echo [1/7] Creating installation directories...
echo [1/7] Creating installation directories... >> "%LOG_FILE%"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%" >> "%LOG_FILE%" 2>&1
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%" >> "%LOG_FILE%" 2>&1
if not exist "%DATA_DIR%\Logs" mkdir "%DATA_DIR%\Logs" >> "%LOG_FILE%" 2>&1
echo Directories checked/created. >> "%LOG_FILE%"

echo [2/7] Copying files...
echo [2/7] Copying files... >> "%LOG_FILE%"
copy /Y "%SERVICE_PATH%" "%INSTALL_DIR%\" >> "%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Failed to copy service executable to %INSTALL_DIR%
    echo ERROR: Failed to copy service executable to %INSTALL_DIR% >> "%LOG_FILE%"
    pause
    exit /b 1
)
echo Service executable copied to %INSTALL_DIR% >> "%LOG_FILE%"

echo [3/7] Installing driver "CryptoShield"...
echo [3/7] Installing driver "CryptoShield"... >> "%LOG_FILE%"
echo Enabling testsigning (if not already enabled)... >> "%LOG_FILE%"
bcdedit /set testsigning on >> "%LOG_FILE%" 2>&1

REM Attempt INF installation
echo Attempting driver installation via INF: %DRIVER_INF% >> "%LOG_FILE%"
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 "%DRIVER_INF%" >> "%LOG_FILE%" 2>&1
set INF_INSTALL_ERRORLEVEL=!errorLevel!

REM Verify if driver service "CryptoShield" was created by INF
sc query CryptoShield >nul 2>&1
set DRIVER_SERVICE_EXISTS_ERRORLEVEL=!errorLevel!

REM --- INICIO DE LA CORRECCIÓN para el IF con OR ---
set "MANUAL_INSTALL_NEEDED=0"
if !INF_INSTALL_ERRORLEVEL! neq 0 set "MANUAL_INSTALL_NEEDED=1"
if !DRIVER_SERVICE_EXISTS_ERRORLEVEL! neq 0 set "MANUAL_INSTALL_NEEDED=1"

if "%MANUAL_INSTALL_NEEDED%" == "1" (
    if !INF_INSTALL_ERRORLEVEL! neq 0 (
        echo WARNING: Driver installation via INF failed. ErrorLevel: !INF_INSTALL_ERRORLEVEL! >> "%LOG_FILE%"
        echo WARNING: Driver installation via INF failed. ErrorLevel: !INF_INSTALL_ERRORLEVEL!
    )
    if !DRIVER_SERVICE_EXISTS_ERRORLEVEL! neq 0 (
        echo INFO: Driver service 'CryptoShield' not found after INF attempt (Error: !DRIVER_SERVICE_EXISTS_ERRORLEVEL!). Will attempt manual creation. >> "%LOG_FILE%"
        echo INFO: Driver service 'CryptoShield' not found after INF attempt. Will attempt manual creation.
    )
    echo Attempting manual installation for driver "CryptoShield"... >> "%LOG_FILE%"
    echo Attempting manual installation for driver "CryptoShield"...
    
    echo Copying driver %DRIVER_PATH% to %SystemRoot%\System32\drivers\CryptoShield.sys >> "%LOG_FILE%"
    copy /Y "%DRIVER_PATH%" "%SystemRoot%\System32\drivers\CryptoShield.sys" >> "%LOG_FILE%" 2>&1
    if !errorLevel! neq 0 (
        echo ERROR: Failed to copy driver to system directory. ErrorLevel: !errorLevel! >> "%LOG_FILE%"
        echo ERROR: Failed to copy driver to system directory. ErrorLevel: !errorLevel!
        pause
        exit /b 1
    )
    
    REM Pre-delete in case of a broken state
    sc delete CryptoShield >nul 2>&1 
    echo Attempted pre-delete of 'CryptoShield' service (if it existed in a broken state). >> "%LOG_FILE%"
    
    echo Manually creating service for driver "CryptoShield" >> "%LOG_FILE%"
    sc create CryptoShield type= kernel start= demand binPath= "system32\drivers\CryptoShield.sys" DisplayName= "CryptoShield Minifilter Driver" Group= "FSFilter Anti-Virus" >> "%LOG_FILE%" 2>&1
    if !errorLevel! neq 0 (
        echo ERROR: Failed to create driver service 'CryptoShield' manually. ErrorLevel: !errorLevel! >> "%LOG_FILE%"
        echo ERROR: Failed to create driver service 'CryptoShield' manually. ErrorLevel: !errorLevel!
        sc delete CryptoShield >nul 2>&1
        pause
        exit /b 1
    )
    echo Driver service 'CryptoShield' created manually. >> "%LOG_FILE%"
) else (
    echo Driver 'CryptoShield' installed successfully via INF. >> "%LOG_FILE%"
    echo Driver 'CryptoShield' installed successfully via INF.
)
REM --- FIN DE LA CORRECCIÓN ---

echo [4/7] Installing service "CryptoShieldService"...
echo [4/7] Installing service "CryptoShieldService"... >> "%LOG_FILE%"
"%INSTALL_DIR%\CryptoShieldService.exe" /install >> "%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Failed to install service "CryptoShieldService". ErrorLevel: %errorLevel%
    echo ERROR: Failed to install service "CryptoShieldService". ErrorLevel: %errorLevel% >> "%LOG_FILE%"
    pause
    exit /b 1
)
echo Service CryptoShieldService installed. >> "%LOG_FILE%"

echo [5/7] Configuring service "CryptoShieldService"...
echo [5/7] Configuring service "CryptoShieldService"... >> "%LOG_FILE%"
sc config CryptoShieldService start= auto >> "%LOG_FILE%" 2>&1
sc failure CryptoShieldService reset= 86400 actions= restart/60000/restart/120000/run/0 >> "%LOG_FILE%" 2>&1
sc description CryptoShieldService "CryptoShield Anti-Ransomware Protection Service" >> "%LOG_FILE%" 2>&1
echo Service CryptoShieldService configured for auto start, recovery and description updated. >> "%LOG_FILE%"

echo [6/7] Setting permissions for %DATA_DIR%...
echo [6/7] Setting permissions for %DATA_DIR%... >> "%LOG_FILE%"
REM Using SID for Administrators: S-1-5-32-544
icacls "%DATA_DIR%" /grant "SYSTEM:(OI)(CI)F" /T /C /Q >> "%LOG_FILE%" 2>&1
icacls "%DATA_DIR%" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q >> "%LOG_FILE%" 2>&1
if !errorLevel! neq 0 (
    echo WARNING: Setting permissions for Administrators on %DATA_DIR% might have failed (Error: !errorLevel!). Check log. >> "%LOG_FILE%"
    echo WARNING: Setting permissions for Administrators on %DATA_DIR% might have failed.
) else (
    echo Permissions set for %DATA_DIR%. >> "%LOG_FILE%"
)

echo [7/7] Creating firewall exception...
echo [7/7] Creating firewall exception... >> "%LOG_FILE%"
netsh advfirewall firewall delete rule name="CryptoShield Service" >> "%LOG_FILE%" 2>&1
netsh advfirewall firewall add rule name="CryptoShield Service" dir=in action=allow program="%INSTALL_DIR%\CryptoShieldService.exe" enable=yes profile=any >> "%LOG_FILE%" 2>&1
echo Firewall rule "CryptoShield Service" ensured. >> "%LOG_FILE%"

echo.
echo. >> "%LOG_FILE%"
echo ===============================================
echo =============================================== >> "%LOG_FILE%"
echo Installation completed successfully for %BUILD_CONFIG% build!
echo Installation completed successfully for %BUILD_CONFIG% build! >> "%LOG_FILE%"
echo ===============================================
echo =============================================== >> "%LOG_FILE%"
echo.
echo. >> "%LOG_FILE%"

choice /C YN /N /M "Do you want to start the CryptoShield components now?"
if !errorLevel! equ 1 (
    echo Starting driver CryptoShield...
    echo Starting driver CryptoShield... >> "%LOG_FILE%"
    sc start CryptoShield >> "%LOG_FILE%" 2>&1
    if !errorLevel! neq 0 (
        echo WARNING: Failed to start driver CryptoShield. ErrorLevel: !errorLevel! It might be an issue with signature, testsigning, or the driver itself.
        echo WARNING: Failed to start driver CryptoShield. ErrorLevel: !errorLevel! >> "%LOG_FILE%"
        echo Please check system event log (System) and DbgView for driver load errors.
    ) else (
        echo Driver CryptoShield started. >> "%LOG_FILE%"
    )
    
    echo Starting service CryptoShieldService...
    echo Starting service CryptoShieldService... >> "%LOG_FILE%"
    net start CryptoShieldService >> "%LOG_FILE%" 2>&1
    if !errorLevel! neq 0 (
        echo ERROR: Failed to start service CryptoShieldService. ErrorLevel: !errorLevel!
        echo ERROR: Failed to start service CryptoShieldService. ErrorLevel: !errorLevel! >> "%LOG_FILE%"
        echo Please check application event log and service debug output (CryptoShieldService.exe /debug) for details.
    ) else (
        echo.
        echo CryptoShield is now active and protecting your system!
        echo CryptoShield is now active and protecting your system! >> "%LOG_FILE%"
    )
) else (
    echo Components not started. You may need to reboot or start them manually via 'sc start CryptoShield' and 'net start CryptoShieldService'.
    echo Components not started. >> "%LOG_FILE%"
)

echo.
echo Installation log saved to: %LOG_FILE%
echo Script finished on %date% at %time% >> "%LOG_FILE%"
echo.
pause