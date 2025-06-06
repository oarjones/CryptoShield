@echo off
REM CryptoShield Uninstallation Script
REM Run as Administrator

setlocal enabledelayedexpansion

echo ===============================================
echo CryptoShield Anti-Ransomware Uninstallation
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

REM Set paths
set INSTALL_DIR=C:\Program Files\CryptoShield
set DATA_DIR=C:\ProgramData\CryptoShield
set LOG_FILE=%DATA_DIR%\uninstall.log

REM Ensure DATA_DIR exists for logging (in case it was manually removed before script ran)
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\Logs" mkdir "%DATA_DIR%\Logs"

echo Script started on %date% at %time% > "%LOG_FILE%"
echo Uninstalling from INSTALL_DIR: %INSTALL_DIR% >> "%LOG_FILE%"
echo Using DATA_DIR: %DATA_DIR% >> "%LOG_FILE%"
echo. >> "%LOG_FILE%"

echo WARNING: This will attempt to completely remove CryptoShield from your system.
choice /C YN /N /M "Do you want to continue with uninstallation?"
if !errorLevel! neq 1 (
    echo Uninstallation cancelled by user.
    echo Uninstallation cancelled by user. >> "%LOG_FILE%"
    pause
    exit /b 0
)

echo.
echo [1/7] Stopping service CryptoShieldService...
echo [1/7] Stopping service CryptoShieldService... >> "%LOG_FILE%"
net stop CryptoShieldService >> "%LOG_FILE%" 2>&1
if !errorLevel! equ 0 (
    echo Service CryptoShieldService stopped successfully.
    echo Service CryptoShieldService stopped successfully. >> "%LOG_FILE%"
) else (
    echo Service CryptoShieldService was not running or failed to stop (Error: !errorLevel!).
    echo Service CryptoShieldService was not running or failed to stop (Error: !errorLevel!). >> "%LOG_FILE%"
)

echo [2/7] Stopping driver CryptoShield...
echo [2/7] Stopping driver CryptoShield... >> "%LOG_FILE%"
sc stop CryptoShield >> "%LOG_FILE%" 2>&1
if !errorLevel! equ 0 (
    echo Driver CryptoShield stopped successfully.
    echo Driver CryptoShield stopped successfully. >> "%LOG_FILE%"
) else (
    echo Driver CryptoShield was not running or failed to stop (Error: !errorLevel!).
    echo Driver CryptoShield was not running or failed to stop (Error: !errorLevel!). >> "%LOG_FILE%"
)

echo [3/7] Uninstalling service CryptoShieldService...
echo [3/7] Uninstalling service CryptoShieldService... >> "%LOG_FILE%"
if exist "%INSTALL_DIR%\CryptoShieldService.exe" (
    "%INSTALL_DIR%\CryptoShieldService.exe" /uninstall >> "%LOG_FILE%" 2>&1
    if !errorLevel! equ 0 (
        echo Service uninstalled via executable. >> "%LOG_FILE%"
    ) else (
        echo Failed to uninstall service via executable (Error: !errorLevel!). Attempting manual deletion. >> "%LOG_FILE%"
        sc delete CryptoShieldService >> "%LOG_FILE%" 2>&1
    )
) else (
    echo Service executable not found at %INSTALL_DIR%\CryptoShieldService.exe. Attempting manual deletion. >> "%LOG_FILE%"
    sc delete CryptoShieldService >> "%LOG_FILE%" 2>&1
)
if !errorLevel! equ 0 (
     echo Service CryptoShieldService deleted successfully.
     echo Service CryptoShieldService deleted successfully. >> "%LOG_FILE%"
) else if !errorLevel! equ 1060 ( REM 1060 is ERROR_SERVICE_DOES_NOT_EXIST
     echo Service CryptoShieldService was not installed. >> "%LOG_FILE%"
     echo Service CryptoShieldService was not installed.
) else (
     echo WARNING: Failed to delete service CryptoShieldService (Error: !errorLevel!).
     echo WARNING: Failed to delete service CryptoShieldService (Error: !errorLevel!). >> "%LOG_FILE%"
)


echo [4/7] Uninstalling driver CryptoShield...
echo [4/7] Uninstalling driver CryptoShield... >> "%LOG_FILE%"
sc delete CryptoShield >> "%LOG_FILE%" 2>&1
if !errorLevel! equ 0 (
    echo Driver CryptoShield uninstalled successfully.
    echo Driver CryptoShield uninstalled successfully. >> "%LOG_FILE%"
) else if !errorLevel! equ 1060 ( REM 1060 is ERROR_SERVICE_DOES_NOT_EXIST
    echo Driver CryptoShield was not installed. >> "%LOG_FILE%"
    echo Driver CryptoShield was not installed.
) else (
    echo WARNING: Failed to uninstall driver CryptoShield (Error: !errorLevel!).
    echo WARNING: Failed to uninstall driver CryptoShield (Error: !errorLevel!). >> "%LOG_FILE%"
)

REM Remove driver file from system32
echo [5/7] Removing driver file from system...
echo [5/7] Removing driver file from system... >> "%LOG_FILE%"
if exist "%SystemRoot%\System32\drivers\CryptoShield.sys" (
    del /F /Q "%SystemRoot%\System32\drivers\CryptoShield.sys" >> "%LOG_FILE%" 2>&1
    if !errorLevel! equ 0 (
        echo Driver file CryptoShield.sys deleted from system32\drivers. >> "%LOG_FILE%"
    ) else (
        echo WARNING: Failed to delete %SystemRoot%\System32\drivers\CryptoShield.sys (Error: !errorLevel!). >> "%LOG_FILE%"
    )
) else (
    echo Driver file CryptoShield.sys not found in system32\drivers. >> "%LOG_FILE%"
)

echo [6/7] Removing firewall exception...
echo [6/7] Removing firewall exception... >> "%LOG_FILE%"
netsh advfirewall firewall delete rule name="CryptoShield Service" >> "%LOG_FILE%" 2>&1
echo Firewall rule "CryptoShield Service" removal attempted. >> "%LOG_FILE%"

echo [7/7] Removing installation files...
echo [7/7] Removing installation files... >> "%LOG_FILE%"
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%" >> "%LOG_FILE%" 2>&1
    if !errorLevel! equ 0 (
        echo Installation directory %INSTALL_DIR% removed. >> "%LOG_FILE%"
    ) else (
        echo WARNING: Failed to remove installation directory %INSTALL_DIR% (Error: !errorLevel!). >> "%LOG_FILE%"
        echo Please manually delete: %INSTALL_DIR%
    )
) else (
    echo Installation directory %INSTALL_DIR% not found. >> "%LOG_FILE%"
)

REM Handling data files - this part from your script is good.
if exist "%DATA_DIR%" (
    echo.
    echo Found data directory: %DATA_DIR%
    echo This may contain logs and configuration files.
    choice /C YN /N /M "Do you want to remove all data files (logs, config)?"
    if !errorLevel! equ 1 (
        echo User chose to remove data files. >> "%LOG_FILE%"
        rmdir /S /Q "%DATA_DIR%" >> "%LOG_FILE%" 2>&1
        if !errorLevel! neq 0 (
            echo WARNING: Failed to remove data directory %DATA_DIR% (Error: !errorLevel!). >> "%LOG_FILE%"
            echo Please manually delete: %DATA_DIR%
        ) else (
            echo Data files and directory %DATA_DIR% removed successfully.
            echo Data files and directory %DATA_DIR% removed successfully. >> "%LOG_FILE%"
        )
    ) else (
        echo User chose to preserve data files at: %DATA_DIR%
        echo User chose to preserve data files. Log file for this uninstallation is inside. >> "%LOG_FILE%"
    )
) else {
    echo Data directory %DATA_DIR% not found. >> "%LOG_FILE%"
}


echo.
echo ===============================================
echo Uninstallation completed!
echo ===============================================
echo Uninstallation process finished. Check %LOG_FILE% for details. >> "%LOG_FILE%"
echo.

REM Check if test signing was enabled
bcdedit | findstr /I "testsigning" | findstr /I "Yes" >nul
if !errorLevel! equ 0 (
    echo NOTE: Test signing is still enabled on this system.
    echo To disable it (recommended after testing), run from an Admin prompt: bcdedit /set testsigning off
    echo.
    echo Test signing is still enabled. >> "%LOG_FILE%"
)

echo Script finished on %date% at %time% >> "%LOG_FILE%"
pause