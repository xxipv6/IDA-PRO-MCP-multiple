@echo off
REM ========================================
REM   IDA MCP Server - Binary Direct Mode
REM   (ELF + PE auto detect)
REM ========================================

setlocal EnableDelayedExpansion

REM ---- Paths & Ports ----
set "WORK_DIR=%~dp0"
set "MCP_DIR=%WORK_DIR%ida-pro-mcp"
set "PORT=8746"
set "BASE_PORT=10000"

cls
echo ========================================
echo   IDA MCP Server (Binary Direct Mode)
echo ========================================
echo.

REM ---- Collect real binaries only ----
set "FILES="

if not exist "%WORK_DIR%analyze\" (
    echo [ERROR] analyze\ directory not found
    pause
    exit /b 1
)

for %%f in ("%WORK_DIR%analyze\*") do (
    REM Skip directories
    if not exist "%%f\" (
        for /f "delims=" %%t in ('file -b "%%f" 2^>nul') do (
            echo %%t | findstr /I "ELF PE32" >nul
            if not errorlevel 1 (
                set "FILES=!FILES! %%f"
            )
        )
    )
)

if "%FILES%"=="" (
    echo [ERROR] No executable binaries found
    pause
    exit /b 1
)

echo Files to analyze:
echo %FILES%
echo.

REM ---- Check / clean port ----
netstat -ano | findstr ":%PORT%" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [Cleaning port %PORT%]
    for /f "tokens=5" %%a in (
        'netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"'
    ) do (
        taskkill /F /PID %%a >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
)

REM ---- Start MCP ----
cd /d "%MCP_DIR%"
echo [Starting MCP Server on port %PORT%]
uv run idalib-mcp-multisession ^
    --port %PORT% ^
    --base-session-port %BASE_PORT% ^
    %FILES%

pause
