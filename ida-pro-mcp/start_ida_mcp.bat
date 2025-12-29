@echo off
REM IDA Pro Multi-Session MCP Server Startup Script
REM Auto mode - empty start, controlled by Python script

setlocal EnableDelayedExpansion

REM Configuration - CHANGE THIS to your IDA path
set "IDADIR=E:\Tools\BinAny\IDA9.2"

REM Auto-detected paths (don't change)
set "SCRIPT_DIR=%~dp0"
set "PORT=8746"
set "BASE_PORT=10000"

cls
echo ========================================
echo   IDA MCP Server
echo ========================================
echo IDADIR: %IDADIR%
echo Port: %PORT%
echo ========================================
echo.

REM Check IDA directory
if not exist "%IDADIR%" (
    echo [ERROR] IDA directory not found: %IDADIR%
    echo Please edit this file and change IDADIR variable
    pause
    exit /b 1
)

REM Check port
netstat -ano | findstr ":%PORT%" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARNING] Port %PORT% is in use
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
        echo Killing process %%a
        taskkill //F //PID %%a >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
)

REM Switch to MCP directory
cd /d "%SCRIPT_DIR%"

REM Check virtual environment
if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found
    echo Please run in this directory: uv sync
    pause
    exit /b 1
)

REM Start in empty mode (no pre-loaded files)
echo [Starting MCP Server]
uv run idalib-mcp-multisession --port %PORT% --base-session-port %BASE_PORT%

endlocal
