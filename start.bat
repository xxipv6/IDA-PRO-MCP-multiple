@echo off
REM IDA MCP Server - Direct File Mode

setlocal EnableDelayedExpansion

set "WORK_DIR=%~dp0"
set "MCP_DIR=%WORK_DIR%ida-pro-mcp"
set "PORT=8746"
set "BASE_PORT=10000"

cls
echo ========================================
echo   IDA MCP Server (Direct Mode)
echo ========================================
echo.

REM Collect files to analyze
set "FILES="
if exist "%WORK_DIR%analyze\*.exe" (
    for %%f in ("%WORK_DIR%analyze\*.exe") do set "FILES=!FILES! %%f"
)

if "%FILES%"=="" (
    echo [ERROR] No files found in analyze\ folder
    pause
    exit /b 1
)

echo Files to analyze:%FILES%
echo.

REM Check/clean port
netstat -ano | findstr ":%PORT%" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [Cleaning port %PORT%]
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
        taskkill //F //PID %%a >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
)

cd /d "%MCP_DIR%"
echo [Starting MCP Server on port %PORT%]
uv run idalib-mcp-multisession --port %PORT% --base-session-port %BASE_PORT% %FILES%

pause
