@echo off
REM Power Platform privileged access audit. Double-click, or run from a command prompt with options, e.g.
REM   Run-PowerPlatformAudit.cmd -All
REM   Run-PowerPlatformAudit.cmd -Tenant SE
setlocal
cd /d "%~dp0"
where pwsh >nul 2>nul
if %errorlevel%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-PowerPlatformAudit.ps1" %*
) else (
  echo PowerShell 7 not found, using Windows PowerShell. PowerShell 7 is faster: winget install Microsoft.PowerShell
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-PowerPlatformAudit.ps1" %*
)
echo.
pause
