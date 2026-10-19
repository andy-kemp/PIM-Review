@echo off
REM Full PIM audit for Entra ID and Azure. Double-click, or run from a command prompt with options, e.g.
REM   Run-PimAudit.cmd -All
REM   Run-PimAudit.cmd -Tenant SE
setlocal
cd /d "%~dp0"
where pwsh >nul 2>nul
if %errorlevel%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-PimAudit.ps1" %*
) else (
  echo PowerShell 7 not found, using Windows PowerShell. PowerShell 7 is faster: winget install Microsoft.PowerShell
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-PimAudit.ps1" %*
)
echo.
pause
