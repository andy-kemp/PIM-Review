@echo off
REM Power Platform admin review. Double-click, or run with options, e.g.
REM   Run-PowerPlatformReview.cmd -All
REM   Run-PowerPlatformReview.cmd -Tenant SE
setlocal
cd /d "%~dp0"
where pwsh >nul 2>nul
if %errorlevel%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-PowerPlatformReview.ps1" %*
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-PowerPlatformReview.ps1" %*
)
echo.
pause
