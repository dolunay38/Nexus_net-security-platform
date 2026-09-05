@echo off
title Aksoy-Net Security Platform - UPDATE
chcp 65001 >nul
cd /d "%~dp0fabric-core"

echo ============================================================
echo    Aksoy-Net Security Platform  -  UPDATE
echo ============================================================
echo.
echo [1/2] Hole neue Images (Ollama) ...
docker compose pull

echo [2/2] Baue fabric-core neu und starte ...
docker compose up -d --build

echo.
echo ============================================================
echo   Update fertig.
echo   HTML-Module aktualisieren? Einfach die Dateien im Ordner
echo   ersetzen und im Browser neu laden (F5). Kein Neustart noetig.
echo ============================================================
echo.
pause
