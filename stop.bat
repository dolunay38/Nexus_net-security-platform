@echo off
title Aksoy-Net Security Platform - STOP
chcp 65001 >nul
cd /d "%~dp0fabric-core"

echo ============================================================
echo    Aksoy-Net Security Platform  -  STOP
echo ============================================================
echo.
echo Stoppe Plattform (fabric-core + Ollama) ...
docker compose down
echo.
echo Gestoppt. Deine Daten bleiben erhalten (Volumes).
echo.
pause
