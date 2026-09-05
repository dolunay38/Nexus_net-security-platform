@echo off
title Aksoy-Net Security Platform - START
chcp 65001 >nul
cd /d "%~dp0fabric-core"

echo ============================================================
echo    Aksoy-Net Security Platform  -  START
echo ============================================================
echo.

where docker >nul 2>nul
if errorlevel 1 (
  echo [FEHLER] Docker wurde nicht gefunden.
  echo          Bitte Docker Desktop installieren und starten.
  echo.
  pause
  exit /b 1
)

echo [1/3] Starte fabric-core + Ollama ...
docker compose up -d
if errorlevel 1 (
  echo [FEHLER] Start fehlgeschlagen. Laeuft Docker Desktop?
  pause
  exit /b 1
)

echo [2/3] Warte, bis der Dienst bereit ist ...
timeout /t 7 >nul

echo [3/3] Oeffne NEXUS im Browser ...
start "" "http://localhost:8800/ui/NEXUS_Kommandozentrale.html"

echo.
echo ============================================================
echo   FERTIG.  Plattform laeuft unter:
echo   http://localhost:8800/ui/NEXUS_Kommandozentrale.html
echo ------------------------------------------------------------
echo   Beim ERSTEN Mal: in ORAKEL ein Modell laden (Button "laden").
echo   In den Modulen unter Einstellungen die fabric-core-URL:
echo        http://localhost:8800
echo ============================================================
echo.
pause
