@echo off
title fabric-core - Netzwerk-Scan
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo    ECHTER Netzwerk-Scan  -^>  fabric-core
echo    !!! NUR dein EIGENES Netz scannen !!!
echo ============================================================
echo.
echo  Dein Netz herausfinden:  ipconfig  (IPv4-Adresse ansehen)
echo  Beispiele:  192.168.1.0/24   oder   192.168.178.0/24
echo.

if "%~1"=="" (
  set /p TARGET="Ziel eingeben: "
) else (
  set "TARGET=%~1"
)

echo.
echo Scanne %TARGET% ... (kann ein paar Minuten dauern)
echo.
python "%~dp0fabric-core\scan.py" %TARGET%

echo.
pause
